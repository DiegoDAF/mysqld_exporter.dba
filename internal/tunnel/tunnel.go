package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"log/slog"
	"golang.org/x/crypto/ssh"
)

// Tunnel represents an active SSH tunnel to a remote host.
// Tunnels self-heal: if the SSH connection fails on startup or dies later
// (keepalive failure, network blip), a background reviver goroutine retries
// attemptConnect with exponential backoff (1s -> 60s) until it succeeds.
type Tunnel struct {
	config     SSHTunnelConfig
	remoteHost string
	remotePort int
	localPort  int

	listener  net.Listener
	sshClient *ssh.Client

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.RWMutex
	active    bool
	lastError error

	// reviverRunning ensures only one reviver goroutine exists per tunnel
	reviverMu      sync.Mutex
	reviverRunning bool
}

// NewTunnel creates a new tunnel instance (but does not start it).
func NewTunnel(config SSHTunnelConfig, remoteHost string, remotePort int) *Tunnel {
	config.SetDefaults()
	return &Tunnel{
		config:     config,
		remoteHost: remoteHost,
		remotePort: remotePort,
	}
}

// Start tries to establish the SSH connection. If the first attempt fails,
// it spawns a reviver goroutine that keeps retrying in the background, so
// callers can keep the tunnel object and check IsActive() later.
func (t *Tunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.active {
		t.mu.Unlock()
		return nil
	}
	if t.ctx == nil {
		t.ctx, t.cancel = context.WithCancel(ctx)
	}
	t.mu.Unlock()

	if err := t.attemptConnect(); err != nil {
		slog.Warn("tunnel", "msg", fmt.Sprintf("tunnel initial connect failed for %s, will retry in background: %v", t.config.Addr(), err))
		t.spawnReviver()
		return err
	}
	return nil
}

// attemptConnect performs one SSH dial + listener bind + goroutine setup.
// On success: sets t.active = true. On failure: returns error, no state changed.
func (t *Tunnel) attemptConnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.active {
		return nil
	}

	if err := t.config.Validate(); err != nil {
		return fmt.Errorf("invalid tunnel config: %w", err)
	}

	authMethods, err := GetAuthMethods(t.config)
	if err != nil {
		return fmt.Errorf("failed to get auth methods: %w", err)
	}

	hostKeyCallback, err := GetHostKeyCallback(t.config)
	if err != nil {
		return fmt.Errorf("failed to get host key callback: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            t.config.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	sshAddr := t.config.Addr()
	slog.Info("tunnel", "msg", fmt.Sprintf("connecting to SSH server %s", sshAddr))

	sshClient, err := ssh.Dial("tcp", sshAddr, sshConfig)
	if err != nil {
		t.lastError = err
		return fmt.Errorf("failed to connect to SSH server %s: %w", sshAddr, err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		sshClient.Close()
		t.lastError = err
		return fmt.Errorf("failed to start local listener: %w", err)
	}

	t.sshClient = sshClient
	t.listener = listener
	t.localPort = listener.Addr().(*net.TCPAddr).Port

	slog.Info("SSH tunnel established",
		"local_port", t.localPort, "ssh_addr", sshAddr,
		"remote_host", t.remoteHost, "remote_port", t.remotePort)

	go t.acceptLoop()
	if t.config.KeepAliveSeconds > 0 {
		go t.keepAlive()
	}

	t.active = true
	t.lastError = nil
	return nil
}

// spawnReviver launches a background goroutine that keeps trying to reconnect
// until the tunnel is active or the context is cancelled. Idempotent — multiple
// concurrent calls result in only one reviver.
func (t *Tunnel) spawnReviver() {
	t.reviverMu.Lock()
	if t.reviverRunning {
		t.reviverMu.Unlock()
		return
	}
	t.reviverRunning = true
	t.reviverMu.Unlock()

	go t.runReviver()
}

// runReviver retries attemptConnect with exponential backoff (1s, 2s, 4s, ..., 60s capped)
// until the tunnel is active or the context is cancelled.
func (t *Tunnel) runReviver() {
	defer func() {
		t.reviverMu.Lock()
		t.reviverRunning = false
		t.reviverMu.Unlock()
	}()

	const minBackoff = 1 * time.Second
	const maxBackoff = 60 * time.Second
	backoff := minBackoff

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(backoff):
		}

		if t.IsActive() {
			return
		}

		if err := t.attemptConnect(); err == nil {
			slog.Info("tunnel", "msg", fmt.Sprintf("SSH tunnel revived for %s", t.config.Addr()))
			return
		} else {
			slog.Warn("tunnel", "msg", fmt.Sprintf("tunnel reviver failed for %s, retry in %s: %v", t.config.Addr(), backoff, err))
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// acceptLoop accepts incoming connections and forwards them through the tunnel.
func (t *Tunnel) acceptLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Set accept deadline to allow periodic ctx check
		t.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

		localConn, err := t.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // timeout, check ctx and retry
			}
			if t.ctx.Err() != nil {
				return // context cancelled
			}
			slog.Warn("tunnel", "msg", fmt.Sprintf("tunnel accept error: %v", err))
			continue
		}

		// Forward this connection
		go t.forward(localConn)
	}
}

// forward handles a single forwarded connection.
func (t *Tunnel) forward(localConn net.Conn) {
	defer localConn.Close()

	remoteAddr := fmt.Sprintf("%s:%d", t.remoteHost, t.remotePort)

	// Dial remote through SSH
	remoteConn, err := t.sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		slog.Warn("tunnel", "msg", fmt.Sprintf("tunnel failed to dial remote %s: %v, marking inactive", remoteAddr, err))
		t.markInactive()
		return
	}
	defer remoteConn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// local -> remote
	go func() {
		defer wg.Done()
		io.Copy(remoteConn, localConn)
	}()

	// remote -> local
	go func() {
		defer wg.Done()
		io.Copy(localConn, remoteConn)
	}()

	wg.Wait()
}

// keepAlive sends periodic keepalive messages to prevent SSH timeout.
// After maxKeepaliveFailures consecutive failures, marks the tunnel as inactive
// and triggers the reviver to attempt reconnection in the background.
func (t *Tunnel) keepAlive() {
	const maxKeepaliveFailures = 3

	ticker := time.NewTicker(time.Duration(t.config.KeepAliveSeconds) * time.Second)
	defer ticker.Stop()

	failures := 0

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			_, _, err := t.sshClient.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				failures++
				slog.Warn("tunnel", "msg", fmt.Sprintf("SSH keepalive failed (%d/%d): %v", failures, maxKeepaliveFailures, err))
				if failures >= maxKeepaliveFailures {
					slog.Warn("tunnel", "msg", fmt.Sprintf("SSH tunnel to %s dead after %d keepalive failures, marking inactive", t.config.Addr(), failures))
					t.markInactive()
					return
				}
			} else {
				failures = 0
			}
		}
	}
}

// markInactive marks the tunnel as dead and triggers the reviver to reconnect.
// Called when SSH dial fails (forward) or keepalive declares the tunnel dead.
func (t *Tunnel) markInactive() {
	t.mu.Lock()
	t.active = false
	// Close the broken SSH client and listener so attemptConnect can rebuild fresh
	if t.sshClient != nil {
		_ = t.sshClient.Close()
		t.sshClient = nil
	}
	if t.listener != nil {
		_ = t.listener.Close()
		t.listener = nil
	}
	t.mu.Unlock()
	t.spawnReviver()
}

// Close stops the tunnel and releases resources.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active {
		return nil
	}

	// Cancel context to stop goroutines (including reviver)
	if t.cancel != nil {
		t.cancel()
	}

	var errs []error

	// Close listener
	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("listener close: %w", err))
		}
	}

	// Close SSH client
	if t.sshClient != nil {
		if err := t.sshClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("ssh client close: %w", err))
		}
	}

	t.active = false

	slog.Info("tunnel", "msg", fmt.Sprintf("SSH tunnel closed: 127.0.0.1:%d", t.localPort))

	if len(errs) > 0 {
		return fmt.Errorf("tunnel close errors: %v", errs)
	}
	return nil
}

// LocalAddr returns the local address string (127.0.0.1:port).
func (t *Tunnel) LocalAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", t.localPort)
}

// LocalPort returns the local port number.
func (t *Tunnel) LocalPort() uint16 {
	return uint16(t.localPort)
}

// IsActive returns true if the tunnel is running.
func (t *Tunnel) IsActive() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active
}

// LastError returns the last error encountered.
func (t *Tunnel) LastError() error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastError
}

// RemoteAddr returns the remote address being tunneled to.
func (t *Tunnel) RemoteAddr() string {
	return fmt.Sprintf("%s:%d", t.remoteHost, t.remotePort)
}
