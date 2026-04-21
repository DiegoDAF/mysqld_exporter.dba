package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Tunnel represents an active SSH tunnel to a remote host.
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

// Start establishes the SSH connection and starts the local listener.
func (t *Tunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.active {
		return nil // already running
	}

	// Create cancellable context
	t.ctx, t.cancel = context.WithCancel(ctx)

	// Validate config
	if err := t.config.Validate(); err != nil {
		return fmt.Errorf("invalid tunnel config: %w", err)
	}

	// Get auth methods
	authMethods, err := GetAuthMethods(t.config)
	if err != nil {
		return fmt.Errorf("failed to get auth methods: %w", err)
	}

	// Get host key callback
	hostKeyCallback, err := GetHostKeyCallback(t.config)
	if err != nil {
		return fmt.Errorf("failed to get host key callback: %w", err)
	}

	// Build SSH client config
	sshConfig := &ssh.ClientConfig{
		User:            t.config.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	// Connect to SSH server
	sshAddr := t.config.Addr()
	slog.Info("connecting to SSH server", "addr", sshAddr)

	sshClient, err := ssh.Dial("tcp", sshAddr, sshConfig)
	if err != nil {
		t.lastError = err
		return fmt.Errorf("failed to connect to SSH server %s: %w", sshAddr, err)
	}
	t.sshClient = sshClient

	// Start local listener on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		sshClient.Close()
		t.lastError = err
		return fmt.Errorf("failed to start local listener: %w", err)
	}
	t.listener = listener

	// Extract assigned port
	t.localPort = listener.Addr().(*net.TCPAddr).Port

	slog.Info("SSH tunnel established",
		"local_port", t.localPort,
		"ssh_addr", sshAddr,
		"remote_host", t.remoteHost,
		"remote_port", t.remotePort)

	// Start accept loop in background
	go t.acceptLoop()

	// Start keepalive if configured
	if t.config.KeepAliveSeconds > 0 {
		go t.keepAlive()
	}

	t.active = true
	t.lastError = nil

	return nil
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
			slog.Warn("tunnel accept error", "err", err)
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
		slog.Warn("tunnel failed to dial remote, marking inactive", "remote", remoteAddr, "err", err)
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
// so that the next GetOrCreate call will reconnect automatically.
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
				slog.Warn("SSH keepalive failed", "failures", failures, "max", maxKeepaliveFailures, "err", err)
				if failures >= maxKeepaliveFailures {
					slog.Warn("SSH tunnel dead, marking inactive", "addr", t.config.Addr(), "failures", failures)
					t.markInactive()
					return
				}
			} else {
				failures = 0
			}
		}
	}
}

// markInactive marks the tunnel as dead so GetOrCreate will reconnect on next scrape.
func (t *Tunnel) markInactive() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = false
}

// Close stops the tunnel and releases resources.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active {
		return nil
	}

	// Cancel context to stop goroutines
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

	slog.Info("SSH tunnel closed", "local_port", t.localPort)

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
