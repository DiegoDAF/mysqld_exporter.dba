package tunnel

import (
	"context"
	"fmt"
	"sync"

	"log/slog"
)

// Manager manages multiple SSH tunnels.
type Manager struct {
	tunnels map[string]*Tunnel // key: serviceID
	mu      sync.RWMutex
	ctx     context.Context
}

// NewManager creates a new tunnel manager.
func NewManager(ctx context.Context) *Manager {
	return &Manager{
		tunnels: make(map[string]*Tunnel),
		ctx:     ctx,
	}
}

// GetOrCreate returns an existing tunnel or creates a new one.
//
// Tunnel objects are kept across Start failures: a Tunnel that failed to
// establish on first attempt has a background reviver running, and will
// become active automatically when SSH connectivity is restored.
//
// On error, the tunnel object is still returned (and stored) so that the
// caller can hold a reference and check IsActive() on subsequent calls.
func (m *Manager) GetOrCreate(serviceID string, config SSHTunnelConfig, remoteHost string, remotePort int) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Existing tunnel: return as-is. If inactive, its reviver is already retrying.
	if t, exists := m.tunnels[serviceID]; exists {
		if t.IsActive() {
			return t, nil
		}
		return t, fmt.Errorf("tunnel for service %s is not yet active (reviver running)", serviceID)
	}

	// New tunnel
	t := NewTunnel(config, remoteHost, remotePort)
	// Store BEFORE Start so the tunnel survives even if first connect fails —
	// the reviver inside will keep retrying and the next GetOrCreate will find it.
	m.tunnels[serviceID] = t

	if err := t.Start(m.ctx); err != nil {
		return t, fmt.Errorf("failed to start tunnel for service %s (will retry in background): %w", serviceID, err)
	}
	return t, nil
}

// Get returns an existing tunnel by serviceID.
func (m *Manager) Get(serviceID string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, exists := m.tunnels[serviceID]
	return t, exists
}

// Close closes and removes a specific tunnel.
func (m *Manager) Close(serviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, exists := m.tunnels[serviceID]
	if !exists {
		return nil
	}

	err := t.Close()
	delete(m.tunnels, serviceID)
	return err
}

// CloseAll closes all managed tunnels.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	total := len(m.tunnels)

	for serviceID, t := range m.tunnels {
		if err := t.Close(); err != nil {
			errs = append(errs, fmt.Errorf("service %s: %w", serviceID, err))
		}
	}

	// Clear map
	m.tunnels = make(map[string]*Tunnel)

	slog.Info("tunnel", "msg", fmt.Sprintf("closed all SSH tunnels (%d total)", total))

	if len(errs) > 0 {
		return fmt.Errorf("errors closing tunnels: %v", errs)
	}
	return nil
}

// Status returns status information for all tunnels.
func (m *Manager) Status() map[string]TunnelStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]TunnelStatus, len(m.tunnels))
	for id, t := range m.tunnels {
		status[id] = TunnelStatus{
			Active:     t.IsActive(),
			LocalAddr:  t.LocalAddr(),
			RemoteAddr: t.RemoteAddr(),
			LastError:  t.LastError(),
		}
	}
	return status
}

// TunnelStatus contains status information for a tunnel.
type TunnelStatus struct {
	Active     bool
	LocalAddr  string
	RemoteAddr string
	LastError  error
}

// Count returns the number of managed tunnels.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}
