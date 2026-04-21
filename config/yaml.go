package config

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/mysqld_exporter/internal/tunnel"
	"gopkg.in/yaml.v3"
)

// YAMLConfig is the optional YAML-based configuration (opt-in via --config.yaml flag).
// When set, it adds SSH tunnel support on top of the regular mysqld_exporter behavior.
// Mirrors the pgscv.dba config layout for operational consistency.
type YAMLConfig struct {
	ListenAddress string                     `yaml:"listen_address,omitempty"`
	Services      map[string]*ServiceConfig  `yaml:"services"`
}

// ServiceConfig describes a single monitored MySQL service.
// The map key in YAMLConfig.Services is used as the tunnel manager's serviceID.
type ServiceConfig struct {
	// ServiceType must be "mysql". Kept for symmetry with pgscv's multi-engine config.
	ServiceType string `yaml:"service_type"`
	// DSN is the raw mysql driver DSN. One of DSN or DSNFile must be set.
	DSN string `yaml:"dsn,omitempty"`
	// DSNFile is a path to a file containing a single-line DSN. Preferred for Docker secrets.
	DSNFile string `yaml:"dsn_file,omitempty"`
	// SSHTunnel is optional. When set, DSN host:port is rewritten to the local tunnel endpoint.
	SSHTunnel *tunnel.SSHTunnelConfig `yaml:"ssh_tunnel,omitempty"`
}

// LoadYAMLConfig reads and validates a YAML config file.
// Returns nil without error if path is empty (config is opt-in).
func LoadYAMLConfig(path string) (*YAMLConfig, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read yaml config: %w", err)
	}

	var cfg YAMLConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid yaml config: %w", err)
	}

	return &cfg, nil
}

// Validate checks invariants across the full config.
func (c *YAMLConfig) Validate() error {
	if len(c.Services) == 0 {
		return fmt.Errorf("services map is empty")
	}
	for id, svc := range c.Services {
		if svc == nil {
			return fmt.Errorf("service %q is nil", id)
		}
		if svc.ServiceType != "mysql" {
			return fmt.Errorf("service %q: service_type must be \"mysql\" (got %q)", id, svc.ServiceType)
		}
		if svc.DSN == "" && svc.DSNFile == "" {
			return fmt.Errorf("service %q: one of dsn or dsn_file is required", id)
		}
		if svc.SSHTunnel != nil {
			svc.SSHTunnel.SetDefaults()
			if err := svc.SSHTunnel.Validate(); err != nil {
				return fmt.Errorf("service %q: %w", id, err)
			}
		}
	}
	return nil
}

// ResolveDSN returns the DSN for the service, reading from DSNFile if necessary.
func (s *ServiceConfig) ResolveDSN() (string, error) {
	if s.DSN != "" {
		return s.DSN, nil
	}
	if s.DSNFile == "" {
		return "", fmt.Errorf("no dsn or dsn_file set")
	}
	data, err := os.ReadFile(s.DSNFile)
	if err != nil {
		return "", fmt.Errorf("read dsn_file %s: %w", s.DSNFile, err)
	}
	return string(trimLine(data)), nil
}

// PrepareDSN resolves the DSN, establishes the SSH tunnel if configured,
// and rewrites the DSN host:port to the local tunnel endpoint.
// Returns the final DSN ready to pass to sql.Open("mysql", dsn).
// If SSHTunnel is nil, the DSN is returned unchanged (after resolving from file).
func (s *ServiceConfig) PrepareDSN(ctx context.Context, mgr *tunnel.Manager, serviceID string) (string, error) {
	dsn, err := s.ResolveDSN()
	if err != nil {
		return "", err
	}

	if s.SSHTunnel == nil {
		return dsn, nil
	}

	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("parse mysql dsn: %w", err)
	}

	// Force TCP network (tunnel is port-forward over TCP).
	if cfg.Net == "" || cfg.Net == "unix" {
		cfg.Net = "tcp"
	}

	host, portStr, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return "", fmt.Errorf("split dsn addr %q: %w", cfg.Addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("parse port %q: %w", portStr, err)
	}

	t, err := mgr.GetOrCreate(serviceID, *s.SSHTunnel, host, port)
	if err != nil {
		return "", fmt.Errorf("establish ssh tunnel: %w", err)
	}

	cfg.Addr = t.LocalAddr()
	return cfg.FormatDSN(), nil
}

// trimLine strips trailing newline and surrounding whitespace.
func trimLine(b []byte) []byte {
	// strip leading whitespace
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	// strip trailing whitespace
	for len(b) > 0 {
		last := b[len(b)-1]
		if last != ' ' && last != '\t' && last != '\n' && last != '\r' {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}
