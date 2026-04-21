package tunnel

import "fmt"

// SSHTunnelConfig defines SSH tunnel connection parameters.
type SSHTunnelConfig struct {
	// Host is the SSH server hostname/IP (bastion host)
	Host string `yaml:"host"`
	// Port is the SSH server port (default: 22)
	Port int `yaml:"port"`
	// User is the SSH username
	User string `yaml:"user"`
	// PrivateKey is the path to SSH private key file
	PrivateKey string `yaml:"private_key"`
	// PrivateKeyPassphrase is the passphrase for encrypted private keys
	PrivateKeyPassphrase string `yaml:"private_key_passphrase"`
	// Password is the SSH password (used if PrivateKey not provided)
	Password string `yaml:"password"`
	// KnownHostsFile is path to known_hosts file (optional, skip verification if empty)
	KnownHostsFile string `yaml:"known_hosts_file"`
	// KeepAliveSeconds sets SSH keepalive interval (default: 30)
	KeepAliveSeconds int `yaml:"keepalive_seconds"`
}

// SetDefaults sets default values for optional fields.
func (c *SSHTunnelConfig) SetDefaults() {
	if c.Port == 0 {
		c.Port = 22
	}
	if c.KeepAliveSeconds == 0 {
		c.KeepAliveSeconds = 30
	}
}

// Validate checks if the configuration is valid.
func (c *SSHTunnelConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("ssh_tunnel.host is required")
	}
	if c.User == "" {
		return fmt.Errorf("ssh_tunnel.user is required")
	}
	if c.PrivateKey == "" && c.Password == "" {
		return fmt.Errorf("ssh_tunnel requires either private_key or password")
	}
	return nil
}

// Addr returns the SSH server address in host:port format.
func (c *SSHTunnelConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
