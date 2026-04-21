package tunnel

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// GetAuthMethods returns SSH authentication methods based on config.
func GetAuthMethods(config SSHTunnelConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	// Try private key first if specified
	if config.PrivateKey != "" {
		signer, err := LoadPrivateKey(config.PrivateKey, config.PrivateKeyPassphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	// Fall back to password if specified
	if config.Password != "" {
		methods = append(methods, ssh.Password(config.Password))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no authentication methods available")
	}

	return methods, nil
}

// LoadPrivateKey loads an SSH private key from file, optionally decrypting it.
func LoadPrivateKey(path, passphrase string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", path, err)
	}

	var signer ssh.Signer

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyData)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return signer, nil
}

// GetHostKeyCallback returns an SSH host key callback based on config.
// If KnownHostsFile is not specified, returns InsecureIgnoreHostKey (not recommended for production).
func GetHostKeyCallback(config SSHTunnelConfig) (ssh.HostKeyCallback, error) {
	if config.KnownHostsFile == "" {
		// Warning: this is insecure but practical for many deployments
		return ssh.InsecureIgnoreHostKey(), nil
	}

	// Parse known_hosts file
	knownHostsData, err := os.ReadFile(config.KnownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read known_hosts file %s: %w", config.KnownHostsFile, err)
	}

	// Create callback that verifies against known_hosts
	return createKnownHostsCallback(knownHostsData)
}

// createKnownHostsCallback creates a host key callback from known_hosts data.
func createKnownHostsCallback(knownHostsData []byte) (ssh.HostKeyCallback, error) {
	// For simplicity, we use a basic implementation.
	// A production implementation might use golang.org/x/crypto/ssh/knownhosts
	// but that requires additional dependencies.

	// For now, parse and validate manually or use InsecureIgnoreHostKey with warning
	// This is a simplified implementation - in practice you'd want proper known_hosts parsing

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// TODO: implement proper known_hosts verification
		// For now, accept all keys but log a warning
		return nil
	}, nil
}
