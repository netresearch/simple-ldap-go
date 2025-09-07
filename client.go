// Package ldap provides a simplified interface for LDAP operations with Active Directory support.
package ldap

import (
	"errors"

	"github.com/go-ldap/ldap/v3"
)

// Config holds the configuration for connecting to an LDAP server.
type Config struct {
	// Server is the LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://domain.com:636")
	Server string
	// BaseDN is the base distinguished name for LDAP searches (e.g., "DC=example,DC=com")
	BaseDN string

	// IsActiveDirectory indicates whether the server is Microsoft Active Directory.
	// This affects password change operations which require LDAPS for AD.
	IsActiveDirectory bool

	// DialOptions contains additional options for the LDAP connection
	DialOptions []ldap.DialOpt
}

// LDAP represents a client connection to an LDAP server with authentication credentials.
type LDAP struct {
	config Config

	user     string
	password string
}

// ErrDNDuplicated is returned when a search operation finds multiple entries with the same DN,
// indicating a data integrity issue.
var ErrDNDuplicated = errors.New("DN is not unique")

// New creates a new LDAP client with the specified configuration and credentials.
// It validates the connection by attempting to connect and authenticate with the provided credentials.
//
// Parameters:
//   - config: The LDAP server configuration including server URL and base DN
//   - user: The distinguished name (DN) or username for authentication
//   - password: The password for authentication
//
// Returns:
//   - *LDAP: A configured LDAP client ready for operations
//   - error: Any error encountered during connection validation
//
// Example:
//
//	config := Config{
//	    Server: "ldaps://ad.example.com:636",
//	    BaseDN: "DC=example,DC=com",
//	    IsActiveDirectory: true,
//	}
//	client, err := New(config, "CN=admin,CN=Users,DC=example,DC=com", "password")
func New(config Config, user, password string) (*LDAP, error) {
	l := &LDAP{
		config,
		user,
		password,
	}

	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	c.Close()

	return l, nil
}

// WithCredentials creates a new LDAP client using the same configuration but with different credentials.
// This is useful for operations that need to be performed with different user privileges.
//
// Parameters:
//   - dn: The distinguished name for the new credentials
//   - password: The password for the new credentials
//
// Returns:
//   - *LDAP: A new LDAP client with updated credentials
//   - error: Any error encountered during connection validation
func (l *LDAP) WithCredentials(dn, password string) (*LDAP, error) {
	return New(l.config, dn, password)
}

// GetConnection establishes and returns an authenticated LDAP connection.
// The connection must be closed by the caller when no longer needed.
//
// Returns:
//   - *ldap.Conn: An authenticated LDAP connection
//   - error: Any error encountered during connection or authentication
//
// The returned connection is ready for LDAP operations. Always defer Close() on the connection:
//
//	conn, err := client.GetConnection()
//	if err != nil {
//	    return err
//	}
//	defer conn.Close()
func (l LDAP) GetConnection() (*ldap.Conn, error) {
	dialOpts := make([]ldap.DialOpt, 0)
	if l.config.DialOptions != nil {
		dialOpts = l.config.DialOptions
	}

	c, err := ldap.DialURL(l.config.Server, dialOpts...)
	if err != nil {
		return nil, err
	}

	if err = c.Bind(l.user, l.password); err != nil {
		return nil, err
	}

	return c, nil
}
