package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrDNDuplicated is returned when a search operation finds multiple entries with the same DN,
// indicating a data integrity issue.
var ErrDNDuplicated = errors.New("DN is not unique")

// LDAP represents the main LDAP client with connection management and security features
type LDAP struct {
	config       *Config
	user         string
	password     string
	logger       *slog.Logger
	cache        Cache
	rateLimiter  *RateLimiter
	perfMonitor  *PerformanceMonitor
	connPool     *ConnectionPool
}

// Config contains the configuration for LDAP connections
type Config struct {
	Server           string
	Port             int
	BaseDN           string
	IsActiveDirectory bool
	TLSConfig        *tls.Config
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// Additional configuration options
	Pool        *PoolConfig
	Cache       *CacheConfig
	Performance *PerformanceConfig
	Logger      *slog.Logger
	DialOptions []ldap.DialOpt
}

// New creates a new LDAP client with the given configuration
func New(config *Config, username, password string) (*LDAP, error) {
	return &LDAP{
		config:   config,
		user:     username,
		password: password,
		logger:   slog.Default(),
	}, nil
}

// GetConnection returns a new LDAP connection
func (l *LDAP) GetConnection() (*ldap.Conn, error) {
	return l.GetConnectionContext(context.Background())
}

// GetConnectionContext returns a new LDAP connection with context
func (l *LDAP) GetConnectionContext(ctx context.Context) (*ldap.Conn, error) {
	// Implementation would go here - for now just return an error
	return nil, fmt.Errorf("connection not implemented")
}

// GetPerformanceStats returns detailed performance statistics for LDAP operations.
//
// Returns:
//   - PerformanceStats: Comprehensive performance metrics including timing, cache hit ratios, error counts, and resource usage
//
// The returned statistics include:
//   - Operation counts and timing percentiles (P50, P95, P99)
//   - Cache hit/miss ratios and slow query detection
//   - Memory usage and goroutine counts
//   - Operation breakdown by type and error statistics
//
// This method provides detailed insights into the performance characteristics of LDAP operations,
// including timing percentiles, cache hit ratios, and slow query detection.
func (l *LDAP) GetPerformanceStats() PerformanceStats {
	if l.perfMonitor == nil {
		return PerformanceStats{}
	}

	stats := l.perfMonitor.GetStats()
	if stats == nil {
		return PerformanceStats{}
	}

	return *stats
}

// WithCredentials creates a new LDAP client with different credentials.
// This method allows for creating a client authenticated as a different user
// while maintaining the same configuration and connection settings.
//
// Parameters:
//   - dn: The distinguished name (DN) for the new credentials
//   - password: The password for the new credentials
//
// Returns:
//   - *LDAP: A new LDAP client authenticated with the provided credentials
//   - error: Any error encountered during client creation
func (l *LDAP) WithCredentials(dn, password string) (*LDAP, error) {
	return New(l.config, dn, password)
}

// Close closes the LDAP client and cleans up resources.
// This method properly closes connection pools, caches, and other resources.
//
// Returns:
//   - error: Any error encountered during cleanup
func (l *LDAP) Close() error {
	var errs []error

	// Close connection pool if it exists
	if l.connPool != nil {
		if err := l.connPool.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection pool: %w", err))
		}
	}

	// Close cache if it exists
	if l.cache != nil {
		if err := l.cache.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close cache: %w", err))
		}
	}

	// Close performance monitor if it exists
	if l.perfMonitor != nil {
		if err := l.perfMonitor.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close performance monitor: %w", err))
		}
	}

	// Return combined errors if any
	if len(errs) > 0 {
		var errMsg string
		for i, err := range errs {
			if i > 0 {
				errMsg += "; "
			}
			errMsg += err.Error()
		}
		return fmt.Errorf("errors during close: %s", errMsg)
	}

	return nil
}

// GetPoolStats returns pool statistics for backward compatibility.
// This method is an alias for GetPerformanceStats().
//
// Returns:
//   - PerformanceStats: Performance and pool statistics
func (l *LDAP) GetPoolStats() PerformanceStats {
	return l.GetPerformanceStats()
}