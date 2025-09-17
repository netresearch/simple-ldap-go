// Package ldap provides a simplified interface for LDAP operations with Active Directory support.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

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

	// Logger is the structured logger for LDAP operations. If nil, a no-op logger is used.
	// Use slog.New() to create a logger with your preferred handler (JSON, text, etc.)
	Logger *slog.Logger

	// Pool is the optional connection pool configuration. When nil, pooling is disabled
	// and the client will create a new connection for each operation (legacy behavior).
	// When configured, enables connection pooling for improved performance in high-volume scenarios.
	Pool *PoolConfig

	// Cache is the optional intelligent caching configuration. When nil, caching is disabled
	// and all operations will be performed against the LDAP server directly (legacy behavior).
	// When configured, enables multi-level caching with LRU eviction and smart invalidation.
	Cache *CacheConfig

	// Performance is the optional performance monitoring configuration. When nil, basic
	// performance monitoring is enabled with default settings. Set to a custom config to
	// tune monitoring behavior, or set Enabled=false to disable completely.
	Performance *PerformanceConfig
}

// LDAP represents a client connection to an LDAP server with authentication credentials.
type LDAP struct {
	config Config
	logger *slog.Logger

	user     string
	password string

	// Connection pool (optional)
	pool *ConnectionPool

	// Intelligent caching system (optional)
	cache Cache

	// Performance monitoring system (optional)
	perfMonitor *PerformanceMonitor
}

// ErrDNDuplicated is returned when a search operation finds multiple entries with the same DN,
// indicating a data integrity issue.
var ErrDNDuplicated = errors.New("DN is not unique")

// New creates a new LDAP client with the specified configuration and credentials.
// It validates the connection by attempting to connect and authenticate with the provided credentials.
//
// This is the legacy constructor maintained for backward compatibility. For new applications,
// consider using NewWithOptions() which provides the modern functional options pattern.
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
//
// For modern applications, consider using NewWithOptions():
//
//	client, err := NewWithOptions(config, username, password,
//	    WithConnectionPool(&PoolConfig{MaxConnections: 20}),
//	    WithCache(&CacheConfig{Enabled: true, TTL: 5 * time.Minute}),
//	    WithPerformanceMonitoring(&PerformanceConfig{Enabled: true}),
//	)
//
// Or use the convenient factory methods:
//
//	client, err := NewHighPerformanceClient(config, username, password)
//	client, err := NewSecureClient(config, username, password)
//	client, err := NewReadOnlyClient(config, username, password)
func New(config Config, user, password string) (*LDAP, error) {
	// Use provided logger or create a no-op logger
	logger := config.Logger
	if logger == nil {
		// Create a no-op logger that discards all output
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	l := &LDAP{
		config:   config,
		logger:   logger,
		user:     user,
		password: password,
	}

	start := time.Now()
	logger.Debug("ldap_client_initializing",
		slog.String("server", config.Server),
		slog.String("base_dn", config.BaseDN),
		slog.Bool("is_active_directory", config.IsActiveDirectory),
		slog.Bool("pooling_enabled", config.Pool != nil),
		slog.Bool("caching_enabled", config.Cache != nil && config.Cache.Enabled),
		slog.Bool("performance_monitoring_enabled", config.Performance == nil || config.Performance.Enabled))

	// Initialize connection pool if configured
	if config.Pool != nil {
		pool, err := NewConnectionPool(config.Pool, config, user, password, logger)
		if err != nil {
			logger.Error("connection_pool_initialization_failed",
				slog.String("server", config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to initialize connection pool: %w", WrapLDAPError("NewConnectionPool", config.Server, err))
		}
		l.pool = pool

		logger.Info("ldap_client_initialized_with_pool",
			slog.String("server", config.Server),
			slog.Int("max_connections", config.Pool.MaxConnections),
			slog.Int("min_connections", config.Pool.MinConnections),
			slog.Duration("duration", time.Since(start)))
	} else {
		// Validate connection without pooling (legacy behavior)
		c, err := l.GetConnection()
		if err != nil {
			logger.Error("ldap_client_initialization_failed",
				slog.String("server", config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to validate connection: %w", WrapLDAPError("GetConnection", config.Server, err))
		}
		c.Close()

		logger.Info("ldap_client_initialized",
			slog.String("server", config.Server),
			slog.Duration("duration", time.Since(start)))
	}

	// Initialize intelligent caching system if configured
	if config.Cache != nil && config.Cache.Enabled {
		cache, err := NewLRUCache(config.Cache, logger)
		if err != nil {
			logger.Error("cache_initialization_failed",
				slog.String("server", config.Server),
				slog.String("error", err.Error()))
			// Don't fail client creation if cache fails, just log and continue without cache
		} else {
			l.cache = cache
			logger.Info("ldap_client_cache_initialized",
				slog.String("server", config.Server),
				slog.Int("max_size", config.Cache.MaxSize),
				slog.Duration("ttl", config.Cache.TTL),
				slog.Int("max_memory_mb", config.Cache.MaxMemoryMB))
		}
	}

	// Initialize performance monitoring system
	perfConfig := config.Performance
	if perfConfig == nil {
		perfConfig = DefaultPerformanceConfig()
	}

	if perfConfig.Enabled {
		perfMonitor := NewPerformanceMonitor(perfConfig, logger)
		l.perfMonitor = perfMonitor

		// Link cache and pool to performance monitor for integrated metrics
		if l.cache != nil {
			perfMonitor.SetCache(l.cache)
		}
		if l.pool != nil {
			perfMonitor.SetConnectionPool(l.pool)
		}

		logger.Info("ldap_client_performance_monitor_initialized",
			slog.String("server", config.Server),
			slog.Duration("slow_query_threshold", perfConfig.SlowQueryThreshold))
	}

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
//
// Note: If the original client used connection pooling, the new client will also use pooling
// with the same configuration but separate connection pools for security isolation.
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
//
// Performance Note: When connection pooling is enabled, this method will reuse existing
// connections when possible, providing significant performance improvements for high-volume scenarios.
// When pooling is disabled, each call creates a new connection (legacy behavior).
func (l LDAP) GetConnection() (*ldap.Conn, error) {
	return l.GetConnectionContext(context.Background())
}

// GetConnectionContext establishes and returns an authenticated LDAP connection with context support.
// The connection must be closed by the caller when no longer needed.
//
// Parameters:
//   - ctx: Context for controlling the connection timeout and cancellation
//
// Returns:
//   - *ldap.Conn: An authenticated LDAP connection
//   - error: Any error encountered during connection or authentication, including context cancellation
//
// The returned connection is ready for LDAP operations. Always defer Close() on the connection:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	conn, err := client.GetConnectionContext(ctx)
//	if err != nil {
//	    return err
//	}
//	defer conn.Close()
//
// Performance Note: When connection pooling is enabled, this method will reuse existing
// connections when possible, providing significant performance improvements for high-volume scenarios.
// The context controls both pool acquisition timeout and connection creation timeout.
//
// Important: When pooling is enabled, you must call Close() on the returned connection to return
// it to the pool. The connection will not actually be closed but returned for reuse.
func (l LDAP) GetConnectionContext(ctx context.Context) (*ldap.Conn, error) {
	// Use connection pool if available
	if l.pool != nil {
		conn, err := l.pool.Get(ctx)
		if err != nil {
			l.logger.Error("pool_connection_failed",
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to get connection from pool: %w", WrapLDAPError("GetConnectionFromPool", l.config.Server, err))
		}

		l.logger.Debug("connection_retrieved_from_pool",
			slog.String("server", l.config.Server))

		// Note: The caller must call Close() which will return this connection to the pool
		// This is handled by the pool's Put method when the connection is closed
		return conn, nil
	}

	// Fallback to direct connection creation (legacy behavior)
	return l.createDirectConnection(ctx)
}

// createDirectConnection creates a new LDAP connection without using the pool (legacy behavior)
func (l LDAP) createDirectConnection(ctx context.Context) (*ldap.Conn, error) {
	start := time.Now()
	l.logger.Debug("ldap_connection_establishing",
		slog.String("server", l.config.Server))

	dialOpts := make([]ldap.DialOpt, 0)
	if l.config.DialOptions != nil {
		dialOpts = l.config.DialOptions
	}

	// Check for context cancellation before dialing
	select {
	case <-ctx.Done():
		l.logger.Debug("ldap_connection_cancelled_before_dial",
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("connection cancelled before dial: %w", WrapLDAPError("DialURL", l.config.Server, ctx.Err()))
	default:
	}

	c, err := ldap.DialURL(l.config.Server, dialOpts...)
	if err != nil {
		l.logger.Error("ldap_connection_dial_failed",
			slog.String("server", l.config.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to dial LDAP server %s: %w", l.config.Server, WrapLDAPError("DialURL", l.config.Server, err))
	}

	// Check for context cancellation before binding
	select {
	case <-ctx.Done():
		c.Close() // Clean up connection on cancellation
		l.logger.Debug("ldap_connection_cancelled_before_bind",
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("connection cancelled before bind: %w", WrapLDAPError("Bind", l.config.Server, ctx.Err()))
	default:
	}

	if err = c.Bind(l.user, l.password); err != nil {
		c.Close() // Clean up connection on bind failure
		l.logger.Error("ldap_connection_bind_failed",
			slog.String("server", l.config.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to bind to LDAP server %s with user %s: %w", l.config.Server, l.user, WrapLDAPError("Bind", l.config.Server, err))
	}

	l.logger.Debug("ldap_connection_established",
		slog.String("server", l.config.Server),
		slog.Duration("duration", time.Since(start)))

	return c, nil
}

// GetPoolStats returns connection pool statistics if pooling is enabled.
// Returns nil if connection pooling is not configured.
//
// Returns:
//   - *PoolStats: Current pool statistics including active/idle connections, hits/misses, etc.
//   - nil: If connection pooling is not enabled
//
// This method is useful for monitoring and debugging connection pool performance.
// The statistics are updated in real-time and provide insights into pool efficiency.
func (l *LDAP) GetPoolStats() *PoolStats {
	if l.pool == nil {
		return nil
	}

	stats := l.pool.Stats()
	return &stats
}

// GetCacheStats returns cache statistics if caching is enabled.
// Returns an empty CacheStats struct if caching is not configured.
//
// Returns:
//   - CacheStats: Current cache statistics including hits/misses, memory usage, etc.
//
// This method is useful for monitoring and debugging cache performance.
// The statistics are updated in real-time and provide insights into cache efficiency.
func (l *LDAP) GetCacheStats() CacheStats {
	if l.cache == nil {
		return CacheStats{}
	}

	return l.cache.Stats()
}

// GetPerformanceStats returns comprehensive performance statistics.
// Returns an empty PerformanceStats struct if performance monitoring is not enabled.
//
// Returns:
//   - PerformanceStats: Current performance metrics including response times, error rates, etc.
//
// This method provides detailed insights into the performance characteristics of LDAP operations,
// including timing percentiles, cache hit ratios, and slow query detection.
func (l *LDAP) GetPerformanceStats() PerformanceStats {
	if l.perfMonitor == nil {
		return PerformanceStats{}
	}

	return l.perfMonitor.GetStats()
}

// ClearCache clears all cached entries if caching is enabled.
// This method is useful for cache invalidation scenarios or testing.
func (l *LDAP) ClearCache() {
	if l.cache != nil {
		l.cache.Clear()
		l.logger.Info("cache_cleared_manually")
	}
}

// Close closes the LDAP client and releases all resources.
// If connection pooling is enabled, this will close all pooled connections.
// If caching is enabled, this will shut down the cache and background tasks.
// If performance monitoring is enabled, this will close the performance monitor.
// This method should be called when the client is no longer needed to prevent resource leaks.
//
// Returns:
//   - error: Any error encountered during cleanup
//
// Example:
//
//	client, err := New(config, user, password)
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
func (l *LDAP) Close() error {
	var errors []error

	// Close performance monitor first
	if l.perfMonitor != nil {
		if err := l.perfMonitor.Close(); err != nil {
			errors = append(errors, fmt.Errorf("performance monitor close error: %w", err))
		}
		l.perfMonitor = nil
	}

	// Close cache
	if l.cache != nil {
		if err := l.cache.Close(); err != nil {
			errors = append(errors, fmt.Errorf("cache close error: %w", err))
		}
		l.cache = nil
	}

	// Close connection pool
	if l.pool != nil {
		if err := l.pool.Close(); err != nil {
			errors = append(errors, fmt.Errorf("connection pool close error: %w", err))
		}
		l.pool = nil
	}

	if len(errors) > 0 {
		return fmt.Errorf("multiple close errors: %v", errors)
	}

	l.logger.Info("ldap_client_closed")
	return nil
}
