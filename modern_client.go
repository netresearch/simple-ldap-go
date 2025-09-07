// Package ldap provides modern Go patterns for LDAP client creation and management.
package ldap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// NewWithOptions creates a new LDAP client using the modern functional options pattern.
// This provides a flexible, extensible way to configure LDAP clients while maintaining
// backward compatibility with the existing New() function.
//
// Parameters:
//   - config: The base LDAP server configuration
//   - username: The distinguished name (DN) or username for authentication
//   - password: The password for authentication
//   - opts: Functional options for customizing the client
//
// Returns:
//   - *LDAP: A configured LDAP client ready for operations
//   - error: Any error encountered during client creation or validation
//
// Examples:
//
// Basic client with custom logger:
//
//	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
//	client, err := NewWithOptions(config, username, password,
//	    WithLogger(logger),
//	)
//
// High-performance client with pooling and caching:
//
//	client, err := NewWithOptions(config, username, password,
//	    WithConnectionPool(&PoolConfig{
//	        MaxConnections: 20,
//	        MinConnections: 5,
//	        MaxIdleTime: 10 * time.Minute,
//	    }),
//	    WithCache(&CacheConfig{
//	        Enabled: true,
//	        TTL: 5 * time.Minute,
//	        MaxSize: 1000,
//	    }),
//	    WithPerformanceMonitoring(&PerformanceConfig{
//	        Enabled: true,
//	        SlowQueryThreshold: 500 * time.Millisecond,
//	    }),
//	)
//
// Secure client with custom TLS and timeouts:
//
//	client, err := NewWithOptions(config, username, password,
//	    WithConnectionOptions(&ConnectionOptions{
//	        ConnectionTimeout: 30 * time.Second,
//	        OperationTimeout: 60 * time.Second,
//	        EnableTLS: true,
//	        ValidateCertificates: true,
//	    }),
//	    WithTimeout(30*time.Second, 60*time.Second),
//	)
func NewWithOptions(config Config, username, password string, opts ...Option) (*LDAP, error) {
	// Start with provided logger or create a no-op logger
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Create initial LDAP client
	l := &LDAP{
		config:   config,
		logger:   logger,
		user:     username,
		password: password,
	}

	// Apply all functional options
	for _, opt := range opts {
		opt(l)
	}

	// Re-validate logger after options are applied
	if l.logger == nil {
		l.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	start := time.Now()
	l.logger.Debug("ldap_modern_client_initializing",
		slog.String("server", l.config.Server),
		slog.String("base_dn", l.config.BaseDN),
		slog.Bool("is_active_directory", l.config.IsActiveDirectory),
		slog.Bool("pooling_enabled", l.config.Pool != nil),
		slog.Bool("caching_enabled", l.config.Cache != nil && l.config.Cache.Enabled),
		slog.Bool("performance_monitoring_enabled", l.config.Performance == nil || l.config.Performance.Enabled),
		slog.Int("dial_options_count", len(l.config.DialOptions)))

	// Initialize connection pool if configured
	if l.config.Pool != nil {
		pool, err := NewConnectionPool(l.config.Pool, l.config, username, password, l.logger)
		if err != nil {
			l.logger.Error("connection_pool_initialization_failed",
				slog.String("server", l.config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to initialize connection pool: %w", WrapLDAPError("NewConnectionPool", l.config.Server, err))
		}
		l.pool = pool
		
		l.logger.Info("ldap_modern_client_initialized_with_pool",
			slog.String("server", l.config.Server),
			slog.Int("max_connections", l.config.Pool.MaxConnections),
			slog.Int("min_connections", l.config.Pool.MinConnections),
			slog.Duration("duration", time.Since(start)))
	} else {
		// Validate connection without pooling
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		c, err := l.GetConnectionContext(ctx)
		if err != nil {
			l.logger.Error("ldap_modern_client_initialization_failed",
				slog.String("server", l.config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to validate connection: %w", WrapLDAPError("GetConnection", l.config.Server, err))
		}
		c.Close()

		l.logger.Info("ldap_modern_client_initialized",
			slog.String("server", l.config.Server),
			slog.Duration("duration", time.Since(start)))
	}

	// Initialize intelligent caching system if configured
	if l.config.Cache != nil && l.config.Cache.Enabled {
		cache, err := NewLRUCache(l.config.Cache, l.logger)
		if err != nil {
			l.logger.Error("cache_initialization_failed",
				slog.String("server", l.config.Server),
				slog.String("error", err.Error()))
			// Don't fail client creation if cache fails, just log and continue without cache
		} else {
			l.cache = cache
			l.logger.Info("ldap_modern_client_cache_initialized",
				slog.String("server", l.config.Server),
				slog.Int("max_size", l.config.Cache.MaxSize),
				slog.Duration("ttl", l.config.Cache.TTL),
				slog.Int("max_memory_mb", l.config.Cache.MaxMemoryMB))
		}
	}

	// Initialize performance monitoring system
	perfConfig := l.config.Performance
	if perfConfig == nil {
		perfConfig = DefaultPerformanceConfig()
	}
	
	if perfConfig.Enabled {
		perfMonitor := NewPerformanceMonitor(perfConfig, l.logger)
		l.perfMonitor = perfMonitor
		
		// Link cache and pool to performance monitor for integrated metrics
		if l.cache != nil {
			perfMonitor.SetCache(l.cache)
		}
		if l.pool != nil {
			perfMonitor.SetConnectionPool(l.pool)
		}
		
		l.logger.Info("ldap_modern_client_performance_monitor_initialized",
			slog.String("server", l.config.Server),
			slog.Duration("slow_query_threshold", perfConfig.SlowQueryThreshold))
	}

	return l, nil
}

// WithConnection provides a modern resource management pattern for LDAP connections.
// This method ensures proper connection cleanup and provides a clean API for operations
// that need a connection.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - fn: Function to execute with the connection
//
// Returns:
//   - error: Any error encountered during connection acquisition or function execution
//
// Example:
//
//	err := client.WithConnection(ctx, func(conn *ldap.Conn) error {
//	    // Use the connection for multiple operations
//	    searchResult, err := conn.Search(searchRequest)
//	    if err != nil {
//	        return err
//	    }
//	    // Process results...
//	    return nil
//	})
func (l *LDAP) WithConnection(ctx context.Context, fn func(*ldap.Conn) error) error {
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			l.logger.Error("connection_close_failed",
				slog.String("error", closeErr.Error()))
		}
	}()

	return fn(conn)
}

// Transaction provides a transaction-like pattern for LDAP operations.
// While LDAP doesn't support true transactions, this method provides a way to
// group operations together with consistent error handling and resource management.
//
// Parameters:
//   - ctx: Context for controlling the transaction timeout and cancellation
//   - fn: Function to execute within the transaction context
//
// Returns:
//   - error: Any error encountered during the transaction
//
// Example:
//
//	err := client.Transaction(ctx, func(tx *Transaction) error {
//	    user, err := tx.CreateUser(userData, password)
//	    if err != nil {
//	        return err
//	    }
//	    
//	    err = tx.AddUserToGroup(user.DN(), groupDN)
//	    if err != nil {
//	        // Attempt cleanup
//	        tx.DeleteUser(user.DN())
//	        return err
//	    }
//	    
//	    return nil
//	})
type Transaction struct {
	client *LDAP
	ctx    context.Context
	conn   *ldap.Conn
}

// Transaction executes a function within a transaction-like context.
func (l *LDAP) Transaction(ctx context.Context, fn func(tx *Transaction) error) error {
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection for transaction: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			l.logger.Error("transaction_connection_close_failed",
				slog.String("error", closeErr.Error()))
		}
	}()

	tx := &Transaction{
		client: l,
		ctx:    ctx,
		conn:   conn,
	}

	return fn(tx)
}

// CreateUser creates a user within a transaction context.
func (tx *Transaction) CreateUser(user FullUser, password string) (string, error) {
	// Use the transaction's connection for the operation
	return tx.client.createUserWithConnection(tx.ctx, tx.conn, user, password)
}

// DeleteUser deletes a user within a transaction context.
func (tx *Transaction) DeleteUser(dn string) error {
	return tx.client.deleteUserWithConnection(tx.ctx, tx.conn, dn)
}

// AddUserToGroup adds a user to a group within a transaction context.
func (tx *Transaction) AddUserToGroup(userDN, groupDN string) error {
	return tx.client.addUserToGroupWithConnection(tx.ctx, tx.conn, userDN, groupDN)
}

// RemoveUserFromGroup removes a user from a group within a transaction context.
func (tx *Transaction) RemoveUserFromGroup(userDN, groupDN string) error {
	return tx.client.removeUserFromGroupWithConnection(tx.ctx, tx.conn, userDN, groupDN)
}

// Modern factory methods for common configurations

// NewBasicClient creates a basic LDAP client with minimal configuration.
// This is equivalent to the traditional New() function but uses the modern pattern.
func NewBasicClient(config Config, username, password string) (*LDAP, error) {
	return NewWithOptions(config, username, password)
}

// NewPooledClient creates an LDAP client optimized for high-volume operations.
// This client uses connection pooling with sensible defaults.
func NewPooledClient(config Config, username, password string, maxConnections int) (*LDAP, error) {
	poolConfig := &PoolConfig{
		MaxConnections:      maxConnections,
		MinConnections:      maxConnections / 4,
		MaxIdleTime:         10 * time.Minute,
		HealthCheckInterval: 1 * time.Minute,
	}

	return NewWithOptions(config, username, password,
		WithConnectionPool(poolConfig),
		WithPerformanceMonitoring(&PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 500 * time.Millisecond,
			MetricsRetentionPeriod:    1 * time.Minute,
		}),
	)
}

// NewCachedClient creates an LDAP client optimized for read-heavy workloads.
// This client uses intelligent caching with sensible defaults.
func NewCachedClient(config Config, username, password string, cacheSize int, cacheTTL time.Duration) (*LDAP, error) {
	cacheConfig := &CacheConfig{
		Enabled:     true,
		TTL:         cacheTTL,
		MaxSize:     cacheSize,
		MaxMemoryMB: 100,
	}

	return NewWithOptions(config, username, password,
		WithCache(cacheConfig),
		WithPerformanceMonitoring(&PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 200 * time.Millisecond,
			MetricsRetentionPeriod:    30 * time.Second,
		}),
	)
}

// NewHighPerformanceClient creates an LDAP client optimized for maximum performance.
// This client combines connection pooling, caching, and performance monitoring.
func NewHighPerformanceClient(config Config, username, password string) (*LDAP, error) {
	poolConfig := &PoolConfig{
		MaxConnections:      20,
		MinConnections:      5,
		MaxIdleTime:         10 * time.Minute,
		HealthCheckInterval: 1 * time.Minute,
	}

	cacheConfig := &CacheConfig{
		Enabled:     true,
		TTL:         5 * time.Minute,
		MaxSize:     1000,
		MaxMemoryMB: 100,
	}

	perfConfig := &PerformanceConfig{
		Enabled:                true,
		SlowQueryThreshold:     300 * time.Millisecond,
		MetricsRetentionPeriod: 30 * time.Minute,
		SampleRate:             1.0,
	}

	return NewWithOptions(config, username, password,
		WithConnectionPool(poolConfig),
		WithCache(cacheConfig),
		WithPerformanceMonitoring(perfConfig),
	)
}

// NewSecureClient creates an LDAP client with enhanced security settings.
// This client enforces TLS, validates certificates, and uses conservative timeouts.
func NewSecureClient(config Config, username, password string) (*LDAP, error) {
	connOptions := &ConnectionOptions{
		ConnectionTimeout:    30 * time.Second,
		OperationTimeout:     60 * time.Second,
		MaxRetries:          3,
		RetryDelay:          2 * time.Second,
		EnableTLS:           true,
		ValidateCertificates: true,
	}

	return NewWithOptions(config, username, password,
		WithConnectionOptions(connOptions),
		WithPerformanceMonitoring(&PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 1 * time.Second,
			MetricsRetentionPeriod:    1 * time.Minute,
		}),
	)
}

// NewReadOnlyClient creates an LDAP client optimized for read-only operations.
// This client uses aggressive caching and connection pooling for read performance.
func NewReadOnlyClient(config Config, username, password string) (*LDAP, error) {
	// Read-only clients benefit from longer cache TTLs
	cacheConfig := &CacheConfig{
		Enabled:     true,
		TTL:         15 * time.Minute,
		MaxSize:     2000,
		MaxMemoryMB: 200,
	}

	// Smaller pool since we're not doing writes
	poolConfig := &PoolConfig{
		MaxConnections:      10,
		MinConnections:      3,
		MaxIdleTime:         15 * time.Minute,
		HealthCheckInterval: 2 * time.Minute,
	}

	return NewWithOptions(config, username, password,
		WithConnectionPool(poolConfig),
		WithCache(cacheConfig),
		WithPerformanceMonitoring(&PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 200 * time.Millisecond,
			MetricsRetentionPeriod:    30 * time.Second,
		}),
	)
}

// Helper methods for transaction operations (these would need to be implemented)

// createUserWithConnection creates a user using a specific connection
func (l *LDAP) createUserWithConnection(ctx context.Context, conn *ldap.Conn, user FullUser, password string) (string, error) {
	// This would implement user creation using the provided connection
	// For now, this is a placeholder that would call the existing CreateUser method
	return l.CreateUserContext(ctx, user, password)
}

// deleteUserWithConnection deletes a user using a specific connection
func (l *LDAP) deleteUserWithConnection(ctx context.Context, conn *ldap.Conn, dn string) error {
	// This would implement user deletion using the provided connection
	// For now, this is a placeholder that would call the existing DeleteUser method
	return l.DeleteUserContext(ctx, dn)
}

// addUserToGroupWithConnection adds a user to a group using a specific connection
func (l *LDAP) addUserToGroupWithConnection(ctx context.Context, conn *ldap.Conn, userDN, groupDN string) error {
	// This would implement adding user to group using the provided connection
	// For now, this is a placeholder that would call the existing AddUserToGroup method
	return l.AddUserToGroupContext(ctx, userDN, groupDN)
}

// removeUserFromGroupWithConnection removes a user from a group using a specific connection
func (l *LDAP) removeUserFromGroupWithConnection(ctx context.Context, conn *ldap.Conn, userDN, groupDN string) error {
	// This would implement removing user from group using the provided connection
	// For now, this is a placeholder that would call the existing RemoveUserFromGroup method
	return l.RemoveUserFromGroupContext(ctx, userDN, groupDN)
}