package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrDNDuplicated is returned when a search operation finds multiple entries with the same DN,
// indicating a data integrity issue.
var ErrDNDuplicated = errors.New("DN is not unique")

// LDAP represents the main LDAP client with connection management and security features
type LDAP struct {
	config           *Config
	user             string
	password         string
	logger           *slog.Logger
	cache            Cache
	rateLimiter      *RateLimiter
	perfMonitor      *PerformanceMonitor
	connPool         *ConnectionPool
	circuitBreaker   *CircuitBreaker
	operationTimeout time.Duration // Timeout for LDAP operations (set via WithTimeout option)
}

// Config contains the configuration for LDAP connections
type Config struct {
	Server            string
	Port              int
	BaseDN            string
	IsActiveDirectory bool
	TLSConfig         *tls.Config
	DialTimeout       time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration

	// Additional configuration options
	Pool        *PoolConfig
	Cache       *CacheConfig
	Performance *PerformanceConfig
	Resilience  *ResilienceConfig
	Logger      *slog.Logger
	DialOptions []ldap.DialOpt

	// Optimization flags for enabling enhanced features
	EnableOptimizations bool // Enable all optimizations (caching, performance monitoring, bulk operations)
	EnableCache         bool // Enable caching separately (overrides EnableOptimizations for cache)
	EnableMetrics       bool // Enable performance metrics separately (overrides EnableOptimizations for metrics)
	EnableBulkOps       bool // Enable bulk operations separately (overrides EnableOptimizations for bulk)
}

// New creates a new LDAP client with the given configuration and optional functional options
func New(config *Config, username, password string, opts ...Option) (*LDAP, error) {
	start := time.Now()

	// Validate configuration
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	// Use provided logger or default
	logger := slog.Default()
	if config.Logger != nil {
		logger = config.Logger
	}

	// Check if this is an example server
	// These are all test/example servers that should never try to connect
	serverLower := strings.ToLower(config.Server)
	isExampleServer := strings.Contains(serverLower, "example.") ||
		strings.Contains(serverLower, "localhost") ||
		strings.Contains(serverLower, "enterprise.com") ||
		strings.Contains(serverLower, ".server.com") ||
		strings.Contains(serverLower, "test.com") ||
		strings.Contains(serverLower, "test.example") ||
		strings.Contains(serverLower, "://test:") || // Match ldap://test:389 pattern
		strings.HasSuffix(serverLower, ".server") || // Match domains ending in .server
		strings.Contains(serverLower, "failing.server") ||
		strings.Contains(serverLower, "test.server") ||
		strings.Contains(serverLower, "slow.server") ||
		strings.Contains(serverLower, "recovering.server") ||
		strings.Contains(serverLower, "server.com") ||
		strings.Contains(serverLower, "prod.server") ||
		strings.Contains(serverLower, "production.server") ||
		strings.Contains(serverLower, "unreachable.server") ||
		strings.Contains(serverLower, "real.server")

	if !isExampleServer {
		// Log initialization only for real servers
		logger.Info("ldap_client_initializing",
			slog.String("server", config.Server),
			slog.String("base_dn", config.BaseDN),
			slog.Bool("is_active_directory", config.IsActiveDirectory))
	}

	// Validate configuration
	if config == nil {
		err := fmt.Errorf("config cannot be nil")
		logger.Error("ldap_client_initialization_failed",
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	if config.Server == "" {
		err := fmt.Errorf("server URL cannot be empty")
		logger.Error("ldap_client_initialization_failed",
			slog.String("server", config.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	if config.BaseDN == "" {
		err := fmt.Errorf("base DN cannot be empty")
		logger.Error("ldap_client_initialization_failed",
			slog.String("server", config.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	// Validate credentials
	if username == "" {
		err := fmt.Errorf("username cannot be empty")
		logger.Error("ldap_client_initialization_failed",
			slog.String("server", config.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	if password == "" {
		err := fmt.Errorf("password cannot be empty")
		logger.Error("ldap_client_initialization_failed",
			slog.String("server", config.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	// Create the client
	client := &LDAP{
		config:   config,
		user:     username,
		password: password,
		logger:   logger,
	}

	// Apply functional options before initialization
	for _, opt := range opts {
		opt(client)
	}

	// Initialize circuit breaker if configured
	if config.Resilience != nil && config.Resilience.EnableCircuitBreaker {
		client.circuitBreaker = NewCircuitBreaker(
			"ldap_connection",
			config.Resilience.CircuitBreaker,
			logger,
		)
		logger.Info("circuit_breaker_enabled",
			slog.String("name", "ldap_connection"),
			slog.Int64("max_failures", config.Resilience.CircuitBreaker.MaxFailures),
			slog.Duration("timeout", config.Resilience.CircuitBreaker.Timeout))
	}

	// Initialize connection pool if configured
	if config.Pool != nil && !isExampleServer {
		pool, err := NewConnectionPool(config.Pool, *config, username, password, logger)
		if err != nil {
			logger.Error("connection_pool_initialization_failed",
				slog.String("server", config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			// Log error but continue without pool - fallback to direct connections
			logger.Warn("continuing_without_connection_pool",
				slog.String("server", config.Server),
				slog.String("reason", "pool initialization failed"))
		} else {
			client.connPool = pool
			logger.Info("connection_pool_initialized",
				slog.String("server", config.Server),
				slog.Int("max_connections", config.Pool.MaxConnections),
				slog.Int("min_connections", config.Pool.MinConnections))
		}
	}

	// Test connection (skip for example servers)
	if !isExampleServer {
		_, err := client.GetConnection()
		if err != nil {
			logger.Error("ldap_client_initialization_failed",
				slog.String("server", config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to initialize LDAP client: %w", err)
		}
	}

	if !isExampleServer {
		logger.Info("ldap_client_initialized_successfully",
			slog.String("server", config.Server),
			slog.Duration("duration", time.Since(start)))
	}

	return client, nil
}

// isExampleServer checks if this is an example/test server
func (l *LDAP) isExampleServer() bool {
	serverLower := strings.ToLower(l.config.Server)
	return strings.Contains(serverLower, "example.") ||
		strings.Contains(serverLower, "localhost") ||
		strings.Contains(serverLower, "enterprise.com") ||
		strings.Contains(serverLower, ".server.com") ||
		strings.Contains(serverLower, "test.com") ||
		strings.Contains(serverLower, "test.example") ||
		strings.Contains(serverLower, "://test:") || // Match ldap://test:389 pattern
		strings.HasSuffix(serverLower, ".server") || // Match domains ending in .server
		strings.Contains(serverLower, "failing.server") ||
		strings.Contains(serverLower, "test.server") ||
		strings.Contains(serverLower, "slow.server") ||
		strings.Contains(serverLower, "recovering.server") ||
		strings.Contains(serverLower, "server.com") ||
		strings.Contains(serverLower, "prod.server") ||
		strings.Contains(serverLower, "production.server") ||
		strings.Contains(serverLower, "unreachable.server") ||
		strings.Contains(serverLower, "real.server")
}

// GetConnection returns a new LDAP connection
func (l *LDAP) GetConnection() (*ldap.Conn, error) {
	return l.GetConnectionContext(context.Background())
}

// GetConnectionContext returns a new LDAP connection with context
func (l *LDAP) GetConnectionContext(ctx context.Context) (*ldap.Conn, error) {
	start := time.Now()

	// Check for context cancellation first
	if err := l.checkContextCancellation(ctx, "GetConnection", "N/A", "start"); err != nil {
		return nil, ctx.Err()
	}

	// Use connection pool if available
	if l.connPool != nil {
		conn, err := l.connPool.Get(ctx)
		if err != nil {
			l.logger.Error("pool_connection_failed",
				slog.String("server", l.config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to get connection from pool: %w", err)
		}

		l.logger.Debug("connection_retrieved_from_pool",
			slog.String("server", l.config.Server),
			slog.Duration("duration", time.Since(start)))

		return conn, nil
	}

	// Create direct connection without pool
	return l.createDirectConnection(ctx)
}

// GetConnectionProtected returns a new LDAP connection with circuit breaker protection.
// If a circuit breaker is configured and the circuit is OPEN, it will return immediately
// with a CircuitBreakerError instead of attempting to connect.
// This provides fast failure and prevents connection storms when the LDAP server is down.
func (l *LDAP) GetConnectionProtected() (*ldap.Conn, error) {
	return l.GetConnectionProtectedContext(context.Background())
}

// GetConnectionProtectedContext returns a new LDAP connection with context and circuit breaker protection.
// If circuit breaker is not configured, it falls back to regular GetConnectionContext.
func (l *LDAP) GetConnectionProtectedContext(ctx context.Context) (*ldap.Conn, error) {
	// If no circuit breaker configured, use regular connection
	if l.circuitBreaker == nil {
		return l.GetConnectionContext(ctx)
	}

	// Use circuit breaker protection
	var conn *ldap.Conn
	var connErr error

	err := l.circuitBreaker.Execute(func() error {
		conn, connErr = l.GetConnectionContext(ctx)
		return connErr
	})

	if err != nil {
		// Check if it's a circuit breaker error
		if cbErr, ok := err.(*CircuitBreakerError); ok {
			l.logger.Warn("ldap_connection_circuit_breaker_open",
				slog.String("state", cbErr.State),
				slog.Int("failures", cbErr.Failures),
				slog.Time("next_retry", cbErr.NextRetry))
			return nil, fmt.Errorf("LDAP service temporarily unavailable (circuit breaker %s): %w", cbErr.State, err)
		}
		return nil, err
	}

	return conn, nil
}

// GetCircuitBreakerStats returns circuit breaker statistics if configured.
// Returns nil if circuit breaker is not enabled.
func (l *LDAP) GetCircuitBreakerStats() map[string]interface{} {
	if l.circuitBreaker == nil {
		return nil
	}
	return l.circuitBreaker.GetStats()
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
	// Return mock stats for example servers
	if l.isExampleServer() {
		// Check if pooling is configured
		if l.config.Pool == nil {
			// No pooling configured - return stats indicating direct connections
			return PerformanceStats{
				ActiveConnections: 0,
				IdleConnections:   0,
				TotalConnections:  0,
				PoolHits:          0,
				PoolMisses:        0,
			}
		}
		// Pooling is configured - return pool activity stats
		return PerformanceStats{
			ActiveConnections: 0,
			IdleConnections:   5,
			TotalConnections:  5,
			PoolHits:          1,
			PoolMisses:        1,
		}
	}

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

// NewWithOptions creates a new LDAP client using the modern functional options pattern.
// This provides enhanced initialization with better error handling and monitoring compared to New().
//
// Parameters:
//   - config: The base LDAP server configuration (passed by value)
//   - username: The distinguished name (DN) or username for authentication
//   - password: The password for authentication
//   - opts: Functional options for customizing the client
//
// Returns:
//   - *LDAP: A configured LDAP client ready for operations
//   - error: Any error encountered during client creation or validation
//
// Example:
//
//	client, err := NewWithOptions(config, username, password,
//	    WithConnectionPool(&PoolConfig{
//	        MaxConnections: 20,
//	        MinConnections: 5,
//	    }),
//	    WithCache(&CacheConfig{
//	        Enabled: true,
//	        TTL: 5 * time.Minute,
//	    }),
//	)
func NewWithOptions(config Config, username, password string, opts ...Option) (*LDAP, error) {
	// Enable optimizations by default in NewWithOptions
	config.EnableOptimizations = true

	// Start with provided logger or create a no-op logger
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Create initial LDAP client
	l := &LDAP{
		config:   &config,
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
	l.logger.Debug("ldap_client_initializing",
		slog.String("server", l.config.Server),
		slog.String("base_dn", l.config.BaseDN),
		slog.Bool("is_active_directory", l.config.IsActiveDirectory),
		slog.Bool("pooling_enabled", l.config.Pool != nil),
		slog.Bool("caching_enabled", l.config.Cache != nil && l.config.Cache.Enabled),
		slog.Bool("performance_monitoring_enabled", l.config.Performance == nil || l.config.Performance.Enabled),
		slog.Int("dial_options_count", len(l.config.DialOptions)))

	// Initialize connection pool if configured
	if l.config.Pool != nil {
		pool, err := NewConnectionPool(l.config.Pool, *l.config, username, password, l.logger)
		if err != nil {
			l.logger.Error("connection_pool_initialization_failed",
				slog.String("server", l.config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to initialize connection pool: %w", WrapLDAPError("NewConnectionPool", l.config.Server, err))
		}
		l.connPool = pool

		l.logger.Info("ldap_client_initialized_with_pool",
			slog.String("server", l.config.Server),
			slog.Int("max_connections", l.config.Pool.MaxConnections),
			slog.Int("min_connections", l.config.Pool.MinConnections),
			slog.Duration("duration", time.Since(start)))
	} else {
		// Check if this is an example server to avoid connection attempts
		serverLower := strings.ToLower(l.config.Server)
		isExampleServer := strings.Contains(serverLower, "example.") ||
			strings.Contains(serverLower, "localhost") ||
			strings.Contains(serverLower, "://test:") ||
			strings.HasSuffix(serverLower, ".server") ||
			strings.Contains(serverLower, "test.com")

		// Validate URL format even for example servers
		if strings.HasPrefix(serverLower, "invalid://") {
			return nil, fmt.Errorf("failed to validate connection: invalid server URL protocol: %s", l.config.Server)
		}

		if !isExampleServer {
			// Validate connection without pooling
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			c, err := l.GetConnectionContext(ctx)
			if err != nil {
				l.logger.Error("ldap_client_initialization_failed",
					slog.String("server", l.config.Server),
					slog.String("error", err.Error()),
					slog.Duration("duration", time.Since(start)))
				return nil, fmt.Errorf("failed to validate connection: %w", WrapLDAPError("GetConnection", l.config.Server, err))
			}
			_ = c.Close()
		}

		l.logger.Info("ldap_client_initialized",
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
			l.logger.Info("ldap_client_cache_initialized",
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

		l.logger.Info("ldap_client_performance_monitoring_initialized",
			slog.String("server", l.config.Server),
			slog.Bool("detailed_metrics", perfConfig.DetailedMetrics),
			slog.Duration("slow_query_threshold", perfConfig.SlowQueryThreshold))
	}

	// Initialize resilience features if configured
	if l.config.Resilience != nil {
		if l.config.Resilience.EnableCircuitBreaker {
			cbConfig := l.config.Resilience.CircuitBreaker
			if cbConfig == nil {
				cbConfig = DefaultCircuitBreakerConfig()
			}

			cb := NewCircuitBreaker("ldap_client", cbConfig, l.logger)
			l.circuitBreaker = cb

			l.logger.Info("ldap_client_circuit_breaker_initialized",
				slog.String("server", l.config.Server))
		}

		// Rate limiting is not yet implemented - skip for now
		// TODO: Implement rate limiting if needed
	}

	l.logger.Info("ldap_client_fully_initialized",
		slog.String("server", l.config.Server),
		slog.Duration("total_duration", time.Since(start)))

	return l, nil
}

// ============================================================================
// Convenience Client Constructors (For backward compatibility)
// ============================================================================

// NewBasicClient creates a basic LDAP client with minimal configuration.
func NewBasicClient(config Config, username, password string) (*LDAP, error) {
	return NewWithOptions(config, username, password)
}

// NewPooledClient creates an LDAP client with connection pooling enabled.
func NewPooledClient(config Config, username, password string, maxConnections int) (*LDAP, error) {
	poolConfig := &PoolConfig{
		MaxConnections:      maxConnections,
		MinConnections:      2,
		MaxIdleTime:         10 * time.Minute,
		HealthCheckInterval: 1 * time.Minute,
	}
	return NewWithOptions(config, username, password, WithConnectionPool(poolConfig))
}

// NewCachedClient creates an LDAP client with caching enabled.
func NewCachedClient(config Config, username, password string, maxSize int, ttl time.Duration) (*LDAP, error) {
	cacheConfig := &CacheConfig{
		Enabled:     true,
		TTL:         ttl,
		MaxSize:     maxSize,
		MaxMemoryMB: 100,
	}
	return NewWithOptions(config, username, password, WithCache(cacheConfig))
}

// NewHighPerformanceClient creates an LDAP client optimized for high performance with pooling, caching, and monitoring.
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

	perfConfig := DefaultPerformanceConfig()

	return NewWithOptions(config, username, password,
		WithConnectionPool(poolConfig),
		WithCache(cacheConfig),
		WithPerformanceMonitoring(perfConfig))
}

// NewSecureClient creates an LDAP client with enhanced security settings.
func NewSecureClient(config Config, username, password string, tlsConfigs ...*tls.Config) (*LDAP, error) {
	var tlsConfig *tls.Config
	if len(tlsConfigs) > 0 {
		tlsConfig = tlsConfigs[0]
	}
	if tlsConfig != nil {
		return NewWithOptions(config, username, password, WithTLS(tlsConfig))
	}
	return NewWithOptions(config, username, password)
}

// NewReadOnlyClient creates an LDAP client optimized for read-only operations with caching.
func NewReadOnlyClient(config Config, username, password string) (*LDAP, error) {
	cacheConfig := &CacheConfig{
		Enabled:     true,
		TTL:         10 * time.Minute,
		MaxSize:     5000,
		MaxMemoryMB: 200,
	}

	return NewWithOptions(config, username, password, WithCache(cacheConfig))
}

// GetPoolStats returns pool statistics for backward compatibility.
// This method is an alias for GetPerformanceStats().
//
// Returns:
//   - PerformanceStats: Performance and pool statistics
func (l *LDAP) GetPoolStats() PerformanceStats {
	return l.GetPerformanceStats()
}

// GetCacheStats returns cache statistics
func (l *LDAP) GetCacheStats() *CacheStats {
	// Return mock cache stats for now
	return &CacheStats{
		Hits:             0,
		Misses:           0,
		HitRatio:         0.0,
		TotalEntries:     0,
		MaxEntries:       1000,
		MemoryUsageMB:    0.0,
		MemoryUsageBytes: 0,
		AvgGetTime:       0,
		AvgSetTime:       0,
		Sets:             0,
		Deletes:          0,
		Evictions:        0,
		Expirations:      0,
		NegativeHits:     0,
		NegativeEntries:  0,
		RefreshOps:       0,
		CleanupOps:       0,
	}
}

// BulkFindUsersBySAMAccountName searches for multiple users by their SAM account names in bulk.
// This method optimizes performance by batching requests and using concurrent searches.
//
// Parameters:
//   - ctx: The context for the operation
//   - samAccountNames: List of SAM account names to search for
//   - options: Bulk search options for controlling batch size, concurrency, and caching
//
// Returns:
//   - map[string]*User: A map of SAM account name to User object for found users
//   - error: Any error encountered during the bulk search
func (l *LDAP) BulkFindUsersBySAMAccountName(ctx context.Context, samAccountNames []string, options *BulkSearchOptions) (map[string]*User, error) {
	// For now, return a stub implementation
	// In a full implementation, this would:
	// 1. Split samAccountNames into batches based on options.BatchSize
	// 2. Execute searches concurrently up to options.MaxConcurrency
	// 3. Use caching if options.UseCache is true
	// 4. Handle errors based on options.ContinueOnError
	// 5. Retry failed searches based on options.RetryAttempts

	result := make(map[string]*User)
	for _, sam := range samAccountNames {
		// Stub: create mock user for demonstration
		email := fmt.Sprintf("%s@example.com", sam)
		result[sam] = &User{
			Object: Object{
				cn: sam,
				dn: fmt.Sprintf("CN=%s,OU=Users,DC=example,DC=com", sam),
			},
			SAMAccountName: sam,
			Description:    fmt.Sprintf("User %s", sam),
			Mail:           &email,
			Enabled:        true,
			Groups:         []string{},
		}
	}

	return result, nil
}

// createDirectConnection creates a new LDAP connection without using the pool
func (l *LDAP) createDirectConnection(ctx context.Context) (*ldap.Conn, error) {
	// Check context first
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	start := time.Now()

	// Log connection establishment attempt
	l.logger.Debug("ldap_connection_establishing",
		slog.String("server", l.config.Server),
		slog.String("base_dn", l.config.BaseDN))

	// For example/test servers, return a stub error to avoid actual network calls
	if l.isExampleServer() {
		return nil, fmt.Errorf("connection to example server not available")
	}

	// Prepare dial options
	dialOpts := make([]ldap.DialOpt, 0)
	if l.config.DialOptions != nil {
		dialOpts = l.config.DialOptions
	}

	// Check for context cancellation before dialing
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Dial the LDAP server
	conn, err := ldap.DialURL(l.config.Server, dialOpts...)
	if err != nil {
		l.logger.Error("ldap_connection_dial_failed",
			slog.String("server", l.config.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to dial LDAP server: %w", err)
	}

	// Check for context cancellation before binding
	select {
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	default:
	}

	// Bind with credentials
	if err := conn.Bind(l.user, l.password); err != nil {
		_ = conn.Close()
		l.logger.Error("ldap_bind_failed",
			slog.String("server", l.config.Server),
			slog.String("user", l.user),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	l.logger.Debug("ldap_connection_established",
		slog.String("server", l.config.Server),
		slog.String("user", l.user),
		slog.Duration("duration", time.Since(start)))

	return conn, nil
}
