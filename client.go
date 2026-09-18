package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrDNDuplicated is returned when a search operation finds multiple entries with the same DN,
// indicating a data integrity issue.
var ErrDNDuplicated = errors.New("DN is not unique")

// LDAP represents the main LDAP client with connection management and security features.
// LDAP is safe for concurrent use by multiple goroutines.
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
	policies         *policyCache  // memoised ppolicy pwdMaxAge per policy DN
}

// Config contains the configuration for LDAP connections
type Config struct {
	Server            string
	Port              int
	BaseDN            string
	IsActiveDirectory bool

	// PasswordPolicyDN names the OpenLDAP ppolicy entry that governs users
	// whose own entry carries no pwdPolicySubentry. It is only consulted for
	// password-expiry lookups on non-Active-Directory servers; Active
	// Directory reports expiry per user without it. Empty means expiry is
	// reported as unknown rather than guessed.
	PasswordPolicyDN string
	TLSConfig        *tls.Config
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// Additional configuration options
	Pool        *PoolConfig
	Cache       *CacheConfig
	Performance *PerformanceConfig
	Resilience  *ResilienceConfig
	Logger      *slog.Logger
	DialOptions []ldap.DialOpt

	// SkipConnectionCheck stops New from dialling the server to verify it is
	// reachable. The client is returned without that round trip, and the first
	// real operation is what finds out whether the directory answers.
	//
	// It is meant for tests that construct a client without a directory, and
	// for callers who want initialization not to block on the network. It does
	// not affect anything else: the cache, the connection pool and the
	// performance monitor are governed by their own flags, and pool warm-up by
	// Pool.MinConnections.
	//
	// Until v1.18.0 this was decided by the hostname instead — any server whose
	// name contained "localhost", "example.", "test.com" and a dozen other
	// substrings silently skipped the check along with the cache, the pool and
	// the metrics.
	SkipConnectionCheck bool

	// Optimization flags for enabling enhanced features
	EnableOptimizations bool // Enable all optimizations (caching, performance monitoring, bulk operations)
	EnableCache         bool // Enable caching separately (overrides EnableOptimizations for cache)
	EnableMetrics       bool // Enable performance metrics separately (overrides EnableOptimizations for metrics)
	EnableBulkOps       bool // Enable bulk operations separately (overrides EnableOptimizations for bulk)
}

// New creates a new LDAP client with the given configuration and optional functional options
func New(config Config, username, password string, opts ...Option) (*LDAP, error) {
	start := time.Now()

	// Value types cannot be nil, so no nil validation needed

	// Use provided logger or default
	logger := slog.Default()
	if config.Logger != nil {
		logger = config.Logger
	}

	logger.Info("ldap_client_initializing",
		slog.String("server", config.Server),
		slog.String("base_dn", config.BaseDN),
		slog.Bool("is_active_directory", config.IsActiveDirectory))

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
		config:   &config,
		user:     username,
		password: password,
		logger:   logger,
		policies: newPolicyCache(),
	}

	// Apply functional options before initialization
	for _, opt := range opts {
		opt(client)
	}

	// Re-bind the local logger variable so that subsequent component
	// initialization (cache, connection pool, circuit breaker, performance
	// monitor) emits its init logs through the caller-supplied logger when
	// WithLogger(...) was passed as an option. Without this, those logs would
	// still hit slog.Default() because `logger` was captured before options ran.
	logger = client.logger

	// Until v1.17.0 New set EnableOptimizations itself, so caching and metrics
	// were on for every client whatever the caller wrote. Now that the flags are
	// honoured, a caller who set none gets neither — and nothing fails to tell
	// them. This record is the signal for an operator upgrading across that
	// change; it is gated on a real server like the other initialization logs.
	if !config.EnableCache && !config.EnableMetrics && !config.EnableOptimizations {
		logger.Info("optimizations_disabled",
			slog.String("server", config.Server),
			slog.String("hint", "no cache and no metrics: set EnableCache, EnableMetrics or EnableOptimizations to enable them"))
	}

	// Initialize cache if enabled (skip for example servers).
	// config.Cache may have been set by the caller or by a WithCache option
	// applied above; client.config is &config, so both land in the same struct.
	if config.EnableCache || config.EnableOptimizations {
		cacheConfig := cacheConfigFor(config)
		cache, err := NewLRUCache(cacheConfig, logger)
		if err != nil {
			logger.Warn("cache_initialization_failed",
				slog.String("server", config.Server),
				slog.String("error", err.Error()))
		} else {
			client.cache = cache
			logger.Info("cache_initialized",
				slog.String("server", config.Server),
				slog.Int("max_entries", cacheConfig.MaxSize),
				slog.Duration("ttl", cacheConfig.TTL))
		}
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
	if config.Pool != nil {
		// NewConnectionPool fills its defaults into the config it is given, so it
		// gets a copy. The log below reads that copy, which is what the pool runs
		// with; config.Pool still holds what the caller wrote.
		poolConfig := poolConfigFor(config.Pool)
		pool, err := NewConnectionPool(poolConfig, config, username, password, logger)
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
				slog.Int("max_connections", poolConfig.MaxConnections),
				slog.Int("min_connections", poolConfig.MinConnections))
		}
	}

	// Initialize performance monitor if metrics are enabled
	if config.EnableMetrics || config.EnableOptimizations {
		perfConfig := performanceConfigFor(config)

		client.perfMonitor = NewPerformanceMonitor(perfConfig, logger)

		// Link cache and pool to performance monitor for integrated metrics
		if client.cache != nil {
			client.perfMonitor.SetCache(client.cache)
		}
		if client.connPool != nil {
			client.perfMonitor.SetConnectionPool(client.connPool)
		}

		logger.Info("performance_monitor_initialized",
			slog.String("server", config.Server),
			slog.Duration("slow_query_threshold", perfConfig.SlowQueryThreshold),
			slog.Float64("sample_rate", perfConfig.SampleRate))
	}

	// Verify the server answers, unless the caller asked not to.
	if !config.SkipConnectionCheck {
		conn, err := client.GetConnection()
		if err == nil {
			// The check took a connection out of the pool; without this it stays
			// checked out for the life of the client, so ActiveConnections never
			// falls back to zero and one slot of MaxConnections is gone.
			if releaseErr := client.ReleaseConnection(conn); releaseErr != nil {
				logger.Warn("initial_connection_release_failed",
					slog.String("server", config.Server),
					slog.String("error", releaseErr.Error()))
			}
		}
		if err != nil {
			logger.Error("ldap_client_initialization_failed",
				slog.String("server", config.Server),
				slog.String("error", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("failed to initialize LDAP client: %w", err)
		}
	}

	logger.Info("ldap_client_initialized_successfully",
		slog.String("server", config.Server),
		slog.Duration("duration", time.Since(start)))

	return client, nil
}

// cacheConfigFor resolves the cache configuration the client builds its cache
// from: the one the caller supplied through Config.Cache, WithCache or
// ConfigBuilder.WithCache, or the defaults when none was.
//
// The result is always a copy. NewLRUCache writes its defaults into the config
// it is handed, so passing the caller's struct through would rewrite the fields
// they left at zero and flip Enabled underneath them.
//
// Enabled is set here rather than read: activation is governed by
// Config.EnableCache and Config.EnableOptimizations, so reaching this function
// already means a cache was asked for.
func cacheConfigFor(config Config) *CacheConfig {
	cacheConfig := DefaultCacheConfig()
	if config.Cache != nil {
		copied := *config.Cache
		cacheConfig = &copied
	}
	cacheConfig.Enabled = true
	return cacheConfig
}

// performanceConfigFor resolves the performance monitor's configuration the
// same way as cacheConfigFor: from the caller's Config.Performance when it is
// set, from the defaults otherwise, and always as a copy, because the client
// enables monitoring on the result and that write must not land in the caller's
// struct.
func performanceConfigFor(config Config) *PerformanceConfig {
	perfConfig := DefaultPerformanceConfig()
	if config.Performance != nil {
		copied := *config.Performance
		perfConfig = &copied
	}
	perfConfig.Enabled = true
	return perfConfig
}

// poolConfigFor copies the caller's pool configuration. NewConnectionPool
// writes its defaults into whatever it is handed, so a caller who set only
// MaxConnections would find the remaining fields filled in behind their back.
// A nil config means no pool and is passed through unchanged.
func poolConfigFor(poolConfig *PoolConfig) *PoolConfig {
	if poolConfig == nil {
		return nil
	}
	copied := *poolConfig
	return &copied
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
func (l *LDAP) GetCircuitBreakerStats() map[string]any {
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
	// A pool without a performance monitor is an ordinary configuration:
	// Config.Pool is read on its own and does not imply EnableMetrics. Reporting
	// zeros there would answer "no connections" for a pool that has them, which
	// is the shape #247 is about, so the pool is read directly.
	if l.perfMonitor == nil {
		stats := PerformanceStats{}
		applyPoolStats(&stats, l.connPool)
		return stats
	}

	stats := l.perfMonitor.GetStats()
	if stats == nil {
		fallback := PerformanceStats{}
		applyPoolStats(&fallback, l.connPool)
		return fallback
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
	return New(*l.config, dn, password)
}

// ReleaseConnection properly returns a connection to the pool or closes it if no pool exists.
// This method should be used in defer statements instead of directly calling conn.Close()
// to ensure proper connection lifecycle management with connection pools.
//
// Parameters:
//   - conn: The LDAP connection to release
//
// Returns:
//   - error: Any error encountered during release/close
//
// Example:
//
//	conn, err := l.GetConnectionContext(ctx)
//	if err != nil {
//	    return err
//	}
//	defer l.ReleaseConnection(conn)
func (l *LDAP) ReleaseConnection(conn *ldap.Conn) error {
	if conn == nil {
		return nil
	}

	// If connection pool exists, return connection to pool
	if l.connPool != nil {
		if err := l.connPool.Put(conn); err != nil {
			l.logger.Debug("connection_pool_return_error",
				slog.String("error", err.Error()))
			// If Put fails, close the connection directly
			if closeErr := conn.Close(); closeErr != nil {
				return fmt.Errorf("failed to return to pool and close: %v, %v", err, closeErr)
			}
			return err
		}
		return nil
	}

	// No pool exists, close connection directly
	if err := conn.Close(); err != nil {
		l.logger.Debug("connection_close_error",
			slog.String("error", err.Error()))
		return err
	}

	return nil
}

// cacheEnabled returns true if caching is active for this client.
// Cache is enabled via either EnableCache or EnableOptimizations config flags.
func (l *LDAP) cacheEnabled() bool {
	return (l.config.EnableCache || l.config.EnableOptimizations) && l.cache != nil
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

	return errors.Join(errs...)
}

// ============================================================================
// Convenience Client Constructors (For backward compatibility)
// ============================================================================

// NewBasicClient creates a basic LDAP client with minimal configuration.
func NewBasicClient(config Config, username, password string) (*LDAP, error) {
	return New(config, username, password)
}

// NewPooledClient creates an LDAP client with connection pooling enabled.
func NewPooledClient(config Config, username, password string, maxConnections int) (*LDAP, error) {
	poolConfig := &PoolConfig{
		MaxConnections:      maxConnections,
		MinConnections:      2,
		MaxIdleTime:         10 * time.Minute,
		HealthCheckInterval: 1 * time.Minute,
	}
	return New(config, username, password, WithConnectionPool(poolConfig))
}

// NewCachedClient creates an LDAP client with caching enabled.
func NewCachedClient(config Config, username, password string, maxSize int, ttl time.Duration) (*LDAP, error) {
	cacheConfig := &CacheConfig{
		Enabled:     true,
		TTL:         ttl,
		MaxSize:     maxSize,
		MaxMemoryMB: 100,
	}
	return New(config, username, password, WithCache(cacheConfig))
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

	return New(config, username, password,
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
		return New(config, username, password, WithTLS(tlsConfig))
	}
	return New(config, username, password)
}

// NewReadOnlyClient creates an LDAP client optimized for read-only operations with caching.
func NewReadOnlyClient(config Config, username, password string) (*LDAP, error) {
	cacheConfig := &CacheConfig{
		Enabled:     true,
		TTL:         10 * time.Minute,
		MaxSize:     5000,
		MaxMemoryMB: 200,
	}

	return New(config, username, password, WithCache(cacheConfig))
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
	if l.cache != nil {
		stats := l.cache.Stats()
		return &stats
	}
	return &CacheStats{}
}

// ClearCache clears all cached entries
func (l *LDAP) ClearCache() {
	if l.cache != nil {
		l.cache.Clear()
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
	if len(samAccountNames) == 0 {
		return make(map[string]*User), nil
	}

	concurrency := 10
	if options != nil && options.BatchSize > 0 {
		concurrency = options.BatchSize
	}
	if concurrency > len(samAccountNames) {
		concurrency = len(samAccountNames)
	}

	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		result = make(map[string]*User, len(samAccountNames))
		errs   []error
	)

	jobs := make(chan string, len(samAccountNames))
	for _, sam := range samAccountNames {
		jobs <- sam
	}
	close(jobs)

	continueOnError := options != nil && options.ContinueOnError

	for range concurrency {
		wg.Go(func() {
			for sam := range jobs {
				user, err := l.FindUserBySAMAccountNameContext(ctx, sam)
				if err != nil {
					if errors.Is(err, ErrUserNotFound) {
						continue
					}
					mu.Lock()
					errs = append(errs, fmt.Errorf("bulk find failed for %s: %w", sam, err))
					mu.Unlock()
					if !continueOnError {
						return
					}
					continue
				}
				mu.Lock()
				result[sam] = user
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	if len(errs) > 0 {
		return result, errors.Join(errs...)
	}
	return result, nil
}

// createDirectConnection creates a new LDAP connection without using the pool,
// bound as the client's configured service account.
func (l *LDAP) createDirectConnection(ctx context.Context) (*ldap.Conn, error) {
	return l.dialAndBind(ctx, l.user, l.password)
}

// dialAndBind creates a new unpooled connection bound as the given identity.
//
// Callers that need a specific bind identity — an RFC 3062 self-service password
// change, which the directory authorises from the bind rather than from the
// request — must use this rather than the pool. Binding a pooled connection as
// an end user would leak that identity to whichever caller borrows it next.
//
// The returned connection is not managed by the pool; close it directly.
func (l *LDAP) dialAndBind(ctx context.Context, bindDN, bindPassword string) (*ldap.Conn, error) {
	// Check context first
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	start := time.Now()

	// Log connection establishment attempt
	l.logger.Debug("ldap_connection_establishing",
		slog.String("server", l.config.Server),
		slog.String("base_dn", l.config.BaseDN))

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
	if err := conn.Bind(bindDN, bindPassword); err != nil {
		_ = conn.Close()
		l.logger.Error("ldap_bind_failed",
			slog.String("server", l.config.Server),
			slog.String("user", bindDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	l.logger.Debug("ldap_connection_established",
		slog.String("server", l.config.Server),
		slog.String("user", bindDN),
		slog.Duration("duration", time.Since(start)))

	return conn, nil
}
