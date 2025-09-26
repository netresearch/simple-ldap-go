// Package ldap provides modern Go patterns for LDAP configuration and initialization.
package ldap

import (
	"crypto/tls"
	"log/slog"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Option represents a functional option for configuring an LDAP client.
// This follows the functional options pattern for flexible and extensible configuration.
type Option func(*LDAP)

// WithLogger sets a custom structured logger for LDAP operations.
// If not provided, a no-op logger will be used.
//
// Example:
//
//	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
//	client, err := New(&config, username, password, WithLogger(logger))
func WithLogger(logger *slog.Logger) Option {
	return func(l *LDAP) {
		if logger != nil {
			l.logger = logger
			l.config.Logger = logger
		}
	}
}

// WithTLS configures TLS settings for secure LDAP connections.
// This option allows fine-grained control over TLS configuration.
//
// Example:
//
//	tlsConfig := &tls.Config{
//	    InsecureSkipVerify: false,
//	    ServerName: "ldap.example.com",
//	}
//	client, err := New(&config, username, password, WithTLS(tlsConfig))
func WithTLS(tlsConfig *tls.Config) Option {
	return func(l *LDAP) {
		// Add TLS configuration to dial options
		if tlsConfig != nil {
			l.config.DialOptions = append(l.config.DialOptions, ldap.DialWithTLSConfig(tlsConfig))
		}
	}
}

// WithConnectionPool enables connection pooling with the specified configuration.
// Connection pooling significantly improves performance for high-volume applications.
//
// Example:
//
//	poolConfig := &PoolConfig{
//	    MaxConnections: 20,
//	    MinConnections: 5,
//	    MaxIdleTime: 10 * time.Minute,
//	    HealthCheckInterval: 1 * time.Minute,
//	}
//	client, err := New(&config, username, password, WithConnectionPool(poolConfig))
func WithConnectionPool(poolConfig *PoolConfig) Option {
	return func(l *LDAP) {
		if poolConfig != nil {
			l.config.Pool = poolConfig
		}
	}
}

// WithCache enables intelligent caching with the specified configuration.
// Caching improves performance for read-heavy workloads by reducing LDAP server load.
//
// Example:
//
//	cacheConfig := &CacheConfig{
//	    Enabled: true,
//	    TTL: 5 * time.Minute,
//	    MaxSize: 1000,
//	    MaxMemoryMB: 100,
//	}
//	client, err := New(&config, username, password, WithCache(cacheConfig))
func WithCache(cacheConfig *CacheConfig) Option {
	return func(l *LDAP) {
		if cacheConfig != nil {
			l.config.Cache = cacheConfig
		}
	}
}

// WithConnectionOptions configures connection settings for the LDAP client.
// This includes timeout settings, retry policies, and other connection-related configurations.
//
// Example:
//
//	connConfig := &ConnectionOptions{
//	    ConnectionTimeout: 30 * time.Second,
//	    OperationTimeout: 60 * time.Second,
//	    MaxRetries: 3,
//	    RetryDelay: 1 * time.Second,
//	}
//	client, err := New(&config, username, password, WithConnectionOptions(connConfig))
func WithConnectionOptions(connOptions *ConnectionOptions) Option {
	return func(l *LDAP) {
		if connOptions != nil {
			// Apply connection configuration
			if connOptions.ConnectionTimeout > 0 {
				l.config.DialOptions = append(l.config.DialOptions,
					ldap.DialWithDialer(&net.Dialer{
						Timeout: connOptions.ConnectionTimeout,
					}))
			}
		}
	}
}

// WithPerformanceMonitoring enables performance monitoring with the specified configuration.
// Performance monitoring provides detailed metrics and helps identify bottlenecks.
//
// Example:
//
//	perfConfig := &PerformanceConfig{
//	    Enabled: true,
//	    SlowQueryThreshold: 500 * time.Millisecond,
//	    MetricsInterval: 1 * time.Minute,
//	}
//	client, err := New(&config, username, password, WithPerformanceMonitoring(perfConfig))
func WithPerformanceMonitoring(perfConfig *PerformanceConfig) Option {
	return func(l *LDAP) {
		if perfConfig != nil {
			l.config.Performance = perfConfig
		}
	}
}

// WithDialOptions adds custom dial options for LDAP connections.
// This allows fine-grained control over connection establishment.
//
// Example:
//
//	dialOpts := []ldap.DialOpt{
//	    ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}),
//	}
//	client, err := New(&config, username, password, WithDialOptions(dialOpts...))
func WithDialOptions(dialOpts ...ldap.DialOpt) Option {
	return func(l *LDAP) {
		if len(dialOpts) > 0 {
			l.config.DialOptions = append(l.config.DialOptions, dialOpts...)
		}
	}
}

// WithTimeout sets operation timeouts for LDAP operations.
// This is a convenience option for common timeout scenarios.
//
// The connectionTimeout is used for establishing LDAP connections.
// The operationTimeout is stored in the LDAP client and can be used
// to create contexts with timeouts for individual LDAP operations.
//
// Example:
//
//	client, err := New(&config, username, password,
//	    WithTimeout(30*time.Second, 60*time.Second))
func WithTimeout(connectionTimeout, operationTimeout time.Duration) Option {
	return func(l *LDAP) {
		if connectionTimeout > 0 {
			l.config.DialOptions = append(l.config.DialOptions,
				ldap.DialWithDialer(&net.Dialer{
					Timeout: connectionTimeout,
				}))
		}
		// Store operation timeout for use in contexts
		if operationTimeout > 0 {
			l.operationTimeout = operationTimeout
		}
	}
}

// ConnectionOptions holds connection-related configuration options.
type ConnectionOptions struct {
	// ConnectionTimeout is the timeout for establishing LDAP connections
	ConnectionTimeout time.Duration
	// OperationTimeout is the timeout for LDAP operations
	OperationTimeout time.Duration
	// MaxRetries is the maximum number of retry attempts for failed operations
	MaxRetries int
	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration
	// EnableTLS forces TLS encryption for all connections
	EnableTLS bool
	// TLSMinVersion is the minimum TLS version to accept
	TLSMinVersion uint16
	// ValidateCertificates controls whether to validate server certificates
	ValidateCertificates bool
}

// DefaultConnectionOptions returns a ConnectionOptions with sensible defaults.
func DefaultConnectionOptions() *ConnectionOptions {
	return &ConnectionOptions{
		ConnectionTimeout:    30 * time.Second,
		OperationTimeout:     60 * time.Second,
		MaxRetries:           3,
		RetryDelay:           1 * time.Second,
		EnableTLS:            true,
		ValidateCertificates: true,
	}
}

// ResilienceConfig holds resilience-related configuration options.
type ResilienceConfig struct {
	// EnableCircuitBreaker enables circuit breaker protection for LDAP connections
	EnableCircuitBreaker bool
	// CircuitBreaker is the circuit breaker configuration
	CircuitBreaker *CircuitBreakerConfig
}

// DefaultResilienceConfig returns a ResilienceConfig with sensible defaults.
// Circuit breaker is disabled by default for backward compatibility.
func DefaultResilienceConfig() *ResilienceConfig {
	return &ResilienceConfig{
		EnableCircuitBreaker: false,
		CircuitBreaker:       DefaultCircuitBreakerConfig(),
	}
}

// WithCircuitBreaker enables circuit breaker protection with the given configuration.
// If config is nil, default configuration will be used.
//
// Example:
//
//	client, err := New(&config, username, password,
//	    WithCircuitBreaker(&CircuitBreakerConfig{
//	        MaxFailures: 5,
//	        Timeout: 30 * time.Second,
//	    }))
func WithCircuitBreaker(config *CircuitBreakerConfig) Option {
	return func(l *LDAP) {
		if l.config.Resilience == nil {
			l.config.Resilience = DefaultResilienceConfig()
		}
		l.config.Resilience.EnableCircuitBreaker = true
		if config != nil {
			l.config.Resilience.CircuitBreaker = config
		}
	}
}
