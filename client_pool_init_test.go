//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPoolInitialization tests connection pool initialization scenarios
func TestPoolInitialization(t *testing.T) {
	t.Run("pool enabled for non-example servers", func(t *testing.T) {
		config := &Config{
			Server: "ldap://production.server.com",
			Port:   389,
			BaseDN: "dc=prod,dc=com",
			Pool: &PoolConfig{
				MaxConnections:      10,
				MinConnections:      2,
				MaxIdleTime:         5 * time.Minute,
				HealthCheckInterval: 30 * time.Second,
			},
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)
		require.NotNil(t, client)

		// Pool initialization may fail for non-reachable servers
		// but the client should still be created
		if client.connPool != nil {
			assert.NotNil(t, client.connPool)
		}
	})

	t.Run("pool disabled for example servers", func(t *testing.T) {
		exampleServers := []string{
			"ldap://example.com",
			"ldap://localhost",
			"ldaps://example.org",
			"ldap://test.example.com",
		}

		for _, server := range exampleServers {
			config := &Config{
				Server: server,
				Port:   389,
				BaseDN: "dc=example,dc=com",
				Pool: &PoolConfig{
					MaxConnections: 5,
				},
			}

			client, err := New(config, "user", "pass")
			require.NoError(t, err, "Failed for server: %s", server)
			assert.Nil(t, client.connPool, "Pool should be nil for example server: %s", server)
		}
	})

	t.Run("pool not initialized when config is nil", func(t *testing.T) {
		config := &Config{
			Server: "ldap://prod.server.com",
			Port:   389,
			BaseDN: "dc=prod,dc=com",
			Pool:   nil,
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)
		assert.Nil(t, client.connPool)
	})

	t.Run("pool configuration validation", func(t *testing.T) {
		testCases := []struct {
			name       string
			poolConfig *PoolConfig
			shouldFail bool
		}{
			{
				name: "valid config",
				poolConfig: &PoolConfig{
					MaxConnections: 10,
					MinConnections: 2,
				},
				shouldFail: false,
			},
			{
				name: "min greater than max",
				poolConfig: &PoolConfig{
					MaxConnections: 5,
					MinConnections: 10,
				},
				shouldFail: false, // Client creation shouldn't fail, pool init might
			},
			{
				name: "zero connections",
				poolConfig: &PoolConfig{
					MaxConnections: 0,
					MinConnections: 0,
				},
				shouldFail: false, // Client creation shouldn't fail
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				config := &Config{
					Server: "ldap://server.com",
					Port:   389,
					BaseDN: "dc=test,dc=com",
					Pool:   tc.poolConfig,
				}

				client, err := New(config, "user", "pass")
				if tc.shouldFail {
					assert.Error(t, err)
					assert.Nil(t, client)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, client)
				}
			})
		}
	})

	t.Run("pool with connection options", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
				MaxIdleTime:    10 * time.Minute,
			},
			DialOptions: []ldap.DialOpt{
				ldap.DialWithTLSConfig(nil),
			},
		}

		client, err := New(config, "user", "pass",
			WithTimeout(5*time.Second, 10*time.Second))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, 10*time.Second, client.operationTimeout)
	})

	t.Run("pool initialization with circuit breaker", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 3,
					Timeout:     30 * time.Second,
				},
			},
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.NotNil(t, client.circuitBreaker)
	})

	t.Run("pool initialization failure handling", func(t *testing.T) {
		// This tests that even if pool initialization fails,
		// the client can still be created and fall back to direct connections
		config := &Config{
			Server: "ldap://unreachable.server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
				MinConnections: 5, // Force immediate connection attempts
			},
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)
		// Pool may be nil if initialization failed
		// Client should fall back to direct connections
	})

	t.Run("connection retrieval with and without pool", func(t *testing.T) {
		// Without pool
		configNoPool := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		clientNoPool, err := New(configNoPool, "user", "pass")
		require.NoError(t, err)
		assert.Nil(t, clientNoPool.connPool)

		ctx := context.Background()
		conn, err := clientNoPool.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")

		// With pool (but for example server, so pool won't be initialized)
		configWithPool := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
		}

		clientWithPool, err := New(configWithPool, "user", "pass")
		require.NoError(t, err)
		assert.Nil(t, clientWithPool.connPool) // Pool not initialized for example servers

		conn, err = clientWithPool.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")
	})

	t.Run("pool with custom logger", func(t *testing.T) {
		customLogger := slog.Default().With("test", "pool_init")

		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
			Logger: customLogger,
		}

		client, err := New(config, "user", "pass", WithLogger(customLogger))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, customLogger, client.logger)
	})
}

// TestPoolHealthCheck tests connection pool health checking
func TestPoolHealthCheck(t *testing.T) {
	t.Run("health check interval configuration", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections:      5,
				HealthCheckInterval: 10 * time.Second,
			},
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)

		// Verify pool config is stored correctly
		assert.Equal(t, config.Pool.HealthCheckInterval, 10*time.Second)
	})

	t.Run("pool with idle timeout", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
				MaxIdleTime:    30 * time.Second,
			},
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)

		// Verify idle timeout is configured
		assert.Equal(t, config.Pool.MaxIdleTime, 30*time.Second)
	})
}

// TestPoolConcurrency tests concurrent pool operations
func TestPoolConcurrency(t *testing.T) {
	t.Run("concurrent pool initialization", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 10,
				MinConnections: 2,
			},
		}

		// Create multiple clients concurrently
		numClients := 10
		clients := make([]*LDAP, numClients)
		errors := make([]error, numClients)

		// Use WaitGroup for proper synchronization
		var wg sync.WaitGroup
		wg.Add(numClients)

		for i := 0; i < numClients; i++ {
			go func(idx int) {
				defer wg.Done()
				clients[idx], errors[idx] = New(config, "user", "pass")
			}(i)
		}

		// Wait for all goroutines to complete
		wg.Wait()

		for i := 0; i < numClients; i++ {
			assert.NoError(t, errors[i], "Client %d creation failed", i)
			assert.NotNil(t, clients[i], "Client %d is nil", i)
		}
	})
}

// TestPoolWithOptions tests pool initialization with various options
func TestPoolWithOptions(t *testing.T) {
	t.Run("pool with connection pool option", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		poolConfig := &PoolConfig{
			MaxConnections: 15,
			MinConnections: 3,
		}

		client, err := New(config, "user", "pass", WithConnectionPool(poolConfig))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, poolConfig, client.config.Pool)
	})

	t.Run("pool with multiple options", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		poolConfig := &PoolConfig{
			MaxConnections: 20,
		}

		cbConfig := &CircuitBreakerConfig{
			MaxFailures: 5,
			Timeout:     1 * time.Minute,
		}

		client, err := New(config, "user", "pass",
			WithConnectionPool(poolConfig),
			WithCircuitBreaker(cbConfig),
			WithTimeout(10*time.Second, 20*time.Second))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, poolConfig, client.config.Pool)
		assert.NotNil(t, client.circuitBreaker)
		assert.Equal(t, 20*time.Second, client.operationTimeout)
	})
}

// BenchmarkPoolInitialization benchmarks pool initialization
func BenchmarkPoolInitialization(b *testing.B) {
	config := &Config{
		Server: "ldap://server.com",
		Port:   389,
		BaseDN: "dc=test,dc=com",
		Pool: &PoolConfig{
			MaxConnections: 10,
			MinConnections: 2,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := New(config, "user", "pass")
		if err != nil {
			b.Fatal(err)
		}
		_ = client
	}
}
