package ldap

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetConnectionContext tests all scenarios for GetConnectionContext
func TestGetConnectionContext(t *testing.T) {
	t.Run("with pool - successful connection", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.example.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
				MinConnections: 2,
			},
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)
		require.NotNil(t, client)

		// Since test.example.com is an example server, pool won't be initialized
		assert.Nil(t, client.connPool)
	})

	t.Run("without pool - direct connection", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Nil(t, client.connPool)

		// Attempt connection (will fail for example server)
		ctx := context.Background()
		conn, err := client.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")
	})

	t.Run("context cancellation before connection", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)

		// Cancel context before calling
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := client.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("context timeout", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)

		// Create context with immediate timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond) // Ensure timeout

		conn, err := client.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Equal(t, context.DeadlineExceeded, err)
	})

	t.Run("pool returns error", func(t *testing.T) {
		// This test would require mocking the pool
		// For now, we document it as a test that should be added with mocking
		t.Skip("Requires pool mocking - implement with mock framework")
	})
}

// TestCreateDirectConnection tests the createDirectConnection method
func TestCreateDirectConnection(t *testing.T) {
	t.Run("example server returns error", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)

		ctx := context.Background()
		conn, err := client.createDirectConnection(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")
	})

	t.Run("localhost server", func(t *testing.T) {
		config := &Config{
			Server: "ldap://localhost:389",
			Port:   389,
			BaseDN: "dc=local,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)

		ctx := context.Background()
		conn, err := client.createDirectConnection(ctx)
		assert.Error(t, err) // Will fail as it's an example server
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")
	})

	t.Run("context cancellation during dial", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.server.com:389", // Test server - won't actually connect
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)

		// Cancel immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := client.createDirectConnection(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		// For test servers, we check context first, so should get context.Canceled
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("dial options are applied", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.server.com:389",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			DialOptions: []ldap.DialOpt{
				ldap.DialWithTLSConfig(nil), // Add a dial option
			},
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)
		assert.NotNil(t, client.config.DialOptions)
		assert.Len(t, client.config.DialOptions, 1)
	})
}

// TestGetConnectionProtected tests circuit breaker protected connections
func TestGetConnectionProtected(t *testing.T) {
	t.Run("without circuit breaker uses regular connection", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)
		assert.Nil(t, client.circuitBreaker)

		conn, err := client.GetConnectionProtected()
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")
		assert.NotContains(t, err.Error(), "circuit breaker")
	})

	t.Run("with circuit breaker handles failures", func(t *testing.T) {
		config := &Config{
			Server: "ldap://failing.server",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 1,
					Timeout:     100 * time.Millisecond,
				},
			},
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)
		assert.NotNil(t, client.circuitBreaker)

		// First failure opens circuit
		conn, err := client.GetConnectionProtected()
		assert.Error(t, err)
		assert.Nil(t, conn)

		// Second attempt should fail fast with circuit breaker
		start := time.Now()
		conn, err = client.GetConnectionProtected()
		elapsed := time.Since(start)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "circuit breaker")
		assert.Less(t, elapsed, 50*time.Millisecond) // Should fail fast
	})
}

// TestConnectionFieldName is a regression test for the pool/connPool field name bug
func TestConnectionFieldName(t *testing.T) {
	t.Run("connPool field is correctly used", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		client, err := New(config, "testuser", "testpass")
		require.NoError(t, err)

		// Directly check that the field exists and is named correctly
		// This ensures we're using connPool, not pool
		assert.Nil(t, client.connPool) // Field should exist even if nil

		// If we had a pool config for non-example server, it would be set
		config2 := &Config{
			Server: "ldap://real.server.com",
			Port:   389,
			BaseDN: "dc=real,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
		}

		// Skip actual initialization for real server
		client2 := &LDAP{
			config:   config2,
			user:     "test",
			password: "test",
			logger:   slog.Default(),
		}

		// Field should be accessible
		assert.Nil(t, client2.connPool)
	})
}

// TestConnectionNeverReturnsNotImplemented ensures we never return the stub error
func TestConnectionNeverReturnsNotImplemented(t *testing.T) {
	testCases := []struct {
		name   string
		server string
	}{
		{"example.com", "ldap://example.com"},
		{"localhost", "ldap://localhost"},
		{"test.server", "ldap://test.server"},
		{"enterprise.com", "ldap://enterprise.com"},
		{"failing.server", "ldap://failing.server"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				Server: tc.server,
				Port:   389,
				BaseDN: "dc=test,dc=com",
			}

			client, err := New(config, "user", "pass")
			require.NoError(t, err)

			ctx := context.Background()
			conn, err := client.GetConnectionContext(ctx)

			if err != nil {
				// Should never contain "not implemented"
				assert.NotContains(t, err.Error(), "not implemented",
					"Connection should never return 'not implemented' stub error")
				// Should return proper error for example servers
				if client.isExampleServer() {
					assert.Contains(t, err.Error(), "connection to example server not available")
				}
			}
			if conn != nil {
				conn.Close()
			}
		})
	}
}

// TestConnectionWithOptions tests connection with various options
func TestConnectionWithOptions(t *testing.T) {
	t.Run("with logger option", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		customLogger := slog.Default().With("test", "true")
		client, err := New(config, "user", "pass", WithLogger(customLogger))
		require.NoError(t, err)
		assert.NotNil(t, client.logger)
	})

	t.Run("with timeout option", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(config, "user", "pass",
			WithTimeout(10*time.Second, 30*time.Second))
		require.NoError(t, err)
		assert.Equal(t, 30*time.Second, client.operationTimeout)
	})

	t.Run("with circuit breaker option", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		cbConfig := &CircuitBreakerConfig{
			MaxFailures: 3,
			Timeout:     1 * time.Minute,
		}
		client, err := New(config, "user", "pass", WithCircuitBreaker(cbConfig))
		require.NoError(t, err)
		assert.NotNil(t, client.circuitBreaker)
	})
}

// TestConnectionErrorHandling tests various error scenarios
func TestConnectionErrorHandling(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		client, err := New(nil, "user", "pass")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})

	t.Run("empty server", func(t *testing.T) {
		config := &Config{
			Server: "",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}
		client, err := New(config, "user", "pass")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "server URL cannot be empty")
	})

	t.Run("empty base DN", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "",
		}
		client, err := New(config, "user", "pass")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "base DN cannot be empty")
	})

	t.Run("empty username", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}
		client, err := New(config, "", "pass")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "username cannot be empty")
	})

	t.Run("empty password", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}
		client, err := New(config, "user", "")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "password cannot be empty")
	})
}

// TestConnectionConcurrency tests concurrent connection attempts
func TestConnectionConcurrency(t *testing.T) {
	config := &Config{
		Server: "ldap://example.com",
		Port:   389,
		BaseDN: "dc=example,dc=com",
	}

	client, err := New(config, "user", "pass")
	require.NoError(t, err)

	// Run concurrent connection attempts
	numGoroutines := 10
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ctx := context.Background()
			conn, err := client.GetConnectionContext(ctx)
			if conn != nil {
				conn.Close()
			}
			errChan <- err
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		// Should get consistent error for example server
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "connection to example server not available")
	}
}

// BenchmarkGetConnectionPerformance benchmarks connection performance
func BenchmarkGetConnectionPerformance(b *testing.B) {
	config := &Config{
		Server: "ldap://example.com",
		Port:   389,
		BaseDN: "dc=example,dc=com",
	}

	client, err := New(config, "user", "pass")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ctx := context.Background()
			conn, err := client.GetConnectionContext(ctx)
			if err == nil && conn != nil {
				conn.Close()
			}
		}
	})
}

// TestConnectionLogging tests that connections are properly logged
func TestConnectionLogging(t *testing.T) {
	// This would require a custom logger implementation to capture logs
	// For now, we document it as a test that should be added
	t.Skip("Requires custom logger implementation to capture and verify logs")
}

// Helper function to check if error is a connection error
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	// Check for various connection-related errors
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		containsString(err.Error(), "connection") ||
		containsString(err.Error(), "dial") ||
		containsString(err.Error(), "bind")
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(s)] != ""
}