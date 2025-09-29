//go:build !integration

package ldap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegressionPoolConnPoolFieldName prevents regression of the pool/connPool field name bug
// This bug was introduced in commit 3994167 where field references were incorrect
func TestRegressionPoolConnPoolFieldName(t *testing.T) {
	t.Run("ensure connPool field is used consistently", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
		}

		// Create client with reflection to check field
		client := &LDAP{
			config:   config,
			user:     "test",
			password: "test",
			logger:   slog.Default(),
		}

		// Field should be accessible as connPool, not pool
		assert.Nil(t, client.connPool)

		// This should compile - if it doesn't, the field name is wrong
		var _ = client.connPool
	})

	t.Run("GetConnectionContext uses connPool not pool", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		// The connection attempt will fail, but should never return "not implemented"
		ctx := context.Background()
		conn, err := client.GetConnectionContext(ctx)

		if err != nil {
			assert.NotContains(t, err.Error(), "not implemented",
				"Connection must never return 'not implemented' stub error")
			assert.NotContains(t, err.Error(), "connection not implemented",
				"Connection must never return 'connection not implemented' error")
		}
		if conn != nil {
			_ = conn.Close()
		}
	})
}

// TestRegressionConnectionNotImplemented prevents the "connection not implemented" stub error
func TestRegressionConnectionNotImplemented(t *testing.T) {
	testCases := []struct {
		name       string
		server     string
		shouldFail bool
		errorMsg   string
	}{
		{
			name:       "example.com returns proper error",
			server:     "ldap://example.com",
			shouldFail: true,
			errorMsg:   "connection to example server not available",
		},
		{
			name:       "localhost returns proper error",
			server:     "ldap://localhost",
			shouldFail: true,
			errorMsg:   "connection to example server not available",
		},
		{
			name:       "production server attempts real connection",
			server:     "ldap://prod.server.com",
			shouldFail: true,
			errorMsg:   "", // Will fail with network error, not stub
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				Server: tc.server,
				Port:   389,
				BaseDN: "dc=test,dc=com",
			}

			client, err := New(*config, "user", "pass")
			require.NoError(t, err)

			ctx := context.Background()
			conn, err := client.GetConnectionContext(ctx)

			if tc.shouldFail {
				assert.Error(t, err)
				assert.Nil(t, conn)

				// Never return stub error
				assert.NotContains(t, err.Error(), "not implemented")
				assert.NotContains(t, err.Error(), "connection not implemented")

				// Check for expected error if specified
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			}

			if conn != nil {
				_ = conn.Close()
			}
		})
	}
}

// TestRegressionContextPropagation ensures context is properly passed through all layers
func TestRegressionContextPropagation(t *testing.T) {
	t.Run("context cancellation in GetConnectionContext", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		// Cancel context immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := client.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("context timeout in GetConnectionContext", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		// Create context with immediate timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond)

		conn, err := client.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Equal(t, context.DeadlineExceeded, err)
	})

	t.Run("context propagation to pool", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := client.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		// Context cancellation should be respected even with pool
		assert.True(t, errors.Is(err, context.Canceled) ||
			strings.Contains(err.Error(), "context canceled"))
	})
}

// TestRegressionOptionsAPI ensures functional options work correctly
func TestRegressionOptionsAPI(t *testing.T) {
	t.Run("New accepts variadic options", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		// This should compile - if it doesn't, the API is broken
		client, err := New(*config, "user", "pass",
			WithTimeout(5*time.Second, 10*time.Second),
			WithLogger(slog.Default()))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, 10*time.Second, client.operationTimeout)
	})

	t.Run("options are applied in order", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		// Apply multiple timeout options - last one should win
		client, err := New(*config, "user", "pass",
			WithTimeout(5*time.Second, 10*time.Second),
			WithTimeout(10*time.Second, 20*time.Second))
		require.NoError(t, err)
		assert.Equal(t, 20*time.Second, client.operationTimeout)
	})
}

// TestRegressionCircuitBreakerRaceCondition prevents race conditions in circuit breaker
func TestRegressionCircuitBreakerRaceCondition(t *testing.T) {
	t.Run("atomic state transitions", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			MaxFailures: 2,
			Timeout:     50 * time.Millisecond,
		}
		cb := NewCircuitBreaker("test", config, slog.Default())

		// Trigger failures concurrently
		errChan := make(chan error, 10)
		for i := 0; i < 10; i++ {
			go func() {
				err := cb.Execute(func() error {
					return errors.New("fail")
				})
				errChan <- err
			}()
		}

		// Collect results
		for i := 0; i < 10; i++ {
			<-errChan
		}

		// State should be consistently OPEN
		state := CircuitBreakerState(cb.state.Load())
		assert.Equal(t, StateCircuitOpen, state)

		// No race condition should occur
		// Next calls should fail fast with circuit breaker error
		err := cb.Execute(func() error {
			return nil
		})
		assert.Error(t, err)
		_, ok := err.(*CircuitBreakerError)
		assert.True(t, ok, "Should return CircuitBreakerError")
	})

	t.Run("concurrent state reads are safe", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			MaxFailures: 3,
			Timeout:     100 * time.Millisecond,
		}
		cb := NewCircuitBreaker("concurrent", config, slog.Default())

		// Read state concurrently
		stateChan := make(chan CircuitBreakerState, 100)
		for i := 0; i < 100; i++ {
			go func() {
				state := CircuitBreakerState(cb.state.Load())
				stateChan <- state
			}()
		}

		// All reads should succeed without race
		for i := 0; i < 100; i++ {
			state := <-stateChan
			assert.Contains(t, []CircuitBreakerState{
				StateCircuitClosed,
				StateCircuitOpen,
				StateCircuitHalfOpen,
			}, state)
		}
	})
}

// TestRegressionIteratorContextUsage ensures iterators use context-aware methods
func TestRegressionIteratorContextUsage(t *testing.T) {
	t.Run("SearchIter uses GetConnectionProtectedContext", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 1,
					Timeout:     50 * time.Millisecond,
				},
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		// Cancel context to test propagation
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		// Iterator should respect context cancellation
		var iterErr error
		for _, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
		}

		assert.Error(t, iterErr)
		assert.Contains(t, iterErr.Error(), "context canceled")
	})

	t.Run("SearchPagedIter uses GetConnectionProtectedContext", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		// Create timeout context
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond)

		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		// Iterator should respect timeout
		var iterErr error
		for _, err := range client.SearchPagedIter(ctx, searchRequest, 10) {
			if err != nil {
				iterErr = err
				break
			}
		}

		assert.Error(t, iterErr)
		assert.Contains(t, iterErr.Error(), "deadline exceeded")
	})
}

// TestRegressionValidation ensures all validation is consistent
func TestRegressionValidation(t *testing.T) {
	// Note: nil config validation test removed since Config is now a value type

	t.Run("empty server validation", func(t *testing.T) {
		config := &Config{
			Server: "",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}
		client, err := New(*config, "user", "pass")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "server URL cannot be empty")
	})

	t.Run("empty credentials validation", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		// Empty username
		client, err := New(*config, "", "pass")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "username cannot be empty")

		// Empty password
		client, err = New(*config, "user", "")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "password cannot be empty")
	})
}

// TestRegressionErrorMessages ensures error messages are consistent and helpful
func TestRegressionErrorMessages(t *testing.T) {
	t.Run("circuit breaker error format", func(t *testing.T) {
		cbErr := &CircuitBreakerError{
			State:       "OPEN",
			Failures:    5,
			LastFailure: time.Now(),
			NextRetry:   time.Now().Add(30 * time.Second),
		}

		errStr := cbErr.Error()
		assert.Contains(t, errStr, "circuit breaker OPEN")
		assert.Contains(t, errStr, "failures: 5")
		assert.NotContains(t, errStr, "is OPEN") // Should not have "is OPEN"
	})

	t.Run("connection errors are descriptive", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		ctx := context.Background()
		conn, err := client.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)

		// Error should be descriptive
		assert.Contains(t, err.Error(), "connection to example server not available")
	})
}

// BenchmarkRegressionCircuitBreaker ensures circuit breaker doesn't introduce performance regression
func BenchmarkRegressionCircuitBreaker(b *testing.B) {
	config := &Config{
		Server: "ldap://example.com",
		Port:   389,
		BaseDN: "dc=example,dc=com",
		Resilience: &ResilienceConfig{
			EnableCircuitBreaker: true,
			CircuitBreaker: &CircuitBreakerConfig{
				MaxFailures: 5,
				Timeout:     30 * time.Second,
			},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), // Silent logger for benchmark
	}

	client, err := New(*config, "user", "pass")
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := client.GetConnectionProtectedContext(ctx)
			if err == nil && conn != nil {
				_ = conn.Close()
			}
		}
	})
}
