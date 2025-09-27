//go:build !integration

package ldap

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCircuitBreaker(t *testing.T) {
	t.Run("state transitions", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			MaxFailures:         3,
			Timeout:             100 * time.Millisecond,
			HalfOpenMaxRequests: 2,
		}
		cb := NewCircuitBreaker("test", config, slog.Default())

		// Initial state should be CLOSED
		assert.Equal(t, StateCircuitClosed, CircuitBreakerState(cb.state.Load()))

		// Simulate failures to trigger OPEN state
		for i := 0; i < 3; i++ {
			err := cb.Execute(func() error {
				return errors.New("connection failed")
			})
			assert.Error(t, err)
		}

		// Circuit should now be OPEN
		assert.Equal(t, StateCircuitOpen, CircuitBreakerState(cb.state.Load()))

		// Further attempts should fail immediately with CircuitBreakerError
		err := cb.Execute(func() error {
			return nil
		})
		assert.Error(t, err)
		_, ok := err.(*CircuitBreakerError)
		assert.True(t, ok, "Expected CircuitBreakerError")

		// Wait for timeout to transition to HALF_OPEN
		time.Sleep(150 * time.Millisecond)

		// Next attempt should be allowed (HALF_OPEN state)
		successCount := 0
		for i := 0; i < 2; i++ {
			err = cb.Execute(func() error {
				successCount++
				return nil
			})
			assert.NoError(t, err)
		}

		// After successful requests in HALF_OPEN, should transition back to CLOSED
		assert.Equal(t, StateCircuitClosed, CircuitBreakerState(cb.state.Load()))
	})

	t.Run("concurrent access", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			MaxFailures:         5,
			Timeout:             100 * time.Millisecond,
			HalfOpenMaxRequests: 3,
		}
		cb := NewCircuitBreaker("concurrent", config, slog.Default())

		var wg sync.WaitGroup
		var failures int64
		var successes int64

		// First, trigger failures to open the circuit
		for i := 0; i < 10; i++ {
			_ = cb.Execute(func() error {
				return errors.New("failed")
			})
		}

		// Now run concurrent requests - some should be blocked by open circuit
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				err := cb.Execute(func() error {
					return nil // All operations would succeed if circuit was closed
				})

				if err != nil {
					atomic.AddInt64(&failures, 1)
				} else {
					atomic.AddInt64(&successes, 1)
				}
			}(i)
		}

		wg.Wait()

		// Should have failures due to open circuit breaker
		assert.Greater(t, atomic.LoadInt64(&failures), int64(0))
		// Should have fewer successes than total requests due to circuit breaker
		assert.Less(t, atomic.LoadInt64(&successes), int64(50))
	})

	t.Run("half open single failure reopens circuit", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			MaxFailures:         2,
			Timeout:             50 * time.Millisecond,
			HalfOpenMaxRequests: 3,
		}
		cb := NewCircuitBreaker("half-open-test", config, slog.Default())

		// Trigger OPEN state
		for i := 0; i < 2; i++ {
			_ = cb.Execute(func() error {
				return errors.New("failed")
			})
		}
		assert.Equal(t, StateCircuitOpen, CircuitBreakerState(cb.state.Load()))

		// Wait for transition to HALF_OPEN
		time.Sleep(60 * time.Millisecond)

		// First request in HALF_OPEN fails
		err := cb.Execute(func() error {
			return errors.New("still failing")
		})
		assert.Error(t, err)

		// Should immediately go back to OPEN
		assert.Equal(t, StateCircuitOpen, CircuitBreakerState(cb.state.Load()))
	})

	t.Run("statistics tracking", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		cb := NewCircuitBreaker("stats", config, slog.Default())

		// Execute some successful operations
		for i := 0; i < 3; i++ {
			_ = cb.Execute(func() error {
				return nil
			})
		}

		// Execute some failures
		for i := 0; i < 2; i++ {
			_ = cb.Execute(func() error {
				return errors.New("failed")
			})
		}

		stats := cb.GetStats()
		assert.Equal(t, "stats", stats["name"])
		assert.Equal(t, "CLOSED", stats["state"])
		assert.Equal(t, int64(5), stats["requests"])
		assert.Equal(t, int64(3), stats["successes"])
		assert.Equal(t, int64(2), stats["failures"])

		successRate := stats["success_rate"].(float64)
		assert.InDelta(t, 0.6, successRate, 0.01)
	})

	t.Run("reset functionality", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			MaxFailures: 1,
			Timeout:     1 * time.Hour, // Long timeout
		}
		cb := NewCircuitBreaker("reset", config, slog.Default())

		// Trigger OPEN state
		_ = cb.Execute(func() error {
			return errors.New("failed")
		})
		assert.Equal(t, StateCircuitOpen, CircuitBreakerState(cb.state.Load()))

		// Reset the circuit breaker
		cb.Reset()
		assert.Equal(t, StateCircuitClosed, CircuitBreakerState(cb.state.Load()))
		assert.Equal(t, int64(0), cb.failures.Load())

		// Should work normally after reset
		err := cb.Execute(func() error {
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestCircuitBreakerError(t *testing.T) {
	cbErr := &CircuitBreakerError{
		State:       "OPEN",
		Failures:    5,
		LastFailure: time.Now().Add(-1 * time.Minute),
		NextRetry:   time.Now().Add(30 * time.Second),
	}

	errStr := cbErr.Error()
	assert.Contains(t, errStr, "circuit breaker OPEN")
	assert.Contains(t, errStr, "failures: 5")
}

func TestLDAPCircuitBreakerIntegration(t *testing.T) {
	t.Run("circuit breaker disabled by default", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		assert.Nil(t, client.circuitBreaker)

		// GetConnectionProtected should work without circuit breaker
		ctx := context.Background()
		conn, err := client.GetConnectionProtectedContext(ctx)
		// Will fail but not with circuit breaker error
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.NotContains(t, err.Error(), "circuit breaker")
	})

	t.Run("circuit breaker enabled via config", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 2,
					Timeout:     50 * time.Millisecond,
				},
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client.circuitBreaker)

		// Stats should be available
		stats := client.GetCircuitBreakerStats()
		assert.NotNil(t, stats)
		assert.Equal(t, "ldap_connection", stats["name"])
		assert.Equal(t, "CLOSED", stats["state"])
	})

	t.Run("circuit breaker protects connections", func(t *testing.T) {
		config := &Config{
			Server: "ldap://failing.server",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 2,
					Timeout:     100 * time.Millisecond,
				},
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)

		ctx := context.Background()

		// First failures should go through
		for i := 0; i < 2; i++ {
			conn, err := client.GetConnectionProtectedContext(ctx)
			assert.Error(t, err)
			assert.Nil(t, conn)
			// These should be actual connection errors
			assert.NotContains(t, err.Error(), "circuit breaker")
		}

		// Now circuit should be OPEN, next attempt should fail fast
		start := time.Now()
		conn, err := client.GetConnectionProtectedContext(ctx)
		elapsed := time.Since(start)

		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "temporarily unavailable")
		assert.Contains(t, err.Error(), "circuit breaker")
		// Should fail fast (< 10ms)
		assert.Less(t, elapsed, 10*time.Millisecond)

		// Check stats
		stats := client.GetCircuitBreakerStats()
		assert.Equal(t, "OPEN", stats["state"])
		assert.Equal(t, int64(2), stats["failures"])
	})
}

func TestWithCircuitBreakerOption(t *testing.T) {
	t.Run("with custom config", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		cbConfig := &CircuitBreakerConfig{
			MaxFailures:         10,
			Timeout:             1 * time.Minute,
			HalfOpenMaxRequests: 5,
		}

		// Apply option
		client := &LDAP{config: config}
		WithCircuitBreaker(cbConfig)(client)

		assert.NotNil(t, client.config.Resilience)
		assert.True(t, client.config.Resilience.EnableCircuitBreaker)
		assert.Equal(t, int64(10), client.config.Resilience.CircuitBreaker.MaxFailures)
		assert.Equal(t, 1*time.Minute, client.config.Resilience.CircuitBreaker.Timeout)
	})

	t.Run("with nil config uses defaults", func(t *testing.T) {
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		// Apply option with nil config
		client := &LDAP{config: config}
		WithCircuitBreaker(nil)(client)

		assert.NotNil(t, client.config.Resilience)
		assert.True(t, client.config.Resilience.EnableCircuitBreaker)
		assert.NotNil(t, client.config.Resilience.CircuitBreaker)
		// Should use defaults
		assert.Equal(t, int64(5), client.config.Resilience.CircuitBreaker.MaxFailures)
		assert.Equal(t, 30*time.Second, client.config.Resilience.CircuitBreaker.Timeout)
	})
}

// Benchmark tests
func BenchmarkCircuitBreakerClosed(b *testing.B) {
	cb := NewCircuitBreaker("bench", DefaultCircuitBreakerConfig(), slog.Default())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.Execute(func() error {
			return nil
		})
	}
}

func BenchmarkCircuitBreakerOpen(b *testing.B) {
	config := &CircuitBreakerConfig{
		MaxFailures: 1,
		Timeout:     1 * time.Hour,
	}
	cb := NewCircuitBreaker("bench", config, slog.Default())

	// Open the circuit
	_ = cb.Execute(func() error {
		return errors.New("fail")
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.Execute(func() error {
			return nil
		})
	}
}
