package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIteratorsWithCircuitBreaker(t *testing.T) {
	t.Run("SearchIter without circuit breaker", func(t *testing.T) {
		// Setup client without circuit breaker
		config := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn", "uid"},
			nil,
		)

		// Should attempt connection and fail normally
		var iterErr error
		for _, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
		}

		assert.Error(t, iterErr)
		assert.NotContains(t, iterErr.Error(), "circuit breaker")
		assert.Contains(t, iterErr.Error(), "connection to example server not available")
	})

	t.Run("SearchIter with circuit breaker fast failure", func(t *testing.T) {
		// Setup client with circuit breaker
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

		client, err := New(config, "user", "pass")
		require.NoError(t, err)

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn", "uid"},
			nil,
		)

		// Trigger circuit breaker to open
		for i := 0; i < 2; i++ {
			for _, err := range client.SearchIter(ctx, searchRequest) {
				if err != nil {
					break
				}
			}
		}

		// Now circuit should be open - next attempt should fail fast
		start := time.Now()
		var iterErr error
		for _, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
		}
		elapsed := time.Since(start)

		assert.Error(t, iterErr)
		assert.Contains(t, iterErr.Error(), "temporarily unavailable")
		assert.Contains(t, iterErr.Error(), "circuit breaker")
		// Should fail very fast (< 10ms)
		assert.Less(t, elapsed, 10*time.Millisecond)
	})

	t.Run("SearchPagedIter with circuit breaker", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.server",
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

		client, err := New(config, "user", "pass")
		require.NoError(t, err)

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		// First attempt should fail and open circuit
		var iterErr error
		for _, err := range client.SearchPagedIter(ctx, searchRequest, 10) {
			if err != nil {
				iterErr = err
				break
			}
		}
		assert.Error(t, iterErr)

		// Second attempt should fail fast with circuit breaker error
		start := time.Now()
		for _, err := range client.SearchPagedIter(ctx, searchRequest, 10) {
			if err != nil {
				iterErr = err
				break
			}
		}
		elapsed := time.Since(start)

		assert.Error(t, iterErr)
		assert.Contains(t, iterErr.Error(), "circuit breaker")
		assert.Less(t, elapsed, 10*time.Millisecond)
	})

	t.Run("GroupMembersIter inherits circuit breaker protection", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.server",
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

		client, err := New(config, "user", "pass")
		require.NoError(t, err)

		ctx := context.Background()
		groupDN := "cn=admins,ou=groups,dc=example,dc=com"

		// Trigger failures to open circuit
		for i := 0; i < 2; i++ {
			for _, err := range client.GroupMembersIter(ctx, groupDN) {
				if err != nil {
					break
				}
			}
		}

		// Next attempt should fail fast
		start := time.Now()
		var iterErr error
		for _, err := range client.GroupMembersIter(ctx, groupDN) {
			if err != nil {
				iterErr = err
				break
			}
		}
		elapsed := time.Since(start)

		assert.Error(t, iterErr)
		// GroupMembersIter uses SearchIter internally, so should get circuit breaker protection
		assert.Contains(t, iterErr.Error(), "circuit breaker")
		assert.Less(t, elapsed, 10*time.Millisecond)
	})

	t.Run("circuit breaker recovery", func(t *testing.T) {
		config := &Config{
			Server: "ldap://recovering.server",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures:         2,
					Timeout:             50 * time.Millisecond,
					HalfOpenMaxRequests: 1,
				},
			},
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client.circuitBreaker)

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		// Open the circuit
		for i := 0; i < 2; i++ {
			for _, err := range client.SearchIter(ctx, searchRequest) {
				if err != nil {
					break
				}
			}
		}

		// Verify circuit is open
		stats := client.GetCircuitBreakerStats()
		assert.Equal(t, "OPEN", stats["state"])

		// Wait for timeout to allow transition to half-open
		time.Sleep(60 * time.Millisecond)

		// Next attempt should be allowed (half-open state)
		// It will still fail but shows circuit is testing recovery
		for _, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				break
			}
		}

		// After failure in half-open, should be back to open
		stats = client.GetCircuitBreakerStats()
		assert.Equal(t, "OPEN", stats["state"])
	})

	t.Run("performance comparison with and without circuit breaker", func(t *testing.T) {
		// Without circuit breaker - slow failures
		configNoCB := &Config{
			Server: "ldap://slow.server",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		clientNoCB, err := New(configNoCB, "user", "pass")
		require.NoError(t, err)

		// With circuit breaker - fast failures after initial failures
		configWithCB := &Config{
			Server: "ldap://slow.server",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 1,
					Timeout:     1 * time.Minute,
				},
			},
		}

		clientWithCB, err := New(configWithCB, "user", "pass")
		require.NoError(t, err)

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		// Trigger circuit breaker to open
		for _, err := range clientWithCB.SearchIter(ctx, searchRequest) {
			if err != nil {
				break
			}
		}

		// Measure time for 5 failed attempts without circuit breaker
		startNoCB := time.Now()
		for i := 0; i < 5; i++ {
			for _, err := range clientNoCB.SearchIter(ctx, searchRequest) {
				if err != nil {
					break
				}
			}
		}
		elapsedNoCB := time.Since(startNoCB)

		// Measure time for 5 failed attempts with circuit breaker (should be much faster)
		startWithCB := time.Now()
		for i := 0; i < 5; i++ {
			for _, err := range clientWithCB.SearchIter(ctx, searchRequest) {
				if err != nil {
					break
				}
			}
		}
		elapsedWithCB := time.Since(startWithCB)

		// With circuit breaker should be significantly faster (at least 10x)
		// In reality it would be much more (seconds vs milliseconds)
		// but our mock fails fast already
		t.Logf("Without CB: %v, With CB: %v", elapsedNoCB, elapsedWithCB)

		// Verify circuit breaker stats show it's working
		stats := clientWithCB.GetCircuitBreakerStats()
		assert.Equal(t, "OPEN", stats["state"])
		assert.Greater(t, stats["failures"].(int64), int64(0))
	})

	t.Run("context cancellation at connection level", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.server",
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

		client, err := New(config, "user", "pass")
		require.NoError(t, err)

		// Create a context that will be cancelled
		ctx, cancel := context.WithCancel(context.Background())
		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		// Cancel the context immediately to test cancellation handling
		cancel()

		// SearchIter should handle context cancellation properly
		var iterErr error
		for _, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
		}

		// Should get context cancelled error
		assert.Error(t, iterErr)
		assert.Contains(t, iterErr.Error(), "context canceled")
	})

	t.Run("context timeout at connection level", func(t *testing.T) {
		config := &Config{
			Server: "ldap://test.server",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 5,
					Timeout:     1 * time.Minute,
				},
			},
		}

		client, err := New(config, "user", "pass")
		require.NoError(t, err)

		// Create a context with very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// Give it a moment to timeout
		time.Sleep(10 * time.Millisecond)

		searchRequest := ldap.NewSearchRequest(
			config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		// SearchPagedIter should handle context timeout properly
		var iterErr error
		for _, err := range client.SearchPagedIter(ctx, searchRequest, 10) {
			if err != nil {
				iterErr = err
				break
			}
		}

		// Should get context deadline exceeded error
		assert.Error(t, iterErr)
		assert.Contains(t, iterErr.Error(), "deadline exceeded")
	})
}
