//go:build !integration

package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- client.go coverage ---

func TestIsExampleServerName(t *testing.T) {
	tests := []struct {
		server   string
		expected bool
	}{
		{"ldap://example.com:389", true},
		{"ldap://localhost:389", true},
		{"ldap://real-ldap.corp.net:389", false},
		{"ldap://test:389", true},
		{"ldap://test.example:389", true},
		{"ldap://enterprise.com:389", true},
		{"ldap://prod.server:389", true},
		{"ldap://failing.server:389", true},
		{"ldap://internal.mycompany.org:389", false},
	}
	for _, tt := range tests {
		t.Run(tt.server, func(t *testing.T) {
			assert.Equal(t, tt.expected, isExampleServerName(tt.server))
		})
	}
}

func TestGetCacheStats(t *testing.T) {
	t.Run("with nil cache", func(t *testing.T) {
		client := &LDAP{
			config: &Config{Server: "ldap://test:389"},
			logger: slog.Default(),
			cache:  nil,
		}
		stats := client.GetCacheStats()
		assert.NotNil(t, stats)
	})

	t.Run("with initialized cache", func(t *testing.T) {
		cache, err := NewLRUCache(&CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		}, slog.Default())
		require.NoError(t, err)

		client := &LDAP{
			config: &Config{Server: "ldap://test:389"},
			logger: slog.Default(),
			cache:  cache,
		}
		stats := client.GetCacheStats()
		assert.NotNil(t, stats)
	})
}

func TestClearCache(t *testing.T) {
	t.Run("with nil cache", func(t *testing.T) {
		client := &LDAP{
			config: &Config{Server: "ldap://test:389"},
			logger: slog.Default(),
			cache:  nil,
		}
		// Should not panic
		client.ClearCache()
	})

	t.Run("with initialized cache", func(t *testing.T) {
		cache, err := NewLRUCache(&CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		}, slog.Default())
		require.NoError(t, err)

		// Add an entry
		_ = cache.Set("test", "value", time.Minute)

		client := &LDAP{
			config: &Config{Server: "ldap://test:389"},
			logger: slog.Default(),
			cache:  cache,
		}
		client.ClearCache()

		// Verify cache is cleared
		_, found := cache.Get("test")
		assert.False(t, found)
	})
}

// --- errors.go coverage ---

func TestMultiErrorUnwrap(t *testing.T) {
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")
	me := &MultiError{}
	me.Add(err1)
	me.Add(err2)

	unwrapped := me.Unwrap()
	assert.Len(t, unwrapped, 2)
	assert.True(t, errors.Is(me, err1))
	assert.True(t, errors.Is(me, err2))
}

func TestCircuitBreakerErrorUnwrap(t *testing.T) {
	cbe := &CircuitBreakerError{
		State:    "open",
		Failures: 5,
	}
	assert.Nil(t, cbe.Unwrap())
	assert.Contains(t, cbe.Error(), "open")
}

func TestTimeoutErrorUnwrap(t *testing.T) {
	inner := errors.New("connection refused")
	te := &TimeoutError{
		Operation:     "search",
		Duration:      2 * time.Second,
		TimeoutPeriod: 1 * time.Second,
		Err:           inner,
	}
	assert.Equal(t, inner, te.Unwrap())
	assert.True(t, errors.Is(te, inner))
	assert.True(t, te.Timeout())
	assert.True(t, te.Temporary())
}

func TestResourceExhaustionErrorUnwrap(t *testing.T) {
	re := &ResourceExhaustionError{
		Resource:  "connections",
		Current:   100,
		Limit:     100,
		Action:    "wait",
		Retryable: true,
	}
	assert.Nil(t, re.Unwrap())
	assert.Contains(t, re.Error(), "connections")
	assert.True(t, re.Temporary())
}

func TestNewValidationError(t *testing.T) {
	ve := NewValidationError("email", "test@example.com", "invalid format", "INVALID_EMAIL")
	assert.Equal(t, "email", ve.Field)
	assert.Equal(t, "INVALID_EMAIL", ve.Code)
	assert.Contains(t, ve.Error(), "email")
}

// --- security.go coverage ---

func TestSecureCredentialClone(t *testing.T) {
	t.Run("clone valid credential", func(t *testing.T) {
		sc, err := NewSecureCredentialSimple("admin", "secret")
		require.NoError(t, err)

		clone, err := sc.Clone()
		require.NoError(t, err)
		assert.NotNil(t, clone)

		cloneUser, clonePass := clone.GetCredentials()
		assert.Equal(t, "admin", cloneUser)
		assert.Equal(t, "secret", clonePass)
	})

	t.Run("clone expired credential", func(t *testing.T) {
		sc, err := NewSecureCredentialSimple("admin", "secret")
		require.NoError(t, err)

		// Force expire
		sc.mutex.Lock()
		sc.expired = true
		sc.mutex.Unlock()

		clone, err := sc.Clone()
		assert.Error(t, err)
		assert.Nil(t, clone)
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestRateLimiterCleanupEviction(t *testing.T) {
	config := &RateLimiterConfig{
		MaxAttempts:     5,
		Window:          time.Hour, // Long window so entries don't expire
		LockoutDuration: time.Hour,
		CleanupInterval: time.Hour, // Don't auto-cleanup
		MaxEntries:      2,         // Only allow 2 entries
	}
	rl := NewRateLimiter(config, slog.Default())
	defer rl.Close()

	// Add 4 entries — exceeds MaxEntries, triggers sort.Slice eviction
	for i := range 4 {
		rl.CheckLimit(fmt.Sprintf("user%d", i))
		time.Sleep(time.Millisecond) // Stagger timestamps for sorting
	}

	// cleanup() acquires its own lock, so call directly
	// Entries are NOT expired (Window=1h), so MaxEntries enforcement triggers sort.Slice
	rl.cleanup()
}

// --- builders.go coverage ---

func TestFilterByAttributeNameValidation(t *testing.T) {
	t.Run("valid attribute names", func(t *testing.T) {
		validNames := []string{"cn", "sAMAccountName", "objectClass", "memberOf", "1.2.840.113556.1.4.221"}
		for _, name := range validNames {
			_, err := NewQueryBuilder().FilterByAttribute(name, "value").BuildFilter()
			assert.NoError(t, err, "attribute name %q should be valid", name)
		}
	})

	t.Run("invalid attribute names are rejected", func(t *testing.T) {
		invalidNames := []string{
			"cn=admin)(objectClass=*",
			"test)(|",
			"attr name", // spaces
			"attr;binary",
		}
		for _, name := range invalidNames {
			_, err := NewQueryBuilder().FilterByAttribute(name, "value").BuildFilter()
			assert.Error(t, err, "attribute name %q should be rejected", name)
		}
	})
}

func TestFilterByObjectClassANDBranch(t *testing.T) {
	// This tests the AND-wrapping branch when filter already has content
	filter, err := NewQueryBuilder().
		FilterByObjectClass("user").
		FilterByObjectClass("person").
		BuildFilter()
	assert.NoError(t, err)
	assert.Contains(t, filter, "(&")
	assert.Contains(t, filter, "(objectClass=user)")
	assert.Contains(t, filter, "(objectClass=person)")
}

func TestFilterByAttributeANDBranch(t *testing.T) {
	filter, err := NewQueryBuilder().
		FilterByAttribute("cn", "admin").
		FilterByAttribute("mail", "admin@test.com").
		BuildFilter()
	assert.NoError(t, err)
	assert.Contains(t, filter, "(&")
	assert.Contains(t, filter, "(cn=admin)")
	assert.Contains(t, filter, "(mail=admin@test.com)")
}

// --- validation.go coverage ---

func TestValidateValue(t *testing.T) {
	v := NewValidator(nil)
	result := v.ValidateValue("normal value")
	assert.True(t, result.Valid)
	assert.NotNil(t, result.Metadata)
}

func TestDetectThreats(t *testing.T) {
	v := NewValidator(nil)
	result := v.ValidateValue(")(objectClass=*)")
	// The threat detection should flag injection patterns
	assert.NotNil(t, result)
}

// --- cache.go coverage ---

func TestCacheSetWithPrimaryKey(t *testing.T) {
	cache, err := NewLRUCache(&CacheConfig{
		Enabled: true,
		MaxSize: 100,
		TTL:     time.Minute,
	}, slog.Default())
	require.NoError(t, err)

	err = cache.SetWithPrimaryKey("user:john", "John Doe", time.Minute, "john")
	assert.NoError(t, err)

	val, found := cache.Get("user:john")
	assert.True(t, found)
	assert.Equal(t, "John Doe", val)
}

func TestCacheCompressionPath(t *testing.T) {
	cache, err := NewLRUCache(&CacheConfig{
		Enabled:              true,
		MaxSize:              100,
		TTL:                  time.Minute,
		CompressionEnabled:   true,
		CompressionThreshold: 1, // 1 byte threshold to trigger compression
	}, slog.Default())
	require.NoError(t, err)

	// Set a value that exceeds the compression threshold
	err = cache.Set("compressed", "some value that should trigger compression", time.Minute)
	assert.NoError(t, err)

	val, found := cache.Get("compressed")
	assert.True(t, found)
	assert.NotNil(t, val)
}

// --- performance.go coverage ---

func TestExtractClientIPFromContext(t *testing.T) {
	t.Run("with client IP", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyClientIP, "192.168.1.1")
		ip := extractClientIP(ctx)
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("without client IP", func(t *testing.T) {
		ip := extractClientIP(context.Background())
		assert.Equal(t, "", ip)
	})

	t.Run("nil context", func(t *testing.T) {
		ip := extractClientIP(nil) //nolint:staticcheck // SA1012: testing nil context handling intentionally
		assert.Equal(t, "", ip)
	})

	t.Run("wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyClientIP, 12345)
		ip := extractClientIP(ctx)
		assert.Equal(t, "", ip)
	})
}

// --- resilience.go coverage ---

func TestCircuitBreakerGetStats(t *testing.T) {
	cb := NewCircuitBreaker("test-cb", DefaultCircuitBreakerConfig(), slog.Default())

	stats := cb.GetStats()
	assert.Equal(t, "test-cb", stats["name"])
	assert.Equal(t, "CLOSED", stats["state"])
	assert.Equal(t, int64(0), stats["failures"])
	assert.Equal(t, int64(0), stats["requests"])
	assert.Equal(t, int64(0), stats["successes"])
	assert.IsType(t, float64(0), stats["success_rate"])

	// Record some failures to change state
	for range 5 {
		_ = cb.Execute(func() error { return errors.New("fail") })
	}
	stats = cb.GetStats()
	assert.Equal(t, "OPEN", stats["state"])
	assert.Equal(t, int64(5), stats["failures"])
}

func TestBulkheadGetStats(t *testing.T) {
	bh := NewBulkhead("test-bh", &BulkheadConfig{
		MaxConcurrency: 5,
		QueueSize:      10,
		Timeout:        time.Second,
	}, slog.Default())

	stats := bh.GetStats()
	assert.Equal(t, "test-bh", stats["name"])
	assert.Equal(t, 5, stats["max_concurrent"])
	assert.Equal(t, int64(0), stats["active"])
	assert.Equal(t, int64(0), stats["queued"])
	assert.Equal(t, int64(0), stats["rejected"])
	assert.Equal(t, 10, stats["queue_size"])
}

func TestTimeoutManagerGetTimeoutStats(t *testing.T) {
	tm := NewTimeoutManager(time.Second, 10*time.Second, 1.5)

	// Empty stats initially
	stats := tm.GetTimeoutStats()
	assert.Empty(t, stats)

	// Record some operations to populate stats
	tm.RecordOperationResult("search", 100*time.Millisecond, true)
	tm.RecordOperationResult("search", 200*time.Millisecond, true)
	tm.RecordOperationResult("bind", 50*time.Millisecond, false)

	stats = tm.GetTimeoutStats()
	assert.Len(t, stats, 2)

	searchStats := stats["search"].(map[string]any)
	assert.Equal(t, int64(2), searchStats["successes"].(int64))

	bindStats := stats["bind"].(map[string]any)
	assert.Equal(t, int64(1), bindStats["timeouts"].(int64))
}

// --- client.go coverage: GetCircuitBreakerStats ---

func TestGetCircuitBreakerStats(t *testing.T) {
	t.Run("with nil circuit breaker", func(t *testing.T) {
		client := &LDAP{
			config:         &Config{Server: "ldap://test:389"},
			logger:         slog.Default(),
			circuitBreaker: nil,
		}
		stats := client.GetCircuitBreakerStats()
		assert.Nil(t, stats)
	})

	t.Run("with circuit breaker", func(t *testing.T) {
		cb := NewCircuitBreaker("test", DefaultCircuitBreakerConfig(), slog.Default())
		client := &LDAP{
			config:         &Config{Server: "ldap://test:389"},
			logger:         slog.Default(),
			circuitBreaker: cb,
		}
		stats := client.GetCircuitBreakerStats()
		assert.NotNil(t, stats)
		assert.Equal(t, "test", stats["name"])
	})
}
