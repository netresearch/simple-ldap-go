//go:build !integration

package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"
)

func TestCacheBasicOperations(t *testing.T) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.MaxSize = 100
	config.TTL = 5 * time.Minute

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	// Test basic set/get operations
	key := "test:key:1"
	value := "test value"

	// Initially should not exist
	if _, found := cache.Get(key); found {
		t.Error("Expected cache miss, got cache hit")
	}

	// Set value
	if err := cache.Set(key, value, time.Hour); err != nil {
		t.Errorf("Failed to set cache value: %v", err)
	}

	// Should now exist
	if cachedValue, found := cache.Get(key); !found {
		t.Error("Expected cache hit, got cache miss")
	} else if cachedValue.(string) != value {
		t.Errorf("Expected %s, got %s", value, cachedValue.(string))
	}

	// Test delete
	if !cache.Delete(key) {
		t.Error("Expected successful delete, got false")
	}

	// Should not exist after delete
	if _, found := cache.Get(key); found {
		t.Error("Expected cache miss after delete, got cache hit")
	}
}

func TestCacheExpiration(t *testing.T) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.TTL = 100 * time.Millisecond

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	key := "test:expiration:1"
	value := "expiring value"

	// Set value with short TTL
	if err := cache.Set(key, value, 50*time.Millisecond); err != nil {
		t.Errorf("Failed to set cache value: %v", err)
	}

	// Should exist immediately
	if _, found := cache.Get(key); !found {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should not exist after expiration
	if _, found := cache.Get(key); found {
		t.Error("Expected cache miss after expiration, got cache hit")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.MaxSize = 3 // Very small cache for testing eviction
	config.TTL = time.Hour

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	// Fill cache to capacity
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("test:lru:%d", i)
		value := fmt.Sprintf("value:%d", i)
		if err := cache.Set(key, value, time.Hour); err != nil {
			t.Errorf("Failed to set cache value %d: %v", i, err)
		}
	}

	// All should exist
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("test:lru:%d", i)
		if _, found := cache.Get(key); !found {
			t.Errorf("Expected cache hit for key %d", i)
		}
	}

	// Add one more item, should evict oldest (key 0)
	if err := cache.Set("test:lru:3", "value:3", time.Hour); err != nil {
		t.Errorf("Failed to set evicting cache value: %v", err)
	}

	// Key 0 should be evicted
	if _, found := cache.Get("test:lru:0"); found {
		t.Error("Expected evicted key to be missing")
	}

	// Keys 1, 2, 3 should still exist
	for i := 1; i <= 3; i++ {
		key := fmt.Sprintf("test:lru:%d", i)
		if _, found := cache.Get(key); !found {
			t.Errorf("Expected cache hit for key %d after eviction", i)
		}
	}
}

func TestCacheStats(t *testing.T) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.MaxSize = 100
	config.TTL = time.Hour

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	// Initial stats should be zero
	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 0 || stats.Sets != 0 {
		t.Error("Expected zero initial stats")
	}

	// Perform some operations
	if err := cache.Set("key1", "value1", time.Hour); err != nil {
		t.Errorf("Failed to set key1: %v", err)
	}
	cache.Get("key1") // 1 hit
	cache.Get("key2") // 1 miss
	if err := cache.Set("key2", "value2", time.Hour); err != nil {
		t.Errorf("Failed to set key2: %v", err)
	}
	cache.Get("key2") // 1 hit

	// Check stats
	stats = cache.Stats()
	if stats.Sets != 2 {
		t.Errorf("Expected 2 sets, got %d", stats.Sets)
	}
	if stats.Hits != 2 {
		t.Errorf("Expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}
	if stats.HitRatio < 66.0 || stats.HitRatio > 67.0 { // Should be ~66.67%
		t.Errorf("Expected hit ratio around 66.67%%, got %.2f%%", stats.HitRatio)
	}
	if stats.TotalEntries != 2 {
		t.Errorf("Expected 2 total entries, got %d", stats.TotalEntries)
	}
}

func TestNegativeCache(t *testing.T) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.NegativeCacheTTL = 100 * time.Millisecond

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	key := "test:negative:1"

	// Set negative cache entry
	if err := cache.SetNegative(key, 100*time.Millisecond); err != nil {
		t.Errorf("Failed to set negative cache: %v", err)
	}

	// Should get negative hit
	if value, found := cache.Get(key); !found {
		t.Error("Expected negative cache hit")
	} else if value != nil {
		t.Errorf("Expected nil for negative cache, got %v", value)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should not exist after expiration
	if _, found := cache.Get(key); found {
		t.Error("Expected cache miss after negative cache expiration")
	}
}

func TestPerformanceMonitor(t *testing.T) {
	config := DefaultPerformanceConfig()
	config.SlowQueryThreshold = 10 * time.Millisecond

	monitor := NewPerformanceMonitor(config, slog.Default())
	defer func() { _ = monitor.Close() }()

	ctx := context.Background()

	// Record some operations
	monitor.RecordOperation(ctx, "TestOperation", 5*time.Millisecond, false, nil, 1)                      // Fast
	monitor.RecordOperation(ctx, "TestOperation", 15*time.Millisecond, true, nil, 1)                      // Slow, cache hit
	monitor.RecordOperation(ctx, "TestOperation", 8*time.Millisecond, false, fmt.Errorf("test error"), 0) // Fast, error

	// Get stats
	stats := monitor.GetStats()

	if stats.OperationsTotal != 3 {
		t.Errorf("Expected 3 operations, got %d", stats.OperationsTotal)
	}
	if stats.SlowQueries != 1 {
		t.Errorf("Expected 1 slow query, got %d", stats.SlowQueries)
	}
	if stats.ErrorCount != 1 {
		t.Errorf("Expected 1 error, got %d", stats.ErrorCount)
	}
	if len(stats.OperationsByType) == 0 {
		t.Error("Expected operations by type data")
	}
	if stats.OperationsByType["TestOperation"] != 3 {
		t.Errorf("Expected 3 TestOperations, got %d", stats.OperationsByType["TestOperation"])
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		params    []string
		expected  string
	}{
		{
			name:      "Simple DN lookup",
			operation: "user:dn",
			params:    []string{"CN=John Doe,CN=Users,DC=example,DC=com"},
			expected:  "user:dn:sha256:a1b2c3d4e5f6",
		},
		{
			name:      "Email lookup",
			operation: "user:email",
			params:    []string{"john.doe@example.com"},
			expected:  "user:email:sha256:x1y2z3w4v5u6",
		},
		{
			name:      "Multi-param search",
			operation: "search:complex",
			params:    []string{"(&(objectClass=user)(mail=*))", "DC=example,DC=com", "subtree"},
			expected:  "search:complex:sha256:m1n2o3p4q5r6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GenerateCacheKey(tt.operation, tt.params...)
			if key == "" {
				t.Error("Generated cache key should not be empty")
			}
			// Check key format
			if len(key) < 20 { // Should be at least operation + hash prefix
				t.Errorf("Generated key seems too short: %s", key)
			}
		})
	}
}

func TestContextCacheOperations(t *testing.T) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.MaxSize = 100

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	ctx := context.Background()
	key := "test:context:key"
	value := "test context value"

	// Test context-aware set
	if err := cache.SetContext(ctx, key, value, time.Hour); err != nil {
		t.Errorf("Failed to set value with context: %v", err)
	}

	// Test context-aware get
	if cached, found := cache.GetContext(ctx, key); !found {
		t.Error("Expected cache hit with context")
	} else if cached.(string) != value {
		t.Errorf("Expected %s, got %s", value, cached.(string))
	}

	// Test with cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Operations with cancelled context should still work but may be faster to fail
	_, _ = cache.GetContext(cancelCtx, key)
}

// Benchmark tests for performance validation

func BenchmarkCacheSet(b *testing.B) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.MaxSize = 10000

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:set:%d", i%1000) // Reuse keys to test updates
		value := fmt.Sprintf("value:%d", i)
		if err := cache.Set(key, value, time.Hour); err != nil {
			b.Errorf("Failed to set cache value: %v", err)
		}
	}
}

func BenchmarkCacheGet(b *testing.B) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.MaxSize = 10000

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("bench:get:%d", i)
		value := fmt.Sprintf("value:%d", i)
		if err := cache.Set(key, value, time.Hour); err != nil {
			b.Errorf("Failed to pre-populate cache: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:get:%d", i%1000)
		cache.Get(key)
	}
}

func BenchmarkCacheMixed(b *testing.B) {
	config := DefaultCacheConfig()
	config.Enabled = true
	config.MaxSize = 10000

	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:mixed:%d", i%1000)

		// 70% reads, 30% writes (typical read-heavy workload)
		if i%10 < 7 {
			cache.Get(key)
		} else {
			value := fmt.Sprintf("value:%d", i)
			if err := cache.Set(key, value, time.Hour); err != nil {
				b.Errorf("Failed to set cache value: %v", err)
			}
		}
	}
}

func BenchmarkPerformanceMonitor(b *testing.B) {
	config := DefaultPerformanceConfig()
	monitor := NewPerformanceMonitor(config, slog.Default())
	defer func() { _ = monitor.Close() }()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		operation := fmt.Sprintf("BenchOperation%d", i%5) // 5 different operation types
		duration := time.Duration(i%100) * time.Microsecond
		cacheHit := i%3 == 0 // ~33% cache hit rate
		var err error
		if i%20 == 0 { // 5% error rate
			err = fmt.Errorf("benchmark error")
		}
		resultCount := 1
		if i%10 == 0 { // Some operations return multiple results
			resultCount = i%5 + 1
		}

		monitor.RecordOperation(ctx, operation, duration, cacheHit, err, resultCount)
	}
}

func BenchmarkCacheKeyGeneration(b *testing.B) {
	components := []string{
		"CN=John Doe,OU=Users,DC=example,DC=com",
		"jdoe@example.com",
		"(&(objectClass=user)(mail=*))",
		"DC=example,DC=com",
		"subtree",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		operation := fmt.Sprintf("operation%d", i%10)
		params := components[:i%len(components)+1] // Use variable number of params
		_ = GenerateCacheKey(operation, params...)
	}
}

// Integration test that combines caching and performance monitoring
func TestCachePerformanceIntegration(t *testing.T) {
	// Setup cache
	cacheConfig := DefaultCacheConfig()
	cacheConfig.Enabled = true
	cacheConfig.MaxSize = 1000

	cache, err := NewLRUCache(cacheConfig, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	// Setup performance monitor
	perfConfig := DefaultPerformanceConfig()
	perfConfig.SlowQueryThreshold = 1 * time.Millisecond

	perfMonitor := NewPerformanceMonitor(perfConfig, slog.Default())
	defer func() { _ = perfMonitor.Close() }()

	ctx := context.Background()
	userDN := "CN=Test User,CN=Users,DC=example,DC=com"
	cacheKey := GenerateCacheKey("user:dn", userDN)

	// First lookup - cache miss
	start := time.Now()
	_, found := cache.GetContext(ctx, cacheKey)
	duration := time.Since(start)

	if found {
		t.Error("Expected cache miss on first lookup")
	}

	// Simulate LDAP operation and caching result
	mockUser := &User{
		Object:         Object{dn: userDN},
		Enabled:        true,
		SAMAccountName: "testuser",
		Description:    "Test User",
	}

	if err := cache.SetContext(ctx, cacheKey, mockUser, 5*time.Minute); err != nil {
		t.Errorf("Failed to cache user: %v", err)
	}
	perfMonitor.RecordOperation(ctx, "FindUserByDN", duration, false, nil, 1)

	// Second lookup - cache hit
	start = time.Now()
	cached, found := cache.GetContext(ctx, cacheKey)
	duration = time.Since(start)

	if !found {
		t.Error("Expected cache hit on second lookup")
	}

	cachedUser, ok := cached.(*User)
	if !ok {
		t.Error("Expected cached user object")
	}

	if cachedUser.SAMAccountName != "testuser" {
		t.Errorf("Expected cached user SAMAccountName to be 'testuser', got %s", cachedUser.SAMAccountName)
	}

	perfMonitor.RecordOperation(ctx, "FindUserByDN", duration, true, nil, 1)

	// Check performance stats
	stats := perfMonitor.GetStats()
	if stats.OperationsTotal != 2 {
		t.Errorf("Expected 2 operations, got %d", stats.OperationsTotal)
	}
	if stats.CacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.CacheHits)
	}

	// Check cache stats
	cacheStats := cache.Stats()
	if cacheStats.Hits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", cacheStats.Hits)
	}
	if cacheStats.Sets != 1 {
		t.Errorf("Expected 1 cache set, got %d", cacheStats.Sets)
	}
}
