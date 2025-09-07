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
	defer cache.Close()
	
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
	defer cache.Close()
	
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
	defer cache.Close()
	
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
	defer cache.Close()
	
	// Initial stats should be zero
	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 0 || stats.Sets != 0 {
		t.Error("Expected zero initial stats")
	}
	
	// Perform some operations
	cache.Set("key1", "value1", time.Hour) // 1 set
	cache.Get("key1")                      // 1 hit
	cache.Get("key2")                      // 1 miss
	cache.Set("key2", "value2", time.Hour) // 1 set
	cache.Get("key2")                      // 1 hit
	
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
	defer cache.Close()
	
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
	defer monitor.Close()
	
	ctx := context.Background()
	
	// Record some operations
	monitor.RecordOperation(ctx, "TestOperation", 5*time.Millisecond, false, nil, 1)  // Fast
	monitor.RecordOperation(ctx, "TestOperation", 15*time.Millisecond, true, nil, 1)  // Slow, cache hit
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
		operation  string
		components []string
		expected   bool // Whether we expect a valid key
	}{
		{"user:dn", []string{"CN=test,DC=example,DC=com"}, true},
		{"user:sam", []string{"testuser"}, true},
		{"user:mail", []string{"test@example.com"}, true},
		{"group:dn", []string{"CN=testgroup,DC=example,DC=com"}, true},
		{"bulk", []string{"operation", "batch1"}, true},
	}
	
	for _, test := range tests {
		key := GenerateCacheKey(test.operation, test.components...)
		
		if test.expected && key == "" {
			t.Errorf("Expected non-empty cache key for %s with %v", test.operation, test.components)
		}
		
		if test.expected && len(key) < 10 {
			t.Errorf("Expected substantial cache key, got %s", key)
		}
		
		// Keys should be consistent
		key2 := GenerateCacheKey(test.operation, test.components...)
		if key != key2 {
			t.Errorf("Cache key generation not consistent: %s != %s", key, key2)
		}
	}
}

func TestSearchOptionsDefaults(t *testing.T) {
	options := DefaultSearchOptions()
	
	if !options.RefreshStale {
		t.Error("Expected RefreshStale to be true by default")
	}
	if !options.UseNegativeCache {
		t.Error("Expected UseNegativeCache to be true by default")
	}
	if options.BackgroundLoad {
		t.Error("Expected BackgroundLoad to be false by default")
	}
	if options.MaxResults != 0 {
		t.Errorf("Expected MaxResults to be 0 (no limit) by default, got %d", options.MaxResults)
	}
	if options.Timeout != 30*time.Second {
		t.Errorf("Expected Timeout to be 30s by default, got %v", options.Timeout)
	}
}

func TestBulkSearchOptionsDefaults(t *testing.T) {
	options := DefaultBulkSearchOptions()
	
	if options.BatchSize != 10 {
		t.Errorf("Expected BatchSize to be 10 by default, got %d", options.BatchSize)
	}
	if options.Timeout != 5*time.Minute {
		t.Errorf("Expected Timeout to be 5m by default, got %v", options.Timeout)
	}
	if !options.ContinueOnError {
		t.Error("Expected ContinueOnError to be true by default")
	}
	if !options.UseCache {
		t.Error("Expected UseCache to be true by default")
	}
	if options.CachePrefix != "bulk" {
		t.Errorf("Expected CachePrefix to be 'bulk' by default, got %s", options.CachePrefix)
	}
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
	defer cache.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:set:%d", i%1000) // Reuse keys to test updates
		value := fmt.Sprintf("value:%d", i)
		cache.Set(key, value, time.Hour)
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
	defer cache.Close()
	
	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("bench:get:%d", i)
		value := fmt.Sprintf("value:%d", i)
		cache.Set(key, value, time.Hour)
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
	defer cache.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:mixed:%d", i%1000)
		
		// 70% reads, 30% writes (typical read-heavy workload)
		if i%10 < 7 {
			cache.Get(key)
		} else {
			value := fmt.Sprintf("value:%d", i)
			cache.Set(key, value, time.Hour)
		}
	}
}

func BenchmarkPerformanceMonitor(b *testing.B) {
	config := DefaultPerformanceConfig()
	monitor := NewPerformanceMonitor(config, slog.Default())
	defer monitor.Close()
	
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
		"additional_component",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		operation := fmt.Sprintf("operation%d", i%5)
		GenerateCacheKey(operation, components...)
	}
}

// Integration test with mock LDAP operations
func TestCacheIntegrationWithMockOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	// This test would require a more complex setup with actual LDAP client
	// For now, we'll test the cache behavior in isolation
	
	config := DefaultCacheConfig()
	config.Enabled = true
	config.TTL = 5 * time.Minute
	config.MaxSize = 1000
	
	cache, err := NewLRUCache(config, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()
	
	perfConfig := DefaultPerformanceConfig()
	perfConfig.SlowQueryThreshold = 100 * time.Millisecond
	
	perfMonitor := NewPerformanceMonitor(perfConfig, slog.Default())
	defer perfMonitor.Close()
	
	ctx := context.Background()
	
	// Simulate user lookups with caching
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"
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
		Object: Object{dn: userDN},
		Enabled: true,
		SAMAccountName: "testuser",
		Description: "Test User",
	}
	
	cache.SetContext(ctx, cacheKey, mockUser, 5*time.Minute)
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
	
	// Validate performance stats
	stats := perfMonitor.GetStats()
	if stats.OperationsTotal != 2 {
		t.Errorf("Expected 2 operations, got %d", stats.OperationsTotal)
	}
	
	// Cache hit should be much faster
	if duration > 1*time.Millisecond {
		t.Errorf("Cache hit took too long: %v", duration)
	}
}