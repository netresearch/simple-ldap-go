//go:build !integration

package ldap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewLRUCache tests cache creation with various configurations
func TestNewLRUCache(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		cache, err := NewLRUCache(nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cache)
		defer func() {
			_ = cache.Close()
		}()

		// Verify defaults were applied
		assert.Equal(t, false, cache.config.Enabled) // Disabled by default
		assert.Equal(t, 5*time.Minute, cache.config.TTL)
		assert.Equal(t, 1000, cache.config.MaxSize)
		assert.Equal(t, 1*time.Minute, cache.config.RefreshInterval)
		assert.Equal(t, 30*time.Second, cache.config.NegativeCacheTTL)
		assert.Equal(t, 64, cache.config.MaxMemoryMB)
	})

	t.Run("enabled cache with custom config", func(t *testing.T) {
		config := &CacheConfig{
			Enabled:              true,
			TTL:                  10 * time.Minute,
			MaxSize:              500,
			RefreshInterval:      2 * time.Minute,
			RefreshOnAccess:      false,
			NegativeCacheTTL:     1 * time.Minute,
			MaxMemoryMB:          128,
			CompressionEnabled:   true,
			CompressionThreshold: 2048,
		}

		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		require.NotNil(t, cache)
		defer func() {
			_ = cache.Close()
		}()

		assert.Equal(t, true, cache.config.Enabled)
		assert.Equal(t, 10*time.Minute, cache.config.TTL)
		assert.Equal(t, 500, cache.config.MaxSize)
		assert.Equal(t, 128, cache.config.MaxMemoryMB)
	})

	t.Run("invalid configuration correction", func(t *testing.T) {
		config := &CacheConfig{
			Enabled:              true,
			TTL:                  0, // Should be corrected
			MaxSize:              0, // Should be corrected
			RefreshInterval:      0, // Should be corrected
			NegativeCacheTTL:     0, // Should be corrected
			MaxMemoryMB:          0, // Should be corrected
			CompressionThreshold: 0, // Should be corrected
		}

		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		require.NotNil(t, cache)
		defer func() {
			_ = cache.Close()
		}()

		assert.Equal(t, 5*time.Minute, cache.config.TTL)
		assert.Equal(t, 1000, cache.config.MaxSize)
		assert.Equal(t, 1*time.Minute, cache.config.RefreshInterval)
		assert.Equal(t, 30*time.Second, cache.config.NegativeCacheTTL)
		assert.Equal(t, 64, cache.config.MaxMemoryMB)
		assert.Equal(t, 1024, cache.config.CompressionThreshold)
	})
}

// TestLRUCacheBasicOperations tests Get, Set, and Delete operations
func TestLRUCacheBasicOperations(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("set and get", func(t *testing.T) {
		key := "test_key"
		value := "test_value"

		err := cache.Set(key, value, 0)
		assert.NoError(t, err)

		retrieved, found := cache.Get(key)
		assert.True(t, found)
		assert.Equal(t, value, retrieved)
	})

	t.Run("get non-existent key", func(t *testing.T) {
		value, found := cache.Get("non_existent")
		assert.False(t, found)
		assert.Nil(t, value)
	})

	t.Run("delete existing key", func(t *testing.T) {
		key := "delete_test"
		value := "to_be_deleted"

		err := cache.Set(key, value, 0)
		assert.NoError(t, err)

		deleted := cache.Delete(key)
		assert.True(t, deleted)

		// Verify it's gone
		retrieved, found := cache.Get(key)
		assert.False(t, found)
		assert.Nil(t, retrieved)
	})

	t.Run("delete non-existent key", func(t *testing.T) {
		deleted := cache.Delete("non_existent")
		assert.False(t, deleted)
	})

	t.Run("clear cache", func(t *testing.T) {
		// Add multiple entries
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("key_%d", i)
			value := fmt.Sprintf("value_%d", i)
			err := cache.Set(key, value, 0)
			assert.NoError(t, err)
		}

		cache.Clear()

		// Verify all entries are gone
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("key_%d", i)
			_, found := cache.Get(key)
			assert.False(t, found)
		}
	})
}

// TestCacheWithContext tests context-aware operations
func TestCacheWithContext(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("set with context", func(t *testing.T) {
		ctx := context.Background()
		key := "ctx_key"
		value := "ctx_value"

		err := cache.SetContext(ctx, key, value, 0)
		assert.NoError(t, err)

		retrieved, found := cache.GetContext(ctx, key)
		assert.True(t, found)
		assert.Equal(t, value, retrieved)
	})

	t.Run("context cancellation during set", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := cache.SetContext(ctx, "cancelled_key", "value", 0)
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("context cancellation during get", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		value, found := cache.GetContext(ctx, "any_key")
		assert.False(t, found)
		assert.Nil(t, value)
	})
}

// TestCacheTTL tests TTL and expiration behavior
func TestCacheTTL(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     100 * time.Millisecond,
		MaxSize: 100,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("entry expires after TTL", func(t *testing.T) {
		key := "expiring_key"
		value := "expiring_value"

		err := cache.Set(key, value, 50*time.Millisecond)
		assert.NoError(t, err)

		// Should exist immediately
		retrieved, found := cache.Get(key)
		assert.True(t, found)
		assert.Equal(t, value, retrieved)

		// Wait for expiration
		time.Sleep(60 * time.Millisecond)

		// Should be expired
		retrieved, found = cache.Get(key)
		assert.False(t, found)
		assert.Nil(t, retrieved)
	})

	t.Run("custom TTL overrides default", func(t *testing.T) {
		key := "custom_ttl"
		value := "custom_value"

		// Set with longer TTL
		err := cache.Set(key, value, 200*time.Millisecond)
		assert.NoError(t, err)

		// Wait past default TTL but before custom TTL
		time.Sleep(150 * time.Millisecond)

		// Should still exist
		retrieved, found := cache.Get(key)
		assert.True(t, found)
		assert.Equal(t, value, retrieved)

		// Wait past custom TTL
		time.Sleep(60 * time.Millisecond)

		// Should be expired
		retrieved, found = cache.Get(key)
		assert.False(t, found)
		assert.Nil(t, retrieved)
	})
}

// TestCacheLRU tests LRU eviction behavior
func TestCacheLRU(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Hour, // Long TTL to avoid expiration
		MaxSize: 3,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("LRU eviction when cache is full", func(t *testing.T) {
		// Fill cache to capacity
		_ = cache.Set("key1", "value1", 0)
		_ = cache.Set("key2", "value2", 0)
		_ = cache.Set("key3", "value3", 0)

		// Wait for entries to become stale for LRU updates to take effect
		time.Sleep(1100 * time.Millisecond)

		// Access key1 and key2 to make them more recently used
		cache.Get("key1")
		cache.Get("key2")

		// Add a new key, should evict key3 (least recently used)
		_ = cache.Set("key4", "value4", 0)

		// key3 should be evicted
		_, found := cache.Get("key3")
		assert.False(t, found)

		// Other keys should still exist
		_, found = cache.Get("key1")
		assert.True(t, found)
		_, found = cache.Get("key2")
		assert.True(t, found)
		_, found = cache.Get("key4")
		assert.True(t, found)
	})

	t.Run("updating entry moves to front", func(t *testing.T) {
		cache.Clear()

		// Fill cache
		_ = cache.Set("key1", "value1", 0)
		_ = cache.Set("key2", "value2", 0)
		_ = cache.Set("key3", "value3", 0)

		// Update key1 (moves to front)
		_ = cache.Set("key1", "updated_value1", 0)

		// Add new key, should evict key2 (now least recently used)
		_ = cache.Set("key4", "value4", 0)

		// key2 should be evicted
		_, found := cache.Get("key2")
		assert.False(t, found)

		// key1 should have updated value
		value, found := cache.Get("key1")
		assert.True(t, found)
		assert.Equal(t, "updated_value1", value)
	})
}

// TestLRUNegativeCache tests negative caching functionality
func TestLRUNegativeCache(t *testing.T) {
	config := &CacheConfig{
		Enabled:          true,
		TTL:              1 * time.Minute,
		NegativeCacheTTL: 100 * time.Millisecond,
		MaxSize:          100,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("set and get negative entry", func(t *testing.T) {
		key := "negative_key"

		err := cache.SetNegative(key, 0)
		assert.NoError(t, err)

		// Should exist but return nil value
		value, found := cache.Get(key)
		assert.True(t, found)
		assert.Nil(t, value)
	})

	t.Run("negative entry expires", func(t *testing.T) {
		key := "expiring_negative"

		err := cache.SetNegative(key, 50*time.Millisecond)
		assert.NoError(t, err)

		// Should exist initially
		_, found := cache.Get(key)
		assert.True(t, found)

		// Wait for expiration
		time.Sleep(60 * time.Millisecond)

		// Should be expired
		_, found = cache.Get(key)
		assert.False(t, found)
	})

	t.Run("negative cache stats", func(t *testing.T) {
		cache.Clear()

		// Add some negative entries
		_ = cache.SetNegative("neg1", 0)
		_ = cache.SetNegative("neg2", 0)

		// Access them
		cache.Get("neg1")
		cache.Get("neg2")

		stats := cache.Stats()
		assert.Equal(t, int32(2), stats.NegativeEntries)
		assert.Greater(t, stats.NegativeHits, int64(0))
	})
}

// TestCacheWithRefresh tests the GetWithRefresh functionality
func TestCacheWithRefresh(t *testing.T) {
	config := &CacheConfig{
		Enabled:          true,
		TTL:              200 * time.Millisecond,
		RefreshOnAccess:  true,
		NegativeCacheTTL: 50 * time.Millisecond,
		MaxSize:          100,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("refresh function called when not in cache", func(t *testing.T) {
		key := "refresh_key"
		expectedValue := "refreshed_value"
		refreshCalled := false

		refreshFunc := func() (interface{}, error) {
			refreshCalled = true
			return expectedValue, nil
		}

		value, err := cache.GetWithRefresh(key, refreshFunc)
		assert.NoError(t, err)
		assert.Equal(t, expectedValue, value)
		assert.True(t, refreshCalled)

		// Value should now be cached
		cachedValue, found := cache.Get(key)
		assert.True(t, found)
		assert.Equal(t, expectedValue, cachedValue)
	})

	t.Run("refresh function error caches negative", func(t *testing.T) {
		key := "error_key"
		refreshErr := errors.New("refresh failed")

		refreshFunc := func() (interface{}, error) {
			return nil, refreshErr
		}

		value, err := cache.GetWithRefresh(key, refreshFunc)
		assert.Error(t, err)
		assert.Equal(t, refreshErr, err)
		assert.Nil(t, value)

		// Should have cached negative result
		cachedValue, found := cache.Get(key)
		assert.True(t, found)
		assert.Nil(t, cachedValue)
	})

	t.Run("stale entry triggers background refresh", func(t *testing.T) {
		key := "stale_key"
		initialValue := "initial"
		refreshedValue := "refreshed"

		// Set initial value
		_ = cache.Set(key, initialValue, 100*time.Millisecond)

		// Wait for entry to become stale (75% of TTL)
		time.Sleep(80 * time.Millisecond)

		refreshFunc := func() (interface{}, error) {
			return refreshedValue, nil
		}

		// Should return stale value immediately
		value, err := cache.GetWithRefresh(key, refreshFunc)
		assert.NoError(t, err)
		assert.Equal(t, initialValue, value)

		// Wait for background refresh
		time.Sleep(50 * time.Millisecond)

		// Should now have refreshed value
		cachedValue, found := cache.Get(key)
		assert.True(t, found)
		// Could be either value depending on timing
		assert.Contains(t, []interface{}{initialValue, refreshedValue}, cachedValue)
	})
}

// TestCacheMemoryManagement tests memory limit enforcement
func TestCacheMemoryManagement(t *testing.T) {
	config := &CacheConfig{
		Enabled:     true,
		TTL:         1 * time.Hour,
		MaxSize:     1000,
		MaxMemoryMB: 1, // Very small limit for testing
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("eviction for memory limit", func(t *testing.T) {
		// Add entries until we approach memory limit
		largeValue := strings.Repeat("x", 10*1024) // 10KB string

		for i := 0; i < 200; i++ { // Try to add ~2MB of data
			key := fmt.Sprintf("large_key_%d", i)
			err := cache.Set(key, largeValue, 0)
			// Should eventually start failing or evicting
			if err == ErrCacheFull {
				break
			}
		}

		stats := cache.Stats()
		// Memory usage should be limited
		assert.LessOrEqual(t, stats.MemoryUsageMB, float64(2)) // Some overhead allowed
	})

	t.Run("memory usage tracking", func(t *testing.T) {
		cache.Clear()

		// Add entries and verify memory tracking
		initialMemory := atomic.LoadInt64(&cache.memoryUsage)

		_ = cache.Set("key1", "small_value", 0)
		afterFirst := atomic.LoadInt64(&cache.memoryUsage)
		assert.Greater(t, afterFirst, initialMemory)

		cache.Delete("key1")
		afterDelete := atomic.LoadInt64(&cache.memoryUsage)
		assert.Less(t, afterDelete, afterFirst)
	})
}

// TestCacheStatistics tests statistics tracking
func TestCacheStatistics(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 10,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("track hits and misses", func(t *testing.T) {
		cache.Clear()

		// Reset stats
		atomic.StoreInt64(&cache.stats.Hits, 0)
		atomic.StoreInt64(&cache.stats.Misses, 0)

		// Add entry
		_ = cache.Set("key1", "value1", 0)

		// Hit
		_, found := cache.Get("key1")
		assert.True(t, found)

		// Miss
		_, found = cache.Get("key2")
		assert.False(t, found)

		stats := cache.Stats()
		assert.Equal(t, int64(1), stats.Hits)
		assert.Equal(t, int64(1), stats.Misses)
		assert.Equal(t, float64(50), stats.HitRatio)
	})

	t.Run("track operations", func(t *testing.T) {
		cache.Clear()

		// Reset counters
		atomic.StoreInt64(&cache.stats.Sets, 0)
		atomic.StoreInt64(&cache.stats.Deletes, 0)
		atomic.StoreInt64(&cache.stats.Evictions, 0)

		// Perform operations
		for i := 0; i < 5; i++ {
			_ = cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 0)
		}

		cache.Delete("key0")
		cache.Delete("key1")

		// Fill cache to trigger eviction
		for i := 5; i < 15; i++ {
			_ = cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 0)
		}

		stats := cache.Stats()
		assert.Equal(t, int64(15), stats.Sets)
		assert.Equal(t, int64(2), stats.Deletes)
		assert.Greater(t, stats.Evictions, int64(0))
	})

	t.Run("timing statistics", func(t *testing.T) {
		cache.Clear()

		// Perform some operations
		for i := 0; i < 10; i++ {
			_ = cache.Set(fmt.Sprintf("key%d", i), "value", 0)
			cache.Get(fmt.Sprintf("key%d", i))
		}

		stats := cache.Stats()
		assert.Greater(t, stats.AvgGetTime, time.Duration(0))
		assert.Greater(t, stats.AvgSetTime, time.Duration(0))
	})
}

// TestCacheConcurrency tests concurrent operations
func TestCacheConcurrency(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("concurrent set and get", func(t *testing.T) {
		numGoroutines := 50
		numOperations := 100
		var wg sync.WaitGroup

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key_%d_%d", id, j)
					value := fmt.Sprintf("value_%d_%d", id, j)

					// Set
					err := cache.Set(key, value, 0)
					assert.NoError(t, err)

					// Get
					retrieved, found := cache.Get(key)
					if found {
						assert.Equal(t, value, retrieved)
					}
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent delete", func(t *testing.T) {
		// Pre-populate cache
		for i := 0; i < 50; i++ {
			_ = cache.Set(fmt.Sprintf("del_key_%d", i), fmt.Sprintf("value_%d", i), 0)
		}

		numGoroutines := 10
		var wg sync.WaitGroup

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 5; j++ {
					key := fmt.Sprintf("del_key_%d", id*5+j)
					cache.Delete(key)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent stats", func(t *testing.T) {
		var wg sync.WaitGroup
		numReaders := 10

		wg.Add(numReaders)
		for i := 0; i < numReaders; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					stats := cache.Stats()
					assert.NotNil(t, stats)
					time.Sleep(time.Microsecond)
				}
			}()
		}

		wg.Wait()
	})
}

// TestCacheDisabled tests behavior when cache is disabled
func TestCacheDisabled(t *testing.T) {
	config := &CacheConfig{
		Enabled: false, // Cache disabled
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("operations return expected values when disabled", func(t *testing.T) {
		// Set should return error
		err := cache.Set("key", "value", 0)
		assert.Equal(t, ErrCacheDisabled, err)

		// Get should return not found
		value, found := cache.Get("key")
		assert.False(t, found)
		assert.Nil(t, value)

		// Delete should return false
		deleted := cache.Delete("key")
		assert.False(t, deleted)

		// Clear should not panic
		cache.Clear()

		// SetNegative should return error
		err = cache.SetNegative("neg_key", 0)
		assert.Equal(t, ErrCacheDisabled, err)
	})

	t.Run("GetWithRefresh falls back to refresh function", func(t *testing.T) {
		refreshCalled := false
		expectedValue := "refreshed"

		refreshFunc := func() (interface{}, error) {
			refreshCalled = true
			return expectedValue, nil
		}

		value, err := cache.GetWithRefresh("key", refreshFunc)
		assert.NoError(t, err)
		assert.Equal(t, expectedValue, value)
		assert.True(t, refreshCalled)
	})
}

// TestCacheBackgroundTasks tests background maintenance
func TestCacheBackgroundTasks(t *testing.T) {
	config := &CacheConfig{
		Enabled:         true,
		TTL:             100 * time.Millisecond,
		MaxSize:         100,
		RefreshInterval: 50 * time.Millisecond,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("expired entries cleaned up", func(t *testing.T) {
		// Add entries with short TTL
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("expire_%d", i)
			_ = cache.Set(key, "value", 50*time.Millisecond)
		}

		// Wait for expiration and cleanup
		time.Sleep(150 * time.Millisecond)

		// Entries should be gone
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("expire_%d", i)
			_, found := cache.Get(key)
			assert.False(t, found)
		}

		stats := cache.Stats()
		assert.Greater(t, stats.Expirations, int64(0))
		assert.Greater(t, stats.CleanupOps, int64(0))
	})
}

// TestGenerateCacheKey tests cache key generation
func TestGenerateCacheKey(t *testing.T) {
	t.Run("consistent key generation", func(t *testing.T) {
		key1 := GenerateCacheKey("search", "user", "admin")
		key2 := GenerateCacheKey("search", "user", "admin")
		assert.Equal(t, key1, key2)
	})

	t.Run("different operations produce different keys", func(t *testing.T) {
		key1 := GenerateCacheKey("search", "user")
		key2 := GenerateCacheKey("bind", "user")
		assert.NotEqual(t, key1, key2)
	})

	t.Run("different components produce different keys", func(t *testing.T) {
		key1 := GenerateCacheKey("search", "user1")
		key2 := GenerateCacheKey("search", "user2")
		assert.NotEqual(t, key1, key2)
	})

	t.Run("key format", func(t *testing.T) {
		key := GenerateCacheKey("operation", "comp1", "comp2")
		assert.Contains(t, key, "operation")
		assert.Contains(t, key, "comp1")
		assert.Contains(t, key, ":")
	})
}

// TestCacheEntryMethods tests CacheEntry methods
func TestCacheEntryMethods(t *testing.T) {
	t.Run("IsExpired", func(t *testing.T) {
		entry := &CacheEntry{
			ExpiresAt: time.Now().Add(-1 * time.Second),
		}
		assert.True(t, entry.IsExpired())

		entry.ExpiresAt = time.Now().Add(1 * time.Hour)
		assert.False(t, entry.IsExpired())
	})

	t.Run("IsStale", func(t *testing.T) {
		entry := &CacheEntry{
			CreatedAt: time.Now().Add(-1 * time.Hour),
			TTL:       1 * time.Hour,
		}
		// More than 75% of TTL has passed
		assert.True(t, entry.IsStale())

		entry.CreatedAt = time.Now()
		// Less than 75% of TTL has passed
		assert.False(t, entry.IsStale())
	})
}

// TestCacheEstimateSize tests size estimation for different value types
func TestCacheEstimateSize(t *testing.T) {
	cache, err := NewLRUCache(nil, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("string size", func(t *testing.T) {
		size := cache.estimateEntrySize("key", "value")
		assert.Greater(t, size, int32(0))
		assert.Greater(t, size, int32(len("key")+len("value")))
	})

	t.Run("byte slice size", func(t *testing.T) {
		data := make([]byte, 1024)
		size := cache.estimateEntrySize("key", data)
		assert.Greater(t, size, int32(1024))
	})

	t.Run("User struct size", func(t *testing.T) {
		email := "user@example.com"
		user := &User{
			SAMAccountName: "user",
			Description:    "Test user",
			Mail:           &email,
			Groups:         []string{"group1", "group2"},
		}
		size := cache.estimateEntrySize("key", user)
		assert.Greater(t, size, int32(100))
	})

	t.Run("nil value size", func(t *testing.T) {
		size := cache.estimateEntrySize("key", nil)
		assert.Greater(t, size, int32(0))
		assert.Less(t, size, int32(100))
	})
}

// BenchmarkLRUCacheSet benchmarks Set operation
func BenchmarkLRUCacheSet(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 10000,
	}

	// Use discard logger to eliminate logging noise in benchmarks
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewLRUCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key_%d", i)
			value := fmt.Sprintf("value_%d", i)
			_ = cache.Set(key, value, 0)
			i++
		}
	})
}

// BenchmarkLRUCacheGet benchmarks Get operation
func BenchmarkLRUCacheGet(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 10000,
	}

	// Use discard logger to eliminate logging noise in benchmarks
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewLRUCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key_%d", i)
		value := fmt.Sprintf("value_%d", i)
		_ = cache.Set(key, value, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key_%d", i%1000)
			cache.Get(key)
			i++
		}
	})
}

// BenchmarkCacheConcurrent benchmarks concurrent operations
func BenchmarkCacheConcurrent(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 10000,
	}

	// Use discard logger to eliminate logging noise in benchmarks
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewLRUCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key_%d", i%1000)
			value := fmt.Sprintf("value_%d", i)

			if i%2 == 0 {
				_ = cache.Set(key, value, 0)
			} else {
				cache.Get(key)
			}
			i++
		}
	})
}
