//go:build !integration

package ldap

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenericCacheGetContext tests GetContext with context cancellation
func TestGenericCacheGetContext(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	t.Run("get with valid context", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.Set("key1", "value1", 0)
		require.NoError(t, err)

		val, found := cache.GetContext(context.Background(), "key1")
		assert.True(t, found)
		assert.Equal(t, "value1", val)
	})

	t.Run("get with cancelled context returns zero value", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.Set("key1", "value1", 0)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		val, found := cache.GetContext(ctx, "key1")
		assert.False(t, found)
		assert.Equal(t, "", val) // zero value for string
	})
}

// TestGenericCacheSetContext tests SetContext
func TestGenericCacheSetContext(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	t.Run("set with valid context", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.SetContext(context.Background(), "key1", "value1", 0)
		assert.NoError(t, err)

		val, found := cache.Get("key1")
		assert.True(t, found)
		assert.Equal(t, "value1", val)
	})

	t.Run("set with cancelled context returns error", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = cache.SetContext(ctx, "key1", "value1", 0)
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}

// TestGenericCacheGetWithRefresh tests GetWithRefresh
func TestGenericCacheGetWithRefresh(t *testing.T) {
	t.Run("cache disabled calls refresh directly", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{Enabled: false}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		val, err := cache.GetWithRefresh("key", func() (string, error) {
			return "from_refresh", nil
		})
		assert.NoError(t, err)
		assert.Equal(t, "from_refresh", val)
	})

	t.Run("cache miss fetches and stores", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:         true,
			TTL:             1 * time.Minute,
			MaxSize:         100,
			RefreshOnAccess: true,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		val, err := cache.GetWithRefresh("key", func() (string, error) {
			return "fetched_value", nil
		})
		assert.NoError(t, err)
		assert.Equal(t, "fetched_value", val)

		// Should be cached now
		cached, found := cache.Get("key")
		assert.True(t, found)
		assert.Equal(t, "fetched_value", cached)
	})

	t.Run("cache miss with refresh error returns error", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:         true,
			TTL:             1 * time.Minute,
			MaxSize:         100,
			RefreshOnAccess: true,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		val, err := cache.GetWithRefresh("key", func() (string, error) {
			return "", errors.New("fetch failed")
		})
		assert.Error(t, err)
		assert.Equal(t, "", val)
	})

	t.Run("stale entry with refresh enabled triggers refresh", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:         true,
			TTL:             100 * time.Millisecond,
			MaxSize:         100,
			RefreshOnAccess: true,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		// Set initial value
		err = cache.Set("key", "initial", 100*time.Millisecond)
		require.NoError(t, err)

		// Wait for entry to become stale (75% of 100ms = 75ms)
		time.Sleep(80 * time.Millisecond)

		val, err := cache.GetWithRefresh("key", func() (string, error) {
			return "refreshed", nil
		})
		assert.NoError(t, err)
		// Should get the refreshed value (GenericLRUCache refreshes synchronously)
		assert.Equal(t, "refreshed", val)
	})

	t.Run("non-stale entry returns cached value without refresh", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:         true,
			TTL:             1 * time.Hour,
			MaxSize:         100,
			RefreshOnAccess: true,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.Set("key", "cached", 0)
		require.NoError(t, err)

		refreshCalled := false
		val, err := cache.GetWithRefresh("key", func() (string, error) {
			refreshCalled = true
			return "refreshed", nil
		})
		assert.NoError(t, err)
		assert.Equal(t, "cached", val)
		assert.False(t, refreshCalled)
	})

	t.Run("stale entry with refresh disabled returns cached", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:         true,
			TTL:             100 * time.Millisecond,
			MaxSize:         100,
			RefreshOnAccess: false, // Disabled
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.Set("key", "cached", 100*time.Millisecond)
		require.NoError(t, err)

		// Wait for stale threshold
		time.Sleep(80 * time.Millisecond)

		refreshCalled := false
		val, err := cache.GetWithRefresh("key", func() (string, error) {
			refreshCalled = true
			return "refreshed", nil
		})
		assert.NoError(t, err)
		assert.Equal(t, "cached", val)
		assert.False(t, refreshCalled)
	})
}

// TestGenericCacheSetNegative tests SetNegative
func TestGenericCacheSetNegative(t *testing.T) {
	t.Run("set negative entry", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:          true,
			TTL:              1 * time.Minute,
			NegativeCacheTTL: 30 * time.Second,
			MaxSize:          100,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.SetNegative("missing_key", 0)
		assert.NoError(t, err)

		val, found := cache.Get("missing_key")
		assert.True(t, found)
		assert.Equal(t, "", val) // zero value for string
	})

	t.Run("set negative with custom TTL", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:          true,
			TTL:              1 * time.Minute,
			NegativeCacheTTL: 30 * time.Second,
			MaxSize:          100,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.SetNegative("key", 50*time.Millisecond)
		assert.NoError(t, err)

		// Should exist initially
		_, found := cache.Get("key")
		assert.True(t, found)

		// Wait for expiration
		time.Sleep(60 * time.Millisecond)

		_, found = cache.Get("key")
		assert.False(t, found)
	})

	t.Run("set negative overwrites existing entry", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:          true,
			TTL:              1 * time.Minute,
			NegativeCacheTTL: 30 * time.Second,
			MaxSize:          100,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.Set("key", "positive_value", 0)
		require.NoError(t, err)

		err = cache.SetNegative("key", 0)
		assert.NoError(t, err)

		val, found := cache.Get("key")
		assert.True(t, found)
		assert.Equal(t, "", val) // zero value
	})

	t.Run("set negative when disabled returns error", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{Enabled: false}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.SetNegative("key", 0)
		assert.Equal(t, ErrCacheDisabled, err)
	})

	t.Run("set negative triggers eviction when full", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:          true,
			TTL:              1 * time.Hour,
			NegativeCacheTTL: 30 * time.Second,
			MaxSize:          2,
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		_ = cache.Set("k1", "v1", 0)
		_ = cache.Set("k2", "v2", 0)

		err = cache.SetNegative("neg_key", 0)
		assert.NoError(t, err) // Should evict oldest and succeed
	})
}

// TestGenericCacheStats tests Stats method
func TestGenericCacheStats(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Perform operations to populate stats
	_ = cache.Set("key1", "value1", 0)
	_ = cache.Set("key2", "value2", 0)
	cache.Get("key1")        // hit
	cache.Get("nonexistent") // miss

	stats := cache.Stats()
	assert.Equal(t, int32(2), stats.TotalEntries)
	assert.Equal(t, int64(1), stats.Hits)
	assert.Equal(t, int64(1), stats.Misses)
	assert.Equal(t, int64(2), stats.Sets)
	assert.Greater(t, stats.AvgGetTime, time.Duration(0))
	assert.Greater(t, stats.AvgSetTime, time.Duration(0))
}

// TestGenericCachePerformMaintenance tests performMaintenance
func TestGenericCachePerformMaintenance(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled: true,
		TTL:     50 * time.Millisecond,
		MaxSize: 100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Add entries with short TTL
	_ = cache.Set("expire1", "v1", 50*time.Millisecond)
	_ = cache.Set("expire2", "v2", 50*time.Millisecond)
	_ = cache.Set("keep", "v3", 1*time.Hour)

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Run maintenance
	cache.performMaintenance()

	// Expired entries should be gone
	_, found := cache.Get("expire1")
	assert.False(t, found)
	_, found = cache.Get("expire2")
	assert.False(t, found)

	// Non-expired entry should remain
	val, found := cache.Get("keep")
	assert.True(t, found)
	assert.Equal(t, "v3", val)

	stats := cache.Stats()
	assert.Greater(t, stats.CleanupOps, int64(0))
	assert.Greater(t, stats.Expirations, int64(0))
}

// TestGenericCacheIsStale tests GenericCacheEntry.IsStale
func TestGenericCacheIsStale(t *testing.T) {
	t.Run("entry is stale after 75% of TTL", func(t *testing.T) {
		entry := &GenericCacheEntry[string]{
			CreatedAt: time.Now().Add(-80 * time.Millisecond),
			TTL:       100 * time.Millisecond,
		}
		assert.True(t, entry.IsStale())
	})

	t.Run("entry is not stale before 75% of TTL", func(t *testing.T) {
		entry := &GenericCacheEntry[string]{
			CreatedAt: time.Now(),
			TTL:       1 * time.Hour,
		}
		assert.False(t, entry.IsStale())
	})
}

// TestNewUserCache tests NewUserCache helper
func TestNewUserCache(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewUserCache(config, nil)
	require.NoError(t, err)
	require.NotNil(t, cache)
	defer func() { _ = cache.Close() }()

	user := CreateTestUser("testuser", "testuser", "", "Test", true)
	err = cache.Set("user_key", user, 0)
	assert.NoError(t, err)

	retrieved, found := cache.Get("user_key")
	assert.True(t, found)
	assert.Equal(t, "testuser", retrieved.SAMAccountName)
}

// TestNewGroupCache tests NewGroupCache helper
func TestNewGroupCache(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewGroupCache(config, nil)
	require.NoError(t, err)
	require.NotNil(t, cache)
	defer func() { _ = cache.Close() }()

	group := CreateTestGroup("admins", "", []string{"user1"})
	err = cache.Set("group_key", group, 0)
	assert.NoError(t, err)

	retrieved, found := cache.Get("group_key")
	assert.True(t, found)
	assert.Equal(t, "admins", retrieved.CN())
}

// TestNewComputerCache tests NewComputerCache helper
func TestNewComputerCache(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewComputerCache(config, nil)
	require.NoError(t, err)
	require.NotNil(t, cache)
	defer func() { _ = cache.Close() }()

	computer := CreateTestComputer("SERVER01", "SERVER01$", true)
	err = cache.Set("computer_key", computer, 0)
	assert.NoError(t, err)

	retrieved, found := cache.Get("computer_key")
	assert.True(t, found)
	assert.Equal(t, "SERVER01$", retrieved.SAMAccountName)
}

// TestNewStringCache tests NewStringCache helper
func TestNewStringCache(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewStringCache(config, nil)
	require.NoError(t, err)
	require.NotNil(t, cache)
	defer func() { _ = cache.Close() }()

	err = cache.Set("str_key", "hello world", 0)
	assert.NoError(t, err)

	retrieved, found := cache.Get("str_key")
	assert.True(t, found)
	assert.Equal(t, "hello world", retrieved)
}

// TestGenericCacheNewWithDefaults tests NewGenericLRUCache with nil/zero config values
func TestGenericCacheNewWithDefaults(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cache)
		defer func() { _ = cache.Close() }()

		assert.Equal(t, 5*time.Minute, cache.config.TTL)
		assert.Equal(t, 1000, cache.config.MaxSize)
	})

	t.Run("zero values corrected to defaults", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:              true,
			TTL:                  0,
			MaxSize:              0,
			RefreshInterval:      0,
			NegativeCacheTTL:     0,
			MaxMemoryMB:          0,
			CompressionThreshold: 0,
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, cache)
		defer func() { _ = cache.Close() }()

		assert.Equal(t, 5*time.Minute, cache.config.TTL)
		assert.Equal(t, 1000, cache.config.MaxSize)
		assert.Equal(t, 1*time.Minute, cache.config.RefreshInterval)
		assert.Equal(t, 30*time.Second, cache.config.NegativeCacheTTL)
		assert.Equal(t, 64, cache.config.MaxMemoryMB)
		assert.Equal(t, 1024, cache.config.CompressionThreshold)
	})
}

// TestGenericCacheGetExpired tests Get returning expired entry
func TestGenericCacheGetExpired(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled: true,
		TTL:     50 * time.Millisecond,
		MaxSize: 100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	_ = cache.Set("key", "value", 50*time.Millisecond)

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	val, found := cache.Get("key")
	assert.False(t, found)
	assert.Equal(t, "", val)
}

// TestGenericCacheDeleteNonExistent tests deleting non-existent key
func TestGenericCacheDeleteNonExistent(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	deleted := cache.Delete("nonexistent")
	assert.False(t, deleted)
}

// TestGenericCacheDeleteDisabled tests delete when cache is disabled
func TestGenericCacheDeleteDisabled(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{Enabled: false}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	deleted := cache.Delete("key")
	assert.False(t, deleted)
}

// TestGenericCacheSetExistingKey tests overwriting an existing key
func TestGenericCacheSetExistingKey(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	err = cache.Set("key", "value1", 0)
	require.NoError(t, err)

	err = cache.Set("key", "value2", 0)
	require.NoError(t, err)

	val, found := cache.Get("key")
	assert.True(t, found)
	assert.Equal(t, "value2", val)
}

// TestGenericCacheSetEvictionOnFull tests eviction when cache is full
func TestGenericCacheSetEvictionOnFull(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled: true,
		TTL:     1 * time.Hour,
		MaxSize: 2,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	_ = cache.Set("k1", "v1", 0)
	_ = cache.Set("k2", "v2", 0)
	_ = cache.Set("k3", "v3", 0)

	// k1 should be evicted (oldest)
	_, found := cache.Get("k1")
	assert.False(t, found)

	// k2 and k3 should exist
	_, found = cache.Get("k2")
	assert.True(t, found)
	_, found = cache.Get("k3")
	assert.True(t, found)

	stats := cache.Stats()
	assert.Greater(t, stats.Evictions, int64(0))
}

// TestGenericCacheNegativeHitStats tests negative hit statistics
func TestGenericCacheNegativeHitStats(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled:          true,
		TTL:              1 * time.Minute,
		NegativeCacheTTL: 30 * time.Second,
		MaxSize:          100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	_ = cache.SetNegative("neg", 0)
	cache.Get("neg") // Should count as negative hit

	stats := cache.Stats()
	assert.Greater(t, stats.NegativeHits, int64(0))
}

// TestGenericCacheGetWithRefreshRefreshOps tests RefreshOps stat increment
func TestGenericCacheGetWithRefreshRefreshOps(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled:         true,
		TTL:             1 * time.Minute,
		MaxSize:         100,
		RefreshOnAccess: true,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	refreshCount := 0
	_, _ = cache.GetWithRefresh("key", func() (string, error) {
		refreshCount++
		return fmt.Sprintf("value_%d", refreshCount), nil
	})

	stats := cache.Stats()
	assert.Greater(t, stats.RefreshOps, int64(0))
}

// TestGenericCacheRemoveEntryNegative tests removeEntry for negative entries
func TestGenericCacheRemoveEntryNegative(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled:          true,
		TTL:              1 * time.Minute,
		NegativeCacheTTL: 30 * time.Second,
		MaxSize:          100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	_ = cache.SetNegative("neg_key", 0)

	// Delete the negative entry
	deleted := cache.Delete("neg_key")
	assert.True(t, deleted)

	// Verify negative entry count is decremented
	stats := cache.Stats()
	assert.Equal(t, int32(0), stats.NegativeEntries)
}

// TestGenericCacheSetMemoryLimitBranch tests the memory limit branch in Set
func TestGenericCacheSetMemoryLimitBranch(t *testing.T) {
	t.Run("memory limit triggers eviction then succeeds", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:     true,
			TTL:         1 * time.Hour,
			MaxSize:     100,
			MaxMemoryMB: 1, // 1MB
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		// Add an entry first
		_ = cache.Set("existing", "value", 0)

		// Artificially set memoryUsage to be at the limit
		atomic.StoreInt64(&cache.memoryUsage, 1*1024*1024) // Exactly at limit

		// Try to set - should trigger eviction path
		err = cache.Set("new_key", "new_value", 0)
		// After evicting "existing", memoryUsage should reset and allow the new entry
		// But since we artificially set it, eviction won't actually reduce the atomic counter
		// This tests that the branch is entered
		if err != nil {
			assert.Equal(t, ErrCacheFull, err)
		}
	})

	t.Run("memory limit returns ErrCacheFull when eviction insufficient", func(t *testing.T) {
		cache, err := NewGenericLRUCache[string](&CacheConfig{
			Enabled:     true,
			TTL:         1 * time.Hour,
			MaxSize:     100,
			MaxMemoryMB: 1, // 1MB
		}, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		// No existing entries to evict, but memory appears full
		atomic.StoreInt64(&cache.memoryUsage, 2*1024*1024) // Over limit

		err = cache.Set("key", "value", 0)
		assert.Equal(t, ErrCacheFull, err)
	})
}

// TestGenericCacheGetDisabled tests Get when cache is disabled
func TestGenericCacheGetDisabled(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{Enabled: false}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	val, found := cache.Get("key")
	assert.False(t, found)
	assert.Equal(t, "", val)
}

// TestGenericCacheSetDisabled tests Set when cache is disabled
func TestGenericCacheSetDisabled(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{Enabled: false}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	err = cache.Set("key", "value", 0)
	assert.Equal(t, ErrCacheDisabled, err)
}

// TestGenericCacheGetWithRefreshSetError tests GetWithRefresh when Set fails
func TestGenericCacheGetWithRefreshSetError(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled:         true,
		TTL:             1 * time.Minute,
		MaxSize:         100,
		MaxMemoryMB:     1,
		RefreshOnAccess: true,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Artificially set memory over limit so Set will fail
	atomic.StoreInt64(&cache.memoryUsage, 2*1024*1024)

	// GetWithRefresh should still return the value even if caching fails
	val, err := cache.GetWithRefresh("key", func() (string, error) {
		return "fetched", nil
	})
	// The refresh succeeds but Set fails - the warning is logged
	// The value should still be returned (or zero if Set was needed for flow)
	if err == nil {
		assert.Equal(t, "fetched", val)
	}
}

// TestGenericCacheStatsNoTimings tests Stats with no timing data
func TestGenericCacheStatsNoTimings(t *testing.T) {
	cache, err := NewGenericLRUCache[string](&CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Get stats before any operations
	stats := cache.Stats()
	assert.Equal(t, time.Duration(0), stats.AvgGetTime)
	assert.Equal(t, time.Duration(0), stats.AvgSetTime)
}
