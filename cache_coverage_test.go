//go:build !integration

package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCacheInvalidateByPrimaryKey tests InvalidateByPrimaryKey for full coverage
func TestCacheInvalidateByPrimaryKey(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	t.Run("invalidate existing primary key with multiple cache keys", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		// Register multiple cache keys under one primary key
		_ = cache.Set("user:dn:john", "John by DN", 0)
		_ = cache.Set("user:sam:john", "John by SAM", 0)
		_ = cache.Set("user:email:john", "John by email", 0)
		cache.RegisterCacheKey("john", "user:dn:john")
		cache.RegisterCacheKey("john", "user:sam:john")
		cache.RegisterCacheKey("john", "user:email:john")

		// Verify all keys exist
		_, found := cache.Get("user:dn:john")
		assert.True(t, found)

		// Invalidate by primary key
		deleted := cache.InvalidateByPrimaryKey("john")
		assert.Equal(t, 3, deleted)

		// Verify all cache entries are gone
		_, found = cache.Get("user:dn:john")
		assert.False(t, found)
		_, found = cache.Get("user:sam:john")
		assert.False(t, found)
		_, found = cache.Get("user:email:john")
		assert.False(t, found)

		// Verify key index is cleaned up
		related := cache.GetRelatedKeys("john")
		assert.Nil(t, related)
	})

	t.Run("invalidate non-existent primary key returns zero", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		deleted := cache.InvalidateByPrimaryKey("nonexistent")
		assert.Equal(t, 0, deleted)
	})

	t.Run("invalidate with empty primary key returns zero", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		deleted := cache.InvalidateByPrimaryKey("")
		assert.Equal(t, 0, deleted)
	})

	t.Run("invalidate when cache is disabled returns zero", func(t *testing.T) {
		disabledCache, err := NewLRUCache(&CacheConfig{Enabled: false}, nil)
		require.NoError(t, err)
		defer func() { _ = disabledCache.Close() }()

		deleted := disabledCache.InvalidateByPrimaryKey("john")
		assert.Equal(t, 0, deleted)
	})

	t.Run("invalidate with some already deleted cache keys", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		_ = cache.Set("cache_a", "value_a", 0)
		_ = cache.Set("cache_b", "value_b", 0)
		cache.RegisterCacheKey("primary1", "cache_a")
		cache.RegisterCacheKey("primary1", "cache_b")
		cache.RegisterCacheKey("primary1", "cache_c") // Not set in cache

		// Delete one before invalidation
		cache.Delete("cache_a")

		deleted := cache.InvalidateByPrimaryKey("primary1")
		// Only cache_b should actually be deleted (cache_a already gone, cache_c never existed)
		assert.Equal(t, 1, deleted)
	})
}

// TestCacheGetRelatedKeys tests GetRelatedKeys for full coverage
func TestCacheGetRelatedKeys(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	t.Run("get related keys for existing primary key", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		cache.RegisterCacheKey("user1", "key_a")
		cache.RegisterCacheKey("user1", "key_b")
		cache.RegisterCacheKey("user1", "key_c")

		related := cache.GetRelatedKeys("user1")
		assert.Len(t, related, 3)
		assert.Contains(t, related, "key_a")
		assert.Contains(t, related, "key_b")
		assert.Contains(t, related, "key_c")
	})

	t.Run("get related keys returns a copy", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		cache.RegisterCacheKey("user2", "key_x")

		related := cache.GetRelatedKeys("user2")
		require.Len(t, related, 1)

		// Modify the returned slice
		related[0] = "modified"

		// Original should not be affected
		original := cache.GetRelatedKeys("user2")
		assert.Equal(t, "key_x", original[0])
	})

	t.Run("get related keys for non-existent primary key", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		related := cache.GetRelatedKeys("nonexistent")
		assert.Nil(t, related)
	})

	t.Run("get related keys with empty primary key", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		related := cache.GetRelatedKeys("")
		assert.Nil(t, related)
	})

	t.Run("get related keys when cache is disabled", func(t *testing.T) {
		disabledCache, err := NewLRUCache(&CacheConfig{Enabled: false}, nil)
		require.NoError(t, err)
		defer func() { _ = disabledCache.Close() }()

		related := disabledCache.GetRelatedKeys("user1")
		assert.Nil(t, related)
	})
}

// TestCacheRegisterCacheKeyFullCoverage tests RegisterCacheKey branches
func TestCacheRegisterCacheKeyFullCoverage(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	t.Run("register new primary key", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		cache.RegisterCacheKey("primary", "cache_key_1")
		related := cache.GetRelatedKeys("primary")
		assert.Len(t, related, 1)
		assert.Equal(t, "cache_key_1", related[0])
	})

	t.Run("register duplicate cache key is ignored", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		cache.RegisterCacheKey("primary", "cache_key_1")
		cache.RegisterCacheKey("primary", "cache_key_1") // Duplicate
		cache.RegisterCacheKey("primary", "cache_key_2")

		related := cache.GetRelatedKeys("primary")
		assert.Len(t, related, 2)
	})

	t.Run("register with empty primary key is no-op", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		cache.RegisterCacheKey("", "cache_key")
		// Should not store anything
	})

	t.Run("register with empty cache key is no-op", func(t *testing.T) {
		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		cache.RegisterCacheKey("primary", "")
		related := cache.GetRelatedKeys("primary")
		assert.Nil(t, related)
	})

	t.Run("register when cache is disabled is no-op", func(t *testing.T) {
		disabledCache, err := NewLRUCache(&CacheConfig{Enabled: false}, nil)
		require.NoError(t, err)
		defer func() { _ = disabledCache.Close() }()

		disabledCache.RegisterCacheKey("primary", "cache_key")
		// Should not panic
	})
}

// TestCacheSetNegativeOverwrite tests SetNegative overwriting an existing entry
func TestCacheSetNegativeOverwrite(t *testing.T) {
	config := &CacheConfig{
		Enabled:          true,
		TTL:              1 * time.Minute,
		NegativeCacheTTL: 30 * time.Second,
		MaxSize:          100,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// First set a normal entry
	err = cache.Set("key1", "value1", 0)
	require.NoError(t, err)

	// Now overwrite with a negative entry
	err = cache.SetNegative("key1", 0)
	require.NoError(t, err)

	// Should return nil value (negative)
	val, found := cache.Get("key1")
	assert.True(t, found)
	assert.Nil(t, val)
}

// TestCacheSetNegativeEviction tests SetNegative triggering eviction
func TestCacheSetNegativeEviction(t *testing.T) {
	config := &CacheConfig{
		Enabled:          true,
		TTL:              1 * time.Hour,
		NegativeCacheTTL: 30 * time.Second,
		MaxSize:          2,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Fill to capacity
	_ = cache.Set("key1", "value1", 0)
	_ = cache.Set("key2", "value2", 0)

	// Adding negative entry should trigger eviction
	err = cache.SetNegative("neg_key", 0)
	assert.NoError(t, err)
}

// TestCacheEstimateEntrySizeAllTypes tests all branches in estimateEntrySize
func TestCacheEstimateEntrySizeAllTypes(t *testing.T) {
	cache, err := NewLRUCache(nil, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("Group type", func(t *testing.T) {
		group := &Group{
			Object:  Object{dn: "cn=admins,dc=example,dc=com"},
			Members: []string{"user1", "user2", "user3"},
		}
		size := cache.estimateEntrySize("group_key", group)
		assert.Greater(t, size, int32(0))
	})

	t.Run("User slice", func(t *testing.T) {
		email := "user@test.com"
		users := []User{
			{
				Object:         Object{dn: "cn=user1,dc=example,dc=com"},
				SAMAccountName: "user1",
				Description:    "Test User 1",
				Mail:           &email,
				Groups:         []string{"group1"},
			},
			{
				Object:         Object{dn: "cn=user2,dc=example,dc=com"},
				SAMAccountName: "user2",
				Description:    "Test User 2",
			},
		}
		size := cache.estimateEntrySize("users_key", users)
		assert.Greater(t, size, int32(100))
	})

	t.Run("Group slice", func(t *testing.T) {
		groups := []Group{
			{
				Object:  Object{dn: "cn=group1,dc=example,dc=com"},
				Members: []string{"user1", "user2"},
			},
			{
				Object:  Object{dn: "cn=group2,dc=example,dc=com"},
				Members: []string{"user3"},
			},
		}
		size := cache.estimateEntrySize("groups_key", groups)
		assert.Greater(t, size, int32(100))
	})

	t.Run("unknown type uses conservative estimate", func(t *testing.T) {
		type customType struct {
			data string
		}
		size := cache.estimateEntrySize("key", &customType{data: "test"})
		// Should be at least key length + 256 (conservative) + 64 (overhead)
		assert.Greater(t, size, int32(256))
	})
}

// TestCacheSetWithPrimaryKeyDisabled tests SetWithPrimaryKey when cache is disabled
func TestCacheSetWithPrimaryKeyDisabled(t *testing.T) {
	cache, err := NewLRUCache(&CacheConfig{Enabled: false}, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	err = cache.SetWithPrimaryKey("key", "value", time.Minute, "primary")
	assert.Equal(t, ErrCacheDisabled, err)
}

// TestCacheRecordTimingsOverflow tests timing buffer overflow
func TestCacheRecordTimingsOverflow(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 2000,
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Record more than 1000 get times
	for i := 0; i < 1100; i++ {
		cache.recordGetTime(time.Duration(i) * time.Microsecond)
	}

	cache.timingMu.Lock()
	assert.LessOrEqual(t, len(cache.getTimes), 1000)
	cache.timingMu.Unlock()

	// Record more than 1000 set times
	for i := 0; i < 1100; i++ {
		cache.recordSetTime(time.Duration(i) * time.Microsecond)
	}

	cache.timingMu.Lock()
	assert.LessOrEqual(t, len(cache.setTimes), 1000)
	cache.timingMu.Unlock()
}

// TestCacheGenerateCacheKeyLongPrefix tests cache key generation with long prefix
func TestCacheGenerateCacheKeyLongPrefix(t *testing.T) {
	longComponent := strings.Repeat("x", 100)
	key := GenerateCacheKey("operation", longComponent)
	// Prefix should be truncated to 32 chars
	parts := strings.SplitN(key, ":", 2)
	prefix := parts[0] + ":" + strings.SplitN(parts[1], ":", 2)[0]
	assert.LessOrEqual(t, len(prefix), 42) // operation:truncated + some margin for hash prefix
}

// TestCacheDefaultConfigValues tests DefaultCacheConfig
func TestCacheDefaultConfigValues(t *testing.T) {
	config := DefaultCacheConfig()
	assert.False(t, config.Enabled)
	assert.Equal(t, 5*time.Minute, config.TTL)
	assert.Equal(t, 1000, config.MaxSize)
	assert.Equal(t, 1*time.Minute, config.RefreshInterval)
	assert.True(t, config.RefreshOnAccess)
	assert.Equal(t, 30*time.Second, config.NegativeCacheTTL)
	assert.Equal(t, 64, config.MaxMemoryMB)
	assert.False(t, config.CompressionEnabled)
	assert.Equal(t, 1024, config.CompressionThreshold)
}

// TestCacheEvictForSpaceFullCoverage tests evictForSpace edge cases
func TestCacheEvictForSpaceFullCoverage(t *testing.T) {
	t.Run("no eviction needed", func(t *testing.T) {
		config := &CacheConfig{
			Enabled:     true,
			TTL:         1 * time.Hour,
			MaxSize:     100,
			MaxMemoryMB: 64,
		}

		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		err = cache.evictForSpace(100)
		assert.NoError(t, err)
	})

	t.Run("eviction succeeds when enough items", func(t *testing.T) {
		config := &CacheConfig{
			Enabled:     true,
			TTL:         1 * time.Hour,
			MaxSize:     100,
			MaxMemoryMB: 1, // 1MB
		}

		cache, err := NewLRUCache(config, nil)
		require.NoError(t, err)
		defer func() { _ = cache.Close() }()

		// Fill up to near memory limit
		largeVal := strings.Repeat("a", 100*1024) // 100KB
		for i := 0; i < 10; i++ {
			_ = cache.Set(fmt.Sprintf("key%d", i), largeVal, 0)
		}

		// Evict space should succeed
		err = cache.evictForSpace(100 * 1024)
		assert.NoError(t, err)
	})
}

// TestCacheNewLRUCacheWithLogger tests creating cache with custom logger
func TestCacheNewLRUCacheWithLogger(t *testing.T) {
	logger := slog.Default()
	cache, err := NewLRUCache(&CacheConfig{
		Enabled:    true,
		TTL:        time.Minute,
		MaxSize:    10,
		MaxMemoryMB: 64,
	}, logger)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	assert.NotNil(t, cache)
}

// TestCacheSetContextMemoryEviction tests SetContext memory-based eviction
func TestCacheSetContextMemoryEviction(t *testing.T) {
	config := &CacheConfig{
		Enabled:     true,
		TTL:         1 * time.Hour,
		MaxSize:     10000,
		MaxMemoryMB: 1, // 1MB very small to trigger memory eviction
	}

	cache, err := NewLRUCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Try to add large entries that should trigger memory eviction
	largeVal := strings.Repeat("x", 500*1024) // 500KB
	ctx := context.Background()

	err = cache.SetContext(ctx, "large1", largeVal, 0)
	assert.NoError(t, err)

	err = cache.SetContext(ctx, "large2", largeVal, 0)
	// May succeed (evicting large1) or fail (ErrCacheFull)
	if err != nil {
		assert.Equal(t, ErrCacheFull, err)
	}
}
