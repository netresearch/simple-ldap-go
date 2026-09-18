package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cache the client builds must come from the configuration the caller
// supplied. Before this, New built it from DefaultCacheConfig() and never read
// Config.Cache, so every field but TTL was inert (#240).

func TestCacheConfigForUsesTheSuppliedConfig(t *testing.T) {
	supplied := &CacheConfig{
		MaxSize:              4242,
		MaxMemoryMB:          256,
		TTL:                  7 * time.Minute,
		NegativeCacheTTL:     11 * time.Second,
		RefreshInterval:      3 * time.Minute,
		RefreshOnAccess:      true,
		CompressionEnabled:   true,
		CompressionThreshold: 2048,
	}

	resolved := cacheConfigFor(Config{Cache: supplied})

	require.NotNil(t, resolved)
	assert.Equal(t, 4242, resolved.MaxSize)
	assert.Equal(t, 256, resolved.MaxMemoryMB)
	assert.Equal(t, 7*time.Minute, resolved.TTL)
	assert.Equal(t, 11*time.Second, resolved.NegativeCacheTTL)
	assert.Equal(t, 3*time.Minute, resolved.RefreshInterval)
	assert.True(t, resolved.RefreshOnAccess)
	assert.True(t, resolved.CompressionEnabled)
	assert.Equal(t, 2048, resolved.CompressionThreshold)
}

func TestCacheConfigForFallsBackToDefaultsWhenNoneSupplied(t *testing.T) {
	defaults := DefaultCacheConfig()

	resolved := cacheConfigFor(Config{})

	require.NotNil(t, resolved)
	assert.Equal(t, defaults.MaxSize, resolved.MaxSize)
	assert.Equal(t, defaults.TTL, resolved.TTL)
	assert.Equal(t, defaults.NegativeCacheTTL, resolved.NegativeCacheTTL)
}

func TestCacheConfigForEnablesTheCacheRegardlessOfTheSuppliedFlag(t *testing.T) {
	// Activation is governed by Config.EnableCache / Config.EnableOptimizations;
	// reaching this function at all means the caller asked for a cache.
	resolved := cacheConfigFor(Config{Cache: &CacheConfig{Enabled: false, MaxSize: 10}})

	require.NotNil(t, resolved)
	assert.True(t, resolved.Enabled)
	assert.Equal(t, 10, resolved.MaxSize)
}

func TestCacheConfigForDoesNotMutateTheCallersConfig(t *testing.T) {
	// NewLRUCache writes defaults into the config it is handed, so handing it the
	// caller's struct would rewrite fields the caller left at zero and flip
	// Enabled underneath them.
	supplied := &CacheConfig{MaxSize: 0, TTL: 0, Enabled: false}

	resolved := cacheConfigFor(Config{Cache: supplied})
	_, err := NewLRUCache(resolved, nil)
	require.NoError(t, err)

	assert.Equal(t, 0, supplied.MaxSize, "MaxSize was written back to the caller's struct")
	assert.Equal(t, time.Duration(0), supplied.TTL, "TTL was written back to the caller's struct")
	assert.False(t, supplied.Enabled, "Enabled was flipped in the caller's struct")
}
