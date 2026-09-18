//go:build integration
// +build integration

package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unit tests beside this one pin cacheConfigFor; this one pins that New
// actually calls it. Without the wiring the cache is built from
// DefaultCacheConfig() and holds 1000 entries whatever the caller asked for
// (#240). It runs against a real server so the whole path is exercised; since
// #246 the cache is built whatever the server is called.

func TestNewBuildsTheCacheFromTheSuppliedConfig(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	config := tc.Config
	config.EnableCache = true
	config.Cache = &CacheConfig{
		MaxSize: 2,
		TTL:     7 * time.Minute,
	}

	client, err := New(config, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	require.NotNil(t, client.cache, "caching was requested but no cache was built")

	// Three entries into a cache sized for two: the third must evict the first.
	for _, key := range []string{"first", "second", "third"} {
		require.NoError(t, client.cache.Set(key, key, time.Minute))
	}

	stats := client.GetCacheStats()
	require.NotNil(t, stats)
	assert.Positive(t, stats.Evictions,
		"no eviction after three writes into a cache configured for two entries")
	assert.LessOrEqual(t, stats.TotalEntries, int32(2),
		"the cache holds more entries than MaxSize allows")

	_, found := client.cache.Get("first")
	assert.False(t, found, "the oldest entry survived eviction")
}

func TestNewDoesNotWriteBackIntoTheCallersCacheConfig(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	supplied := &CacheConfig{} // every field at its zero value

	config := tc.Config
	config.EnableCache = true
	config.Cache = supplied

	client, err := New(config, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	assert.Equal(t, 0, supplied.MaxSize, "MaxSize was written back to the caller's struct")
	assert.Equal(t, time.Duration(0), supplied.TTL, "TTL was written back to the caller's struct")
	assert.False(t, supplied.Enabled, "Enabled was flipped in the caller's struct")
}
