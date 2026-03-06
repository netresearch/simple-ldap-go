//go:build !integration

package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIndexedGroupCacheSetNil tests setting nil group in indexed cache
func TestIndexedGroupCacheSetNil(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedGroupCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Setting nil should delegate to base cache without indexing
	err = cache.Set("nil_group", nil, 0)
	assert.NoError(t, err)
}

// TestIndexedGroupCacheFindByDNEmpty tests FindByDN with empty DN
func TestIndexedGroupCacheFindByDNEmpty(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedGroupCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	found, exists := cache.FindByDN("")
	assert.False(t, exists)
	assert.Nil(t, found)
}

// TestIndexedGroupCacheFindByDNNotInIndex tests FindByDN when DN is not in index
func TestIndexedGroupCacheFindByDNNotInIndex(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedGroupCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	found, exists := cache.FindByDN("cn=nonexistent,dc=example,dc=com")
	assert.False(t, exists)
	assert.Nil(t, found)
}

// TestIndexedComputerCacheSetNil tests setting nil computer in indexed cache
func TestIndexedComputerCacheSetNil(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	err = cache.Set("nil_computer", nil, 0)
	assert.NoError(t, err)
}

// TestIndexedComputerCacheClear tests Clear for computer cache
func TestIndexedComputerCacheClear(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Add computers
	c1 := CreateTestComputer("SERVER01", "SERVER01$", true)
	c2 := CreateTestComputer("SERVER02", "SERVER02$", true)
	_ = cache.Set("key1", c1, 0)
	_ = cache.Set("key2", c2, 0)

	// Verify indexed
	found, exists := cache.FindByDN(c1.DN())
	assert.True(t, exists)
	assert.NotNil(t, found)

	found, exists = cache.FindBySAMAccountName("SERVER02$")
	assert.True(t, exists)
	assert.NotNil(t, found)

	// Clear
	cache.Clear()

	// Verify indexes are empty
	cache.indexMu.RLock()
	assert.Equal(t, 0, len(cache.dnIndex))
	assert.Equal(t, 0, len(cache.samAccountIndex))
	cache.indexMu.RUnlock()

	// Verify lookups return nothing
	found, exists = cache.FindByDN(c1.DN())
	assert.False(t, exists)
	assert.Nil(t, found)
}

// TestIndexedComputerCacheFindByDNEmpty tests FindByDN with empty DN
func TestIndexedComputerCacheFindByDNEmpty(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	found, exists := cache.FindByDN("")
	assert.False(t, exists)
	assert.Nil(t, found)
}

// TestIndexedComputerCacheFindByDNNotInIndex tests FindByDN when DN is not in index
func TestIndexedComputerCacheFindByDNNotInIndex(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	found, exists := cache.FindByDN("cn=nonexistent,dc=example,dc=com")
	assert.False(t, exists)
	assert.Nil(t, found)
}

// TestIndexedComputerCacheFindBySAMAccountNameEmpty tests empty SAMAccountName
func TestIndexedComputerCacheFindBySAMAccountNameEmpty(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	found, exists := cache.FindBySAMAccountName("")
	assert.False(t, exists)
	assert.Nil(t, found)
}

// TestIndexedComputerCacheFindBySAMAccountNameNotInIndex tests non-existent SAMAccountName
func TestIndexedComputerCacheFindBySAMAccountNameNotInIndex(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	found, exists := cache.FindBySAMAccountName("NONEXISTENT$")
	assert.False(t, exists)
	assert.Nil(t, found)
}

// TestIndexedGroupCacheSetWithEmptyDN tests setting group with empty DN
func TestIndexedGroupCacheSetWithEmptyDN(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedGroupCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Group with empty DN should be stored but not indexed
	group := &Group{
		Object: Object{dn: "", cn: "emptydn"},
	}
	err = cache.Set("key", group, 0)
	assert.NoError(t, err)

	cache.indexMu.RLock()
	_, exists := cache.dnIndex[""]
	cache.indexMu.RUnlock()
	assert.False(t, exists)
}

// TestIndexedComputerCacheSetWithEmptyFields tests setting computer with empty fields
func TestIndexedComputerCacheSetWithEmptyFields(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Computer with empty DN and SAMAccountName should not be indexed
	computer := &Computer{
		Object:         Object{dn: "", cn: "empty"},
		SAMAccountName: "",
	}
	err = cache.Set("key", computer, 0)
	assert.NoError(t, err)
}
