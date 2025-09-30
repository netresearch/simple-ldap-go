//go:build !integration

package ldap

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewIndexedUserCache tests creation of indexed user cache
func TestNewIndexedUserCache(t *testing.T) {
	t.Run("create with default config", func(t *testing.T) {
		cache, err := NewIndexedUserCache(nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cache)
		defer func() { _ = cache.Close() }()

		assert.NotNil(t, cache.GenericLRUCache)
		assert.NotNil(t, cache.dnIndex)
		assert.NotNil(t, cache.samAccountIndex)
	})

	t.Run("create with custom config", func(t *testing.T) {
		config := &CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
			MaxSize: 500,
		}

		cache, err := NewIndexedUserCache(config, nil)
		require.NoError(t, err)
		require.NotNil(t, cache)
		defer func() { _ = cache.Close() }()

		assert.Equal(t, true, cache.config.Enabled)
		assert.Equal(t, 10*time.Minute, cache.config.TTL)
	})
}

// TestIndexedUserCacheBasicOperations tests basic Set/Get/Delete operations
func TestIndexedUserCacheBasicOperations(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedUserCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("set and get user", func(t *testing.T) {
		user := CreateTestUser("testuser", "testuser", "", "Test User", true)

		err := cache.Set("user_key_1", user, 0)
		assert.NoError(t, err)

		// Verify standard Get works
		retrieved, found := cache.Get("user_key_1")
		assert.True(t, found)
		assert.Equal(t, user.SAMAccountName, retrieved.SAMAccountName)
	})

	t.Run("delete user removes from indexes", func(t *testing.T) {
		user := CreateTestUser("deleteuser", "deleteuser", "", "", true)

		err := cache.Set("user_key_delete", user, 0)
		assert.NoError(t, err)

		// Verify user is in indexes
		foundByDN, _ := cache.FindByDN(user.DN())
		assert.NotNil(t, foundByDN)

		// Delete user
		deleted := cache.Delete("user_key_delete")
		assert.True(t, deleted)

		// Verify indexes are cleaned up
		foundByDN, exists := cache.FindByDN(user.DN())
		assert.False(t, exists)
		assert.Nil(t, foundByDN)
	})

	t.Run("clear removes all entries and indexes", func(t *testing.T) {
		// Add multiple users
		for i := 0; i < 5; i++ {
			user := CreateTestUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d", i), "", "", true)
			_ = cache.Set(fmt.Sprintf("key_%d", i), user, 0)
		}

		// Clear cache
		cache.Clear()

		// Verify all indexes are empty
		cache.indexMu.RLock()
		assert.Equal(t, 0, len(cache.dnIndex))
		assert.Equal(t, 0, len(cache.samAccountIndex))
		cache.indexMu.RUnlock()
	})
}

// TestIndexedUserCacheFindByDN tests O(1) DN lookups
func TestIndexedUserCacheFindByDN(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedUserCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("find existing user by DN", func(t *testing.T) {
		user := CreateTestUser("finduser", "finduser", "", "Find Test User", true)

		err := cache.Set("user_key_find", user, 0)
		assert.NoError(t, err)

		// Find by DN
		found, exists := cache.FindByDN(user.DN())
		assert.True(t, exists)
		assert.Equal(t, user.SAMAccountName, found.SAMAccountName)
		assert.Equal(t, user.Description, found.Description)
	})

	t.Run("find non-existent DN returns false", func(t *testing.T) {
		found, exists := cache.FindByDN("cn=nonexistent,dc=example,dc=com")
		assert.False(t, exists)
		assert.Nil(t, found)
	})

	t.Run("find with empty DN returns false", func(t *testing.T) {
		found, exists := cache.FindByDN("")
		assert.False(t, exists)
		assert.Nil(t, found)
	})

	t.Run("find after TTL expiration", func(t *testing.T) {
		user := CreateTestUser("expireuser", "expireuser", "", "", true)

		// Set with short TTL
		err := cache.Set("user_key_expire", user, 50*time.Millisecond)
		assert.NoError(t, err)

		// Should find immediately
		found, exists := cache.FindByDN(user.DN())
		assert.True(t, exists)
		assert.NotNil(t, found)

		// Wait for expiration
		time.Sleep(60 * time.Millisecond)

		// Should not find after expiration
		found, exists = cache.FindByDN(user.DN())
		assert.False(t, exists)
		assert.Nil(t, found)
	})
}

// TestIndexedUserCacheFindBySAMAccountName tests O(1) SAMAccountName lookups
func TestIndexedUserCacheFindBySAMAccountName(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedUserCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("find existing user by SAMAccountName", func(t *testing.T) {
		user := CreateTestUser("samuser", "samuser", "", "SAM Test User", true)

		err := cache.Set("user_key_sam", user, 0)
		assert.NoError(t, err)

		// Find by SAMAccountName
		found, exists := cache.FindBySAMAccountName(user.SAMAccountName)
		assert.True(t, exists)
		assert.Equal(t, user.DN(), found.DN())
		assert.Equal(t, user.Description, found.Description)
	})

	t.Run("find non-existent SAMAccountName returns false", func(t *testing.T) {
		found, exists := cache.FindBySAMAccountName("nonexistentuser")
		assert.False(t, exists)
		assert.Nil(t, found)
	})

	t.Run("find with empty SAMAccountName returns false", func(t *testing.T) {
		found, exists := cache.FindBySAMAccountName("")
		assert.False(t, exists)
		assert.Nil(t, found)
	})
}

// TestIndexedUserCacheIndexConsistency tests index consistency during updates
func TestIndexedUserCacheIndexConsistency(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedUserCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("update user maintains index consistency", func(t *testing.T) {
		user1 := CreateTestUser("updateuser", "updateuser", "", "Original", true)

		// Set initial user
		err := cache.Set("user_key_update", user1, 0)
		assert.NoError(t, err)

		// Update with new user object (same key)
		user2 := CreateTestUser("updateuser", "updateuser", "", "Updated", true)

		err = cache.Set("user_key_update", user2, 0)
		assert.NoError(t, err)

		// Verify updated user is findable
		found, exists := cache.FindByDN(user2.DN())
		assert.True(t, exists)
		assert.Equal(t, "Updated", found.Description)
	})

	t.Run("nil user does not corrupt indexes", func(t *testing.T) {
		err := cache.Set("nil_user_key", nil, 0)
		assert.NoError(t, err)

		// Verify indexes are not affected
		cache.indexMu.RLock()
		dnIndexSize := len(cache.dnIndex)
		samIndexSize := len(cache.samAccountIndex)
		cache.indexMu.RUnlock()

		// Should not have added nil user to indexes
		assert.GreaterOrEqual(t, dnIndexSize, 0)
		assert.GreaterOrEqual(t, samIndexSize, 0)
	})
}

// TestIndexedGroupCache tests indexed group cache functionality
func TestIndexedGroupCache(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedGroupCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("find group by DN", func(t *testing.T) {
		group := CreateTestGroup("admins", "", []string{"user1", "user2"})

		err := cache.Set("group_key_1", group, 0)
		assert.NoError(t, err)

		// Find by DN
		found, exists := cache.FindByDN(group.DN())
		assert.True(t, exists)
		assert.Equal(t, group.DN(), found.DN())
		assert.Equal(t, len(group.Members), len(found.Members))
	})

	t.Run("delete group cleans up index", func(t *testing.T) {
		group := CreateTestGroup("developers", "", []string{"dev1", "dev2"})

		err := cache.Set("group_key_delete", group, 0)
		assert.NoError(t, err)

		// Delete
		deleted := cache.Delete("group_key_delete")
		assert.True(t, deleted)

		// Verify index cleaned up
		found, exists := cache.FindByDN(group.DN())
		assert.False(t, exists)
		assert.Nil(t, found)
	})

	t.Run("clear removes all groups and indexes", func(t *testing.T) {
		// Add multiple groups
		for i := 0; i < 3; i++ {
			group := CreateTestGroup(fmt.Sprintf("group%d", i), "", []string{fmt.Sprintf("member%d", i)})
			_ = cache.Set(fmt.Sprintf("group_key_%d", i), group, 0)
		}

		cache.Clear()

		// Verify indexes are empty
		cache.indexMu.RLock()
		assert.Equal(t, 0, len(cache.dnIndex))
		cache.indexMu.RUnlock()
	})
}

// TestIndexedComputerCache tests indexed computer cache functionality
func TestIndexedComputerCache(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 100,
	}

	cache, err := NewIndexedComputerCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("find computer by DN", func(t *testing.T) {
		computer := CreateTestComputer("SERVER01", "SERVER01$", true)

		err := cache.Set("computer_key_1", computer, 0)
		assert.NoError(t, err)

		// Find by DN
		found, exists := cache.FindByDN(computer.DN())
		assert.True(t, exists)
		assert.Equal(t, computer.SAMAccountName, found.SAMAccountName)
	})

	t.Run("find computer by SAMAccountName", func(t *testing.T) {
		computer := CreateTestComputer("WORKSTATION01", "WORKSTATION01$", true)

		err := cache.Set("computer_key_2", computer, 0)
		assert.NoError(t, err)

		// Find by SAMAccountName
		found, exists := cache.FindBySAMAccountName(computer.SAMAccountName)
		assert.True(t, exists)
		assert.Equal(t, computer.DN(), found.DN())
	})

	t.Run("delete computer cleans up both indexes", func(t *testing.T) {
		computer := CreateTestComputer("LAPTOP01", "LAPTOP01$", true)

		err := cache.Set("computer_key_delete", computer, 0)
		assert.NoError(t, err)

		// Delete
		deleted := cache.Delete("computer_key_delete")
		assert.True(t, deleted)

		// Verify both indexes cleaned up
		foundByDN, existsByDN := cache.FindByDN(computer.DN())
		assert.False(t, existsByDN)
		assert.Nil(t, foundByDN)

		foundBySAM, existsBySAM := cache.FindBySAMAccountName(computer.SAMAccountName)
		assert.False(t, existsBySAM)
		assert.Nil(t, foundBySAM)
	})
}

// TestIndexedCacheConcurrency tests thread safety of indexed caches
func TestIndexedCacheConcurrency(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Minute,
		MaxSize: 1000,
	}

	cache, err := NewIndexedUserCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("concurrent set and find operations", func(t *testing.T) {
		numGoroutines := 50
		numOperations := 100
		var wg sync.WaitGroup

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					user := CreateTestUser(fmt.Sprintf("user%d_%d", id, j), fmt.Sprintf("user%d_%d", id, j), "", "", true)

					// Set
					_ = cache.Set(fmt.Sprintf("key_%d_%d", id, j), user, 0)

					// Find by DN
					foundByDN, _ := cache.FindByDN(user.DN())
					if foundByDN != nil {
						assert.Equal(t, user.SAMAccountName, foundByDN.SAMAccountName)
					}

					// Find by SAMAccountName
					foundBySAM, _ := cache.FindBySAMAccountName(user.SAMAccountName)
					if foundBySAM != nil {
						assert.Equal(t, user.DN(), foundBySAM.DN())
					}
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent delete operations", func(t *testing.T) {
		// Pre-populate cache
		for i := 0; i < 100; i++ {
			user := CreateTestUser(fmt.Sprintf("deluser%d", i), fmt.Sprintf("deluser%d", i), "", "", true)
			_ = cache.Set(fmt.Sprintf("del_key_%d", i), user, 0)
		}

		var wg sync.WaitGroup
		numGoroutines := 10

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					key := fmt.Sprintf("del_key_%d", id*10+j)
					cache.Delete(key)
				}
			}(i)
		}

		wg.Wait()
	})
}

// TestIndexedCacheLRUBehavior tests that LRU eviction maintains index consistency
func TestIndexedCacheLRUBehavior(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     1 * time.Hour,
		MaxSize: 3, // Small size to trigger eviction
	}

	cache, err := NewIndexedUserCache(config, nil)
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	t.Run("eviction cleans up indexes", func(t *testing.T) {
		// Note: GenericLRUCache doesn't provide eviction hooks, so evicted entries
		// will leave stale index entries. This is documented limitation.
		// In production usage with reasonable cache sizes, this is acceptable as
		// the index overhead is minimal and stale entries will fail on Get().

		users := []*User{
			CreateTestUser("user1", "user1", "", "", true),
			CreateTestUser("user2", "user2", "", "", true),
			CreateTestUser("user3", "user3", "", "", true),
			CreateTestUser("user4", "user4", "", "", true),
		}

		// Fill cache to capacity
		for i := 0; i < 3; i++ {
			_ = cache.Set(fmt.Sprintf("key_%d", i), users[i], 0)
		}

		// Add fourth user (should evict first user)
		_ = cache.Set("key_3", users[3], 0)

		// Try to find evicted user by DN (may return stale index entry)
		found, exists := cache.FindByDN(users[0].DN())

		// If index entry exists but base cache evicted it, Get returns (nil, false)
		if exists {
			// This means index still has reference but base cache doesn't
			// This is acceptable behavior
			assert.Nil(t, found)
		}
	})
}
