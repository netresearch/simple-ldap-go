//go:build !integration

package ldap

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkIndexedUserCacheFindByDN benchmarks O(1) DN lookup
func BenchmarkIndexedUserCacheFindByDN(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000, // 1 minute in nanoseconds
		MaxSize: 10000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedUserCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache with 1000 users
	for i := 0; i < 1000; i++ {
		user := CreateTestUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d", i), "", fmt.Sprintf("User %d", i), true)
		_ = cache.Set(fmt.Sprintf("key_%d", i), user, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			dn := fmt.Sprintf("cn=user%d,ou=users,dc=example,dc=com", i%1000)
			_, _ = cache.FindByDN(dn)
			i++
		}
	})
}

// BenchmarkIndexedUserCacheFindBySAMAccountName benchmarks O(1) SAMAccountName lookup
func BenchmarkIndexedUserCacheFindBySAMAccountName(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 10000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedUserCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache with 1000 users
	for i := 0; i < 1000; i++ {
		user := CreateTestUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d", i), "", "", true)
		_ = cache.Set(fmt.Sprintf("key_%d", i), user, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			samAccountName := fmt.Sprintf("user%d", i%1000)
			_, _ = cache.FindBySAMAccountName(samAccountName)
			i++
		}
	})
}

// BenchmarkLinearSearchByDN benchmarks O(n) linear search for comparison
func BenchmarkLinearSearchByDN(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 10000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewUserCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache with 1000 users
	users := make([]*User, 1000)
	for i := 0; i < 1000; i++ {
		user := CreateTestUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d", i), "", "", true)
		users[i] = user
		_ = cache.Set(fmt.Sprintf("key_%d", i), user, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			targetDN := fmt.Sprintf("cn=user%d,ou=users,dc=example,dc=com", i%1000)

			// Linear search simulation
			for j := 0; j < 1000; j++ {
				user, found := cache.Get(fmt.Sprintf("key_%d", j))
				if found && user != nil && user.DN() == targetDN {
					break
				}
			}
			i++
		}
	})
}

// BenchmarkIndexedUserCacheSet benchmarks Set operation with index updates
func BenchmarkIndexedUserCacheSet(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 100000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedUserCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			user := CreateTestUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d", i), "", "", true)
			_ = cache.Set(fmt.Sprintf("key_%d", i), user, 0)
			i++
		}
	})
}

// BenchmarkIndexedUserCacheDelete benchmarks Delete operation with index cleanup
func BenchmarkIndexedUserCacheDelete(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 100000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedUserCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache
	for i := 0; i < b.N; i++ {
		user := CreateTestUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d", i), "", "", true)
		_ = cache.Set(fmt.Sprintf("key_%d", i), user, 0)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Delete(fmt.Sprintf("key_%d", i))
	}
}

// BenchmarkIndexedGroupCacheFindByDN benchmarks group DN lookup
func BenchmarkIndexedGroupCacheFindByDN(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 10000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedGroupCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache with 1000 groups
	for i := 0; i < 1000; i++ {
		group := CreateTestGroup(fmt.Sprintf("group%d", i), "", []string{"member1", "member2"})
		_ = cache.Set(fmt.Sprintf("key_%d", i), group, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			dn := fmt.Sprintf("cn=group%d,ou=groups,dc=example,dc=com", i%1000)
			_, _ = cache.FindByDN(dn)
			i++
		}
	})
}

// BenchmarkIndexedComputerCacheFindByDN benchmarks computer DN lookup
func BenchmarkIndexedComputerCacheFindByDN(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 10000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedComputerCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache with 1000 computers
	for i := 0; i < 1000; i++ {
		computer := CreateTestComputer(fmt.Sprintf("COMPUTER%d", i), fmt.Sprintf("COMPUTER%d$", i), true)
		_ = cache.Set(fmt.Sprintf("key_%d", i), computer, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			dn := fmt.Sprintf("cn=COMPUTER%d,ou=computers,dc=example,dc=com", i%1000)
			_, _ = cache.FindByDN(dn)
			i++
		}
	})
}

// BenchmarkIndexedComputerCacheFindBySAMAccountName benchmarks computer SAMAccountName lookup
func BenchmarkIndexedComputerCacheFindBySAMAccountName(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 10000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedComputerCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache with 1000 computers
	for i := 0; i < 1000; i++ {
		computer := CreateTestComputer(fmt.Sprintf("COMPUTER%d", i), fmt.Sprintf("COMPUTER%d$", i), true)
		_ = cache.Set(fmt.Sprintf("key_%d", i), computer, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			samAccountName := fmt.Sprintf("COMPUTER%d$", i%1000)
			_, _ = cache.FindBySAMAccountName(samAccountName)
			i++
		}
	})
}

// BenchmarkIndexedCacheConcurrentMixed benchmarks mixed concurrent operations
func BenchmarkIndexedCacheConcurrentMixed(b *testing.B) {
	config := &CacheConfig{
		Enabled: true,
		TTL:     60 * 1000000000,
		MaxSize: 100000,
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache, err := NewIndexedUserCache(config, discardLogger)
	require.NoError(b, err)
	defer func() { _ = cache.Close() }()

	// Pre-populate cache
	for i := 0; i < 5000; i++ {
		user := CreateTestUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d", i), "", "", true)
		_ = cache.Set(fmt.Sprintf("key_%d", i), user, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			op := i % 3
			userNum := i % 5000

			switch op {
			case 0: // Set
				user := CreateTestUser(fmt.Sprintf("user%d", userNum), fmt.Sprintf("user%d", userNum), "", "", true)
				_ = cache.Set(fmt.Sprintf("key_%d", userNum), user, 0)
			case 1: // FindByDN
				dn := fmt.Sprintf("cn=user%d,ou=users,dc=example,dc=com", userNum)
				_, _ = cache.FindByDN(dn)
			case 2: // FindBySAMAccountName
				samAccountName := fmt.Sprintf("user%d", userNum)
				_, _ = cache.FindBySAMAccountName(samAccountName)
			}
			i++
		}
	})
}
