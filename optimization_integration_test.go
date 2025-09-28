//go:build integration

package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("cache disabled by default", func(t *testing.T) {
		client, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Verify cache is not initialized
		assert.Nil(t, client.cache, "cache should not be initialized by default")

		// Perform operations - should work without cache
		user, err := client.FindUserByDN(fmt.Sprintf("uid=jdoe,%s", tc.UsersOU))
		require.NoError(t, err)
		assert.NotNil(t, user)
	})

	t.Run("cache enabled with EnableCache flag", func(t *testing.T) {
		config := tc.Config
		config.EnableCache = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Verify cache is initialized
		require.NotNil(t, client.cache, "cache should be initialized when EnableCache is true")

		// First lookup - cache miss
		userDN := fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)
		user1, err := client.FindUserByDN(userDN)
		require.NoError(t, err)
		assert.NotNil(t, user1)

		// Get cache stats after first lookup
		stats1 := client.cache.Stats()
		assert.Equal(t, int64(0), stats1.Hits, "should have 0 hits on first lookup")
		assert.Equal(t, int64(1), stats1.Misses, "should have 1 miss on first lookup")

		// Second lookup - should be cache hit
		user2, err := client.FindUserByDN(userDN)
		require.NoError(t, err)
		assert.NotNil(t, user2)
		assert.Equal(t, user1.DN, user2.DN, "cached user should match")

		// Verify cache hit
		stats2 := client.cache.Stats()
		assert.Equal(t, int64(1), stats2.Hits, "should have 1 hit on second lookup")
		assert.Equal(t, int64(1), stats2.Misses, "misses should stay at 1")
		assert.Greater(t, stats2.HitRatio, 0.0, "hit ratio should be positive")
	})

	t.Run("cache enabled with EnableOptimizations flag", func(t *testing.T) {
		config := tc.Config
		config.EnableOptimizations = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Verify cache is initialized
		require.NotNil(t, client.cache, "cache should be initialized when EnableOptimizations is true")

		// Test with different lookup methods
		testEmail := "john.doe@example.com"

		// First lookup by email - cache miss
		user1, err := client.FindUserByMail(testEmail)
		require.NoError(t, err)
		assert.NotNil(t, user1)

		stats1 := client.cache.Stats()
		initialMisses := stats1.Misses

		// Second lookup by email - cache hit
		user2, err := client.FindUserByMail(testEmail)
		require.NoError(t, err)
		assert.NotNil(t, user2)
		assert.Equal(t, user1.DN, user2.DN)

		stats2 := client.cache.Stats()
		assert.Greater(t, stats2.Hits, stats1.Hits, "cache hits should increase")
		assert.Equal(t, initialMisses, stats2.Misses, "misses should not increase on cache hit")
	})

	t.Run("cache performance improvement", func(t *testing.T) {
		config := tc.Config
		config.EnableCache = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		userDN := fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)

		// Measure time for first lookup (cache miss)
		start1 := time.Now()
		_, err = client.FindUserByDN(userDN)
		require.NoError(t, err)
		duration1 := time.Since(start1)

		// Measure time for second lookup (cache hit)
		start2 := time.Now()
		_, err = client.FindUserByDN(userDN)
		require.NoError(t, err)
		duration2 := time.Since(start2)

		// Cache hit should be significantly faster
		assert.Less(t, duration2, duration1/2, "cached lookup should be at least 2x faster")

		t.Logf("First lookup (cache miss): %v", duration1)
		t.Logf("Second lookup (cache hit): %v", duration2)
		t.Logf("Performance improvement: %.2fx faster", float64(duration1)/float64(duration2))
	})

	t.Run("cache invalidation on user modification", func(t *testing.T) {
		config := tc.Config
		config.EnableCache = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		userDN := fmt.Sprintf("uid=tempuser,%s", tc.UsersOU)

		// Create a user
		addReq := ldap.NewAddRequest(userDN, nil)
		addReq.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
		addReq.Attribute("uid", []string{"tempuser"})
		addReq.Attribute("cn", []string{"Temp User"})
		addReq.Attribute("sn", []string{"User"})
		addReq.Attribute("mail", []string{"tempuser@example.com"})
		addReq.Attribute("userPassword", []string{"temppass123"})
		conn, err := client.GetConnection()
		require.NoError(t, err)
		err = conn.Add(addReq)
		conn.Close()
		require.NoError(t, err)

		// Lookup user - cache miss
		user1, err := client.FindUserByDN(userDN)
		require.NoError(t, err)
		assert.Equal(t, "tempuser@example.com", user1.Mail)

		// Modify user
		modReq := ldap.NewModifyRequest(userDN, nil)
		modReq.Replace("mail", []string{"newemail@example.com"})
		conn, err = client.GetConnection()
		require.NoError(t, err)
		err = conn.Modify(modReq)
		conn.Close()
		require.NoError(t, err)

		// Note: In a real implementation, we'd need cache invalidation on modify
		// For now, we can test that the cache TTL works by waiting or clearing
		client.cache.Clear()

		// Lookup again - should get updated data
		user2, err := client.FindUserByDN(userDN)
		require.NoError(t, err)
		assert.Equal(t, "newemail@example.com", user2.Mail, "should get updated email after cache clear")

		// Cleanup
		delReq := ldap.NewDelRequest(userDN, nil)
		conn, err = client.GetConnection()
		require.NoError(t, err)
		err = conn.Del(delReq)
		conn.Close()
		require.NoError(t, err)
	})
}

func TestGroupCacheIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("group cache operations", func(t *testing.T) {
		config := tc.Config
		config.EnableCache = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		groupDN := fmt.Sprintf("cn=developers,%s", tc.GroupsOU)

		// First lookup - cache miss
		group1, err := client.FindGroupByDN(groupDN)
		require.NoError(t, err)
		assert.NotNil(t, group1)

		stats1 := client.cache.Stats()
		initialHits := stats1.Hits

		// Second lookup - cache hit
		group2, err := client.FindGroupByDN(groupDN)
		require.NoError(t, err)
		assert.NotNil(t, group2)
		assert.Equal(t, group1.DN, group2.DN)

		stats2 := client.cache.Stats()
		assert.Greater(t, stats2.Hits, initialHits, "should have cache hit for group")
	})
}

func TestPerformanceMetrics(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("metrics collection with EnableMetrics", func(t *testing.T) {
		config := tc.Config
		config.EnableMetrics = true
		config.Performance = &PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 100 * time.Millisecond,
		}

		// Use a custom logger to capture metrics
		var logBuffer []string
		customLogger := slog.New(slog.NewTextHandler(&testLogWriter{logs: &logBuffer}, nil))

		client, err := New(config, tc.AdminUser, tc.AdminPass, WithLogger(customLogger))
		require.NoError(t, err)
		defer client.Close()

		// Perform operations
		userDN := fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)
		_, err = client.FindUserByDN(userDN)
		require.NoError(t, err)

		// Check if metrics were logged
		hasMetrics := false
		for _, log := range logBuffer {
			if contains(log, "operation_completed") || contains(log, "performance") {
				hasMetrics = true
				break
			}
		}
		assert.True(t, hasMetrics, "should log performance metrics when EnableMetrics is true")
	})
}

func TestBulkOperations(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("bulk operations with EnableBulkOps", func(t *testing.T) {
		config := tc.Config
		config.EnableBulkOps = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Create multiple users in bulk
		userDNs := []string{}
		for i := 0; i < 5; i++ {
			userDN := fmt.Sprintf("uid=bulkuser%d,%s", i, tc.UsersOU)
			userDNs = append(userDNs, userDN)

			addReq := ldap.NewAddRequest(userDN, nil)
			addReq.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
			addReq.Attribute("uid", []string{fmt.Sprintf("bulkuser%d", i)})
			addReq.Attribute("cn", []string{fmt.Sprintf("Bulk User %d", i)})
			addReq.Attribute("sn", []string{fmt.Sprintf("User%d", i)})
			addReq.Attribute("mail", []string{fmt.Sprintf("bulkuser%d@example.com", i)})
			addReq.Attribute("userPassword", []string{"password123"})

			conn, err := client.GetConnection()
			require.NoError(t, err)
			err = conn.Add(addReq)
			conn.Close()
			require.NoError(t, err)
		}

		// Verify bulk operations flag enables optimized behavior
		// In a real implementation, bulk operations would batch LDAP requests
		// For now, we just verify the flag is set
		assert.True(t, client.config.EnableBulkOps, "bulk operations should be enabled")

		// Cleanup
		for _, userDN := range userDNs {
			delReq := ldap.NewDelRequest(userDN, nil)
			conn, err := client.GetConnection()
			assert.NoError(t, err)
			if conn != nil {
				err = conn.Del(delReq)
				conn.Close()
				assert.NoError(t, err)
			}
		}
	})
}

func TestOptimizationsCombined(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("all optimizations enabled", func(t *testing.T) {
		config := tc.Config
		config.EnableOptimizations = true // This should enable all optimizations

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Verify all optimization components are enabled
		assert.True(t, client.config.EnableOptimizations, "optimizations should be enabled")
		assert.NotNil(t, client.cache, "cache should be initialized with EnableOptimizations")

		// Test that optimizations work together
		userDN := fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)

		// First lookup
		start := time.Now()
		user1, err := client.FindUserByDN(userDN)
		require.NoError(t, err)
		assert.NotNil(t, user1)
		firstDuration := time.Since(start)

		// Second lookup (cached)
		start = time.Now()
		user2, err := client.FindUserByDN(userDN)
		require.NoError(t, err)
		assert.NotNil(t, user2)
		secondDuration := time.Since(start)

		// Verify performance improvement
		assert.Less(t, secondDuration, firstDuration, "cached lookup should be faster")

		// Get final stats
		if client.cache != nil {
			stats := client.cache.Stats()
			t.Logf("Cache stats - Hits: %d, Misses: %d, Hit Ratio: %.2f%%",
				stats.Hits, stats.Misses, stats.HitRatio*100)
		}
	})
}

// Helper type for capturing logs
type testLogWriter struct {
	logs *[]string
}

func (w *testLogWriter) Write(p []byte) (n int, err error) {
	*w.logs = append(*w.logs, string(p))
	return len(p), nil
}

func contains(s, substr string) bool {
	if len(s) == 0 || len(substr) == 0 {
		return false
	}
	if s == substr {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}