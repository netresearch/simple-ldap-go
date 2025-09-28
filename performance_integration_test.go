//go:build integration

package ldap

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerformanceMonitoring(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("metrics collection enabled", func(t *testing.T) {
		config := tc.Config
		config.EnableMetrics = true
		config.Performance = &PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 50 * time.Millisecond,
		}

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Verify performance monitor is initialized
		assert.NotNil(t, client.perfMonitor, "perfMonitor should be initialized when EnableMetrics is true")

		// Perform some operations
		userDN := fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)
		_, _ = client.FindUserByDN(userDN)
		_, _ = client.FindUserByMail("john.doe@example.com")
		_, _ = client.FindUserBySAMAccountName("jdoe")

		// Get performance stats
		stats := client.GetPerformanceStats()
		assert.NotNil(t, stats)
		assert.Greater(t, stats.OperationsTotal, int64(0), "should have recorded operations")
		assert.NotNil(t, stats.OperationsByType)
		assert.Contains(t, stats.OperationsByType, "FindUserByDN")
		assert.Contains(t, stats.OperationsByType, "FindUserByMail")
		assert.Contains(t, stats.OperationsByType, "FindUserBySAMAccountName")
	})

	t.Run("cache hit tracking", func(t *testing.T) {
		config := tc.Config
		config.EnableMetrics = true
		config.EnableCache = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		userDN := fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)

		// First lookup - cache miss
		_, err = client.FindUserByDN(userDN)
		require.NoError(t, err)

		// Second lookup - cache hit
		_, err = client.FindUserByDN(userDN)
		require.NoError(t, err)

		// Check metrics
		stats := client.GetPerformanceStats()
		assert.Greater(t, stats.CacheHits, int64(0), "should have cache hits")
		assert.Greater(t, stats.CacheMisses, int64(0), "should have cache misses")
		assert.Greater(t, stats.CacheHitRatio, 0.0, "cache hit ratio should be positive")
	})

	t.Run("slow query detection", func(t *testing.T) {
		config := tc.Config
		config.EnableMetrics = true
		config.Performance = &PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 1 * time.Nanosecond, // Very low threshold to ensure queries are marked as slow
		}

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Perform operation
		userDN := fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)
		_, _ = client.FindUserByDN(userDN)

		// Check metrics
		stats := client.GetPerformanceStats()
		assert.Greater(t, stats.SlowQueries, int64(0), "should have detected slow queries")
	})
}

func TestBulkOperationsPerformance(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("bulk create users", func(t *testing.T) {
		config := tc.Config
		config.EnableBulkOps = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Prepare test users
		users := []FullUser{
			{
				CN:             "Bulk User 1",
				FirstName:      "Bulk1",
				LastName:       "User1",
				Email:          ptr("bulk1@example.com"),
				SAMAccountName: ptr("bulkuser1"),
				ObjectClasses: []string{
					"top",
					"person",
					"organizationalPerson",
					"inetOrgPerson",
				},
			},
			{
				CN:             "Bulk User 2",
				FirstName:      "Bulk2",
				LastName:       "User2",
				Email:          ptr("bulk2@example.com"),
				SAMAccountName: ptr("bulkuser2"),
				ObjectClasses: []string{
					"top",
					"person",
					"organizationalPerson",
					"inetOrgPerson",
				},
			},
			{
				CN:             "Bulk User 3",
				FirstName:      "Bulk3",
				LastName:       "User3",
				Email:          ptr("bulk3@example.com"),
				SAMAccountName: ptr("bulkuser3"),
				ObjectClasses: []string{
					"top",
					"person",
					"organizationalPerson",
					"inetOrgPerson",
				},
			},
		}

		// Set path for users
		for i := range users {
			users[i].Path = &tc.UsersOU
		}

		// Create users in bulk
		results, err := client.BulkCreateUsers(users, "password123")
		require.NoError(t, err)
		assert.Len(t, results, len(users))

		// Check results
		successCount := 0
		for _, result := range results {
			if result.Error == nil {
				successCount++
			} else {
				t.Logf("User creation failed: %v", result.Error)
			}
		}
		assert.Greater(t, successCount, 0, "at least some users should be created")

		// Cleanup
		for i := range users {
			dn := fmt.Sprintf("cn=%s,%s", users[i].CN, tc.UsersOU)
			_ = client.DeleteUser(dn)
		}
	})

	t.Run("bulk operations disabled by default", func(t *testing.T) {
		config := tc.Config
		// EnableBulkOps is false by default

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		users := []FullUser{{CN: "Test User"}}
		_, err = client.BulkCreateUsers(users, "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bulk operations are not enabled")
	})

	t.Run("bulk delete users", func(t *testing.T) {
		config := tc.Config
		config.EnableBulkOps = true

		client, err := New(config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Create test users first
		conn, err := client.GetConnection()
		require.NoError(t, err)

		dns := []string{}
		for i := 1; i <= 3; i++ {
			dn := fmt.Sprintf("cn=DeleteTest%d,%s", i, tc.UsersOU)
			dns = append(dns, dn)

			addReq := ldap.NewAddRequest(dn, nil)
			addReq.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
			addReq.Attribute("cn", []string{fmt.Sprintf("DeleteTest%d", i)})
			addReq.Attribute("sn", []string{fmt.Sprintf("Test%d", i)})
			addReq.Attribute("uid", []string{fmt.Sprintf("deletetest%d", i)})
			_ = conn.Add(addReq)
		}
		conn.Close()

		// Delete users in bulk
		results, err := client.BulkDeleteUsers(dns)
		require.NoError(t, err)
		assert.Len(t, results, len(dns))

		// Check results
		successCount := 0
		for _, result := range results {
			if result.Error == nil {
				successCount++
			}
		}
		assert.Greater(t, successCount, 0, "at least some users should be deleted")
	})
}

func BenchmarkBulkVsSequential(b *testing.B) {
	// This would require a test container setup
	b.Skip("Skipping benchmark that requires LDAP container")
}

// Helper function to create string pointer
func ptr(s string) *string {
	return &s
}
