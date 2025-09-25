package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchIter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	ctx := context.Background()

	t.Run("successful iteration", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn", "uid", "mail"},
			nil,
		)

		entries := make([]*ldap.Entry, 0)
		var iterErr error

		for entry, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
			entries = append(entries, entry)
		}

		require.NoError(t, iterErr)
		assert.NotEmpty(t, entries, "Should have found at least one person")
	})

	t.Run("early termination", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn", "uid", "mail"},
			nil,
		)

		count := 0
		maxEntries := 1

		for entry, err := range client.SearchIter(ctx, searchRequest) {
			require.NoError(t, err)
			require.NotNil(t, entry)
			count++
			if count >= maxEntries {
				break // Early termination
			}
		}

		assert.Equal(t, maxEntries, count, "Should have terminated early after %d entries", maxEntries)
	})

	t.Run("context cancellation", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", // Broad search to ensure we have entries
			[]string{"cn"},
			nil,
		)

		cancelCtx, cancel := context.WithCancel(ctx)
		entries := make([]*ldap.Entry, 0)
		var iterErr error

		// Cancel context immediately
		cancel()

		for entry, err := range client.SearchIter(cancelCtx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
			entries = append(entries, entry)
		}

		// Should get a context error
		assert.Error(t, iterErr)
		assert.ErrorIs(t, iterErr, context.Canceled)
	})

	t.Run("invalid search filter", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(invalid filter", // Invalid LDAP filter
			[]string{"cn"},
			nil,
		)

		var iterErr error
		for _, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
		}

		assert.Error(t, iterErr, "Should error on invalid filter")
	})
}

func TestSearchPagedIter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	ctx := context.Background()

	t.Run("paged iteration", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn", "uid", "mail"},
			nil,
		)

		pageSize := uint32(2)
		entries := make([]*ldap.Entry, 0)
		var iterErr error

		for entry, err := range client.SearchPagedIter(ctx, searchRequest, pageSize) {
			if err != nil {
				iterErr = err
				break
			}
			entries = append(entries, entry)
		}

		require.NoError(t, iterErr)
		assert.NotEmpty(t, entries, "Should have found at least one person")
	})

	t.Run("context cancellation during paging", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		cancelCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
		defer cancel()

		pageSize := uint32(1) // Small page size to ensure multiple pages
		var iterErr error

		for _, err := range client.SearchPagedIter(cancelCtx, searchRequest, pageSize) {
			if err != nil {
				iterErr = err
				break
			}
			// Add small delay to ensure context timeout
			time.Sleep(2 * time.Millisecond)
		}

		assert.Error(t, iterErr)
		assert.ErrorIs(t, iterErr, context.DeadlineExceeded)
	})

	t.Run("early termination with paging", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		pageSize := uint32(1)
		count := 0
		maxEntries := 1

		for entry, err := range client.SearchPagedIter(ctx, searchRequest, pageSize) {
			require.NoError(t, err)
			require.NotNil(t, entry)
			count++
			if count >= maxEntries {
				break
			}
		}

		assert.Equal(t, maxEntries, count, "Should terminate after %d entries", maxEntries)
	})

	t.Run("zero page size", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		pageSize := uint32(0) // Zero page size should still work
		entries := make([]*ldap.Entry, 0)

		for entry, err := range client.SearchPagedIter(ctx, searchRequest, pageSize) {
			require.NoError(t, err)
			entries = append(entries, entry)
		}

		assert.NotEmpty(t, entries, "Should handle zero page size")
	})
}

func TestGroupMembersIter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()
	ctx := context.Background()

	t.Run("iterate group members", func(t *testing.T) {
		// Try to find any existing group first
		groups, err := client.FindGroupsOptimized(ctx, nil)
		if err != nil || len(groups) == 0 {
			t.Skip("No groups found in test LDAP")
		}

		groupDN := groups[0].DN()
		members := make([]string, 0)
		var iterErr error

		for member, err := range client.GroupMembersIter(ctx, groupDN) {
			if err != nil {
				iterErr = err
				break
			}
			if member != "" {
				members = append(members, member)
			}
		}

		require.NoError(t, iterErr)
		// Group may or may not have members, but iteration should complete successfully
		t.Logf("Found %d members in group %s", len(members), groupDN)
	})

	t.Run("context cancellation", func(t *testing.T) {
		groups, err := client.FindGroupsOptimized(ctx, nil)
		if err != nil || len(groups) == 0 {
			t.Skip("No groups found in test LDAP")
		}

		groupDN := groups[0].DN()
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		var iterErr error
		for _, err := range client.GroupMembersIter(cancelCtx, groupDN) {
			if err != nil {
				iterErr = err
				break
			}
		}

		assert.Error(t, iterErr)
		assert.ErrorIs(t, iterErr, context.Canceled)
	})

	t.Run("nonexistent group", func(t *testing.T) {
		nonexistentGroupDN := "cn=nonexistent,ou=groups," + client.config.BaseDN
		var iterErr error

		for _, err := range client.GroupMembersIter(ctx, nonexistentGroupDN) {
			if err != nil {
				iterErr = err
				break
			}
		}

		// Should error when group doesn't exist
		assert.Error(t, iterErr)
	})

	t.Run("early termination", func(t *testing.T) {
		// Use the test user DN as a non-group entry
		userDN := testData.ValidUserDN
		count := 0

		// This should find the entry but it won't have member attributes
		for member, err := range client.GroupMembersIter(ctx, userDN) {
			require.NoError(t, err)
			if member != "" {
				count++
				if count >= 1 {
					break // Early termination
				}
			}
		}

		// User entry shouldn't have member attributes, so count should be 0
		assert.Equal(t, 0, count, "User entry should not have member attributes")
	})
}

func TestIteratorMemoryEfficiency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	ctx := context.Background()

	t.Run("streaming without accumulation", func(t *testing.T) {
		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		// Process entries without accumulating them in memory
		processedCount := 0
		for entry, err := range client.SearchIter(ctx, searchRequest) {
			require.NoError(t, err)
			require.NotNil(t, entry)
			processedCount++
			// Simulate processing without storing
			_ = entry.DN
		}

		assert.Greater(t, processedCount, 0, "Should have processed at least one entry")
	})
}

func TestIteratorErrorPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	ctx := context.Background()

	t.Run("connection error simulation", func(t *testing.T) {
		// Save original config
		originalServer := client.config.Server

		// Set invalid server to force connection error
		client.config.Server = "invalid.server.local"

		searchRequest := ldap.NewSearchRequest(
			client.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=person)",
			[]string{"cn"},
			nil,
		)

		var iterErr error
		for _, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				iterErr = err
				break
			}
		}

		assert.Error(t, iterErr, "Should propagate connection error")

		// Restore original config
		client.config.Server = originalServer
	})
}

// Benchmark tests for iterators
func BenchmarkSearchIter(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})
	ctx := context.Background()

	searchRequest := ldap.NewSearchRequest(
		client.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{"cn", "uid", "mail"},
		nil,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		for entry, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				b.Fatal(err)
			}
			if entry != nil {
				count++
			}
		}
	}
}

func BenchmarkSearchPagedIter(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})
	ctx := context.Background()

	searchRequest := ldap.NewSearchRequest(
		client.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{"cn", "uid", "mail"},
		nil,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		for entry, err := range client.SearchPagedIter(ctx, searchRequest, 10) {
			if err != nil {
				b.Fatal(err)
			}
			if entry != nil {
				count++
			}
		}
	}
}
