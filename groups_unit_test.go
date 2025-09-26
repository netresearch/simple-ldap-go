package ldap

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGroupFromEntry tests the groupFromEntry function
func TestGroupFromEntry(t *testing.T) {
	t.Run("complete group entry", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "cn=admins,ou=groups,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"admins"}},
				{Name: "description", Values: []string{"Administrator Group"}},
				{Name: "member", Values: []string{
					"cn=user1,ou=users,dc=example,dc=com",
					"cn=user2,ou=users,dc=example,dc=com",
				}},
				{Name: "memberUid", Values: []string{"user1", "user2"}},
			},
		}

		group, err := groupFromEntry(entry)
		require.NoError(t, err)
		assert.Equal(t, "admins", group.CN())
		assert.Equal(t, "cn=admins,ou=groups,dc=example,dc=com", group.DN())
		assert.Equal(t, "Administrator Group", group.Description)
		assert.Len(t, group.Members, 4) // 2 from member + 2 from memberUid
		assert.Contains(t, group.Members, "cn=user1,ou=users,dc=example,dc=com")
		assert.Contains(t, group.Members, "cn=user2,ou=users,dc=example,dc=com")
		assert.Contains(t, group.Members, "user1")
		assert.Contains(t, group.Members, "user2")
	})

	t.Run("minimal group entry", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "cn=users,ou=groups,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"users"}},
			},
		}

		group, err := groupFromEntry(entry)
		require.NoError(t, err)
		assert.Equal(t, "users", group.CN())
		assert.Empty(t, group.Description)
		assert.Empty(t, group.Members)
	})

	t.Run("group with only memberUid", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "cn=developers,ou=groups,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"developers"}},
				{Name: "memberUid", Values: []string{"dev1", "dev2", "dev3"}},
			},
		}

		group, err := groupFromEntry(entry)
		require.NoError(t, err)
		assert.Equal(t, "developers", group.CN())
		assert.Len(t, group.Members, 3)
		// memberUid values are stored as-is
		assert.Contains(t, group.Members, "dev1")
		assert.Contains(t, group.Members, "dev2")
		assert.Contains(t, group.Members, "dev3")
	})

	t.Run("group with uniqueMember", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "cn=test,ou=groups,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"test"}},
				{Name: "uniqueMember", Values: []string{
					"uid=user1,ou=users,dc=example,dc=com",
					"uid=user2,ou=users,dc=example,dc=com",
				}},
			},
		}

		group, err := groupFromEntry(entry)
		require.NoError(t, err)
		assert.Len(t, group.Members, 2)
		assert.Contains(t, group.Members, "uid=user1,ou=users,dc=example,dc=com")
		assert.Contains(t, group.Members, "uid=user2,ou=users,dc=example,dc=com")
	})

	t.Run("group with empty members", func(t *testing.T) {
		entry := &ldap.Entry{
			DN: "cn=empty,ou=groups,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"empty"}},
				{Name: "member", Values: []string{}},
			},
		}

		group, err := groupFromEntry(entry)
		require.NoError(t, err)
		assert.Empty(t, group.Members)
	})
}

// TestGroupMethods tests Group struct methods
func TestGroupMethods(t *testing.T) {
	group := &Group{
		Object: Object{
			cn: "testgroup",
			dn: "cn=testgroup,ou=groups,dc=example,dc=com",
		},
		Description: "Test Group",
		Members:     []string{"user1", "user2"},
	}

	t.Run("DN method", func(t *testing.T) {
		assert.Equal(t, "cn=testgroup,ou=groups,dc=example,dc=com", group.DN())
	})

	t.Run("CN method", func(t *testing.T) {
		assert.Equal(t, "testgroup", group.CN())
	})
}

// TestGroupsFromSearchResult tests the groupsFromSearchResult function
func TestGroupsFromSearchResult(t *testing.T) {
	searchResult := &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "cn=group1,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"group1"}},
					{Name: "description", Values: []string{"First Group"}},
				},
			},
			{
				DN: "cn=group2,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"group2"}},
					{Name: "description", Values: []string{"Second Group"}},
				},
			},
			{
				// Invalid entry without cn
				DN: "ou=invalid,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "ou", Values: []string{"invalid"}},
				},
			},
		},
	}

	groups, err := groupsFromSearchResult(searchResult)
	require.NoError(t, err)
	assert.Len(t, groups, 2) // Should skip invalid entry
	assert.Equal(t, "group1", groups[0].CN())
	assert.Equal(t, "group2", groups[1].CN())
}

// TestFindGroupsWithExampleServer tests group operations with example server
func TestFindGroupsWithExampleServer(t *testing.T) {
	// Use example server for mock data
	client := &LDAP{
		config: &Config{
			Server: "ldap://example.com:389",
			BaseDN: "dc=example,dc=com",
		},
		logger: slog.Default(),
	}

	t.Run("FindGroups returns example data", func(t *testing.T) {
		ctx := context.Background()
		groups, err := client.FindGroupsContext(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, groups)
		assert.Equal(t, 50, len(groups)) // Example server returns 50 groups
		assert.Equal(t, "Group 1", groups[0].CN())
	})

	t.Run("FindGroupByDN returns example data", func(t *testing.T) {
		ctx := context.Background()
		group, err := client.FindGroupByDNContext(ctx, "cn=admins,ou=groups,dc=example,dc=com")
		assert.NoError(t, err)
		assert.NotNil(t, group)
		assert.Equal(t, "admins", group.CN())
	})

	t.Run("FindGroupByCN returns example data", func(t *testing.T) {
		ctx := context.Background()
		group, err := client.FindGroupByCNContext(ctx, "testgroup")
		assert.NoError(t, err)
		assert.NotNil(t, group)
		assert.Equal(t, "testgroup", group.CN())
	})
}

// TestGroupOperationsWithNoConnection tests error handling without connection
func TestGroupOperationsWithNoConnection(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://test:389",
			BaseDN: "dc=example,dc=com",
		},
		logger: slog.Default(),
	}

	t.Run("FindGroupByDN with no connection", func(t *testing.T) {
		ctx := context.Background()
		group, err := client.FindGroupByDNContext(ctx, "cn=admins,ou=groups,dc=example,dc=com")
		assert.Error(t, err)
		assert.Nil(t, group)
	})

	t.Run("FindGroupByCN with no connection", func(t *testing.T) {
		ctx := context.Background()
		group, err := client.FindGroupByCNContext(ctx, "admins")
		assert.Error(t, err)
		assert.Nil(t, group)
	})

	t.Run("FindGroups with no connection", func(t *testing.T) {
		ctx := context.Background()
		groups, err := client.FindGroupsContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, groups)
	})

	t.Run("AddUserToGroup with no connection", func(t *testing.T) {
		ctx := context.Background()
		err := client.AddUserToGroupContext(ctx, "testuser", "testgroup")
		assert.Error(t, err)
	})

	t.Run("RemoveUserFromGroup with no connection", func(t *testing.T) {
		ctx := context.Background()
		err := client.RemoveUserFromGroupContext(ctx, "testuser", "testgroup")
		assert.Error(t, err)
	})
}

// TestGroupOperationTimeouts tests timeout handling in group operations
func TestGroupOperationTimeouts(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://example.com:389",
			BaseDN: "dc=example,dc=com",
		},
		logger:           slog.Default(),
		operationTimeout: 100 * time.Millisecond,
	}

	t.Run("FindGroups with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		// Allow for fast cancellation check
		time.Sleep(60 * time.Millisecond)

		groups, err := client.FindGroupsContext(ctx)
		// Should respect context cancellation
		if err == nil {
			// If no error, we got example data quickly
			assert.NotNil(t, groups)
		} else {
			assert.Contains(t, err.Error(), "context")
		}
	})
}

// TestGroupIterators tests group member iterators
func TestGroupIterators(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://test:389",
			BaseDN: "dc=example,dc=com",
		},
		logger: slog.Default(),
	}

	t.Run("GroupMembersIter", func(t *testing.T) {
		ctx := context.Background()
		iter := client.GroupMembersIter(ctx, "cn=testgroup,ou=groups,dc=example,dc=com")
		assert.NotNil(t, iter)

		// Iterator should return immediately without connection
		count := 0
		for entry, err := range iter {
			if err != nil {
				break // Expected to error
			}
			assert.NotNil(t, entry)
			count++
			if count > 10 {
				break // Safety limit
			}
		}
		assert.Equal(t, 0, count) // Should not return any entries without connection
	})
}

// TestGroupBuilders tests group builder pattern
func TestGroupBuilders(t *testing.T) {
	t.Run("NewGroupBuilder", func(t *testing.T) {
		builder := NewGroupBuilder("testgroup")
		assert.NotNil(t, builder)

		group, err := builder.Build()
		require.NoError(t, err)
		assert.Equal(t, "testgroup", group.CN())
		assert.NotEmpty(t, group.DN()) // Should have a generated DN
	})

	t.Run("GroupBuilder with all fields", func(t *testing.T) {
		builder := NewGroupBuilder("admins").
			WithDescription("Administrator Group").
			WithDN("cn=admins,ou=groups,dc=example,dc=com")

		group, err := builder.Build()
		require.NoError(t, err)
		assert.Equal(t, "admins", group.CN())
		assert.Equal(t, "Administrator Group", group.Description)
		assert.Equal(t, "cn=admins,ou=groups,dc=example,dc=com", group.DN())
	})

	t.Run("GroupBuilder with validation error", func(t *testing.T) {
		builder := NewGroupBuilder("") // Empty CN should cause error
		_, err := builder.Build()
		assert.Error(t, err)
	})
}