package objects

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindGroupByDN(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	tests := []struct {
		name          string
		dn            string
		expectError   bool
		expectedError error
		validateGroup func(*testing.T, *Group)
	}{
		{
			name:        "valid group DN",
			dn:          testData.ValidGroupDN,
			expectError: false,
			validateGroup: func(t *testing.T, group *Group) {
				assert.Equal(t, testData.ValidGroupCN, group.CN())
				assert.Equal(t, strings.ToLower(testData.ValidGroupDN), strings.ToLower(group.DN()))
				// Should have members (we added users to admin group during setup)
				assert.NotNil(t, group.Members)
			},
		},
		{
			name:          "nonexistent group DN",
			dn:            "cn=nonexistent,ou=groups,dc=example,dc=org",
			expectError:   true,
			expectedError: ErrGroupNotFound,
		},
		{
			name:        "malformed DN",
			dn:          "invalid-dn",
			expectError: true,
		},
		{
			name:        "empty DN",
			dn:          "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group, err := client.FindGroupByDN(tt.dn)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, group)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, group)
				assert.Equal(t, strings.ToLower(tt.dn), strings.ToLower(group.DN()))

				if tt.validateGroup != nil {
					tt.validateGroup(t, group)
				}
			}
		})
	}
}

func TestFindGroups(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	groups, err := client.FindGroups()
	require.NoError(t, err)
	require.NotNil(t, groups)

	// Should find at least the test groups we created
	assert.GreaterOrEqual(t, len(groups), 3)

	// Validate that all groups have required fields
	for _, group := range groups {
		assert.NotEmpty(t, group.CN())
		assert.NotEmpty(t, group.DN())
		assert.NotNil(t, group.Members) // Can be empty slice, but not nil
	}

	// Find specific test groups
	groupNames := make(map[string]bool)
	for _, group := range groups {
		groupNames[strings.ToLower(group.CN())] = true
	}

	expectedGroups := []string{"admins", "users", "developers"}
	for _, expectedGroup := range expectedGroups {
		assert.True(t, groupNames[expectedGroup], "Should find group: %s", expectedGroup)
	}
}

func TestGroupStructValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	group, err := client.FindGroupByDN(testData.ValidGroupDN)
	require.NoError(t, err)
	require.NotNil(t, group)

	// Test Group struct methods and fields
	t.Run("DN method", func(t *testing.T) {
		dn := group.DN()
		assert.NotEmpty(t, dn)
		assert.Contains(t, strings.ToLower(dn), "cn="+strings.ToLower(testData.ValidGroupCN))
	})

	t.Run("CN method", func(t *testing.T) {
		cn := group.CN()
		assert.NotEmpty(t, cn)
		assert.Equal(t, testData.ValidGroupCN, cn)
	})

	t.Run("Members field", func(t *testing.T) {
		assert.NotNil(t, group.Members)
		// Members could be empty or contain member DNs
		if len(group.Members) > 0 {
			for _, member := range group.Members {
				assert.NotEmpty(t, member)
				// Member DNs should be valid LDAP DNs
				assert.Contains(t, member, "=")
			}
		}
	})
}

func TestGroupMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	// Test examining group membership
	t.Run("admin group membership", func(t *testing.T) {
		adminGroup, err := client.FindGroupByDN(fmt.Sprintf("cn=admins,%s", tc.GroupsOU))
		require.NoError(t, err)
		require.NotNil(t, adminGroup)

		assert.Equal(t, "admins", adminGroup.CN())
		assert.NotNil(t, adminGroup.Members)

		// Verify that members are valid DNs
		for _, member := range adminGroup.Members {
			assert.Contains(t, member, "uid=")
			assert.Contains(t, member, "ou=people")
		}
	})

	t.Run("users group membership", func(t *testing.T) {
		usersGroup, err := client.FindGroupByDN(fmt.Sprintf("cn=users,%s", tc.GroupsOU))
		require.NoError(t, err)
		require.NotNil(t, usersGroup)

		assert.Equal(t, "users", usersGroup.CN())
		assert.NotNil(t, usersGroup.Members)
	})

	t.Run("developers group membership", func(t *testing.T) {
		developersGroup, err := client.FindGroupByDN(fmt.Sprintf("cn=developers,%s", tc.GroupsOU))
		require.NoError(t, err)
		require.NotNil(t, developersGroup)

		assert.Equal(t, "developers", developersGroup.CN())
		assert.NotNil(t, developersGroup.Members)
	})
}

func TestGroupSearchByAttribute(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	// Test finding groups with specific attributes
	t.Run("find all groups with members", func(t *testing.T) {
		groups, err := client.FindGroups()
		require.NoError(t, err)

		groupsWithMembers := 0
		for _, group := range groups {
			if len(group.Members) > 0 {
				groupsWithMembers++
			}
		}

		// At least some of our test groups should have members
		assert.Greater(t, groupsWithMembers, 0)
	})

	t.Run("validate group DN format", func(t *testing.T) {
		groups, err := client.FindGroups()
		require.NoError(t, err)

		for _, group := range groups {
			dn := group.DN()
			assert.Contains(t, strings.ToLower(dn), "cn=")
			assert.Contains(t, strings.ToLower(dn), "ou=groups")
			assert.Contains(t, strings.ToLower(dn), "dc=example,dc=org")
		}
	})
}

func TestGroupErrorConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	t.Run("search with special characters", func(t *testing.T) {
		// Test DN with characters that need escaping
		_, err := client.FindGroupByDN("cn=group(with)parens,ou=groups,dc=example,dc=org")
		assert.Error(t, err) // Should be group not found
		assert.Equal(t, ErrGroupNotFound, err)
	})

	t.Run("very long DN", func(t *testing.T) {
		longDN := "cn=" + strings.Repeat("a", 1000) + ",ou=groups,dc=example,dc=org"
		_, err := client.FindGroupByDN(longDN)
		assert.Error(t, err)
	})

	t.Run("DN pointing to non-group object", func(t *testing.T) {
		// Try to find a user DN as if it's a group
		testData := tc.GetTestData()
		_, err := client.FindGroupByDN(testData.ValidUserDN)
		assert.Error(t, err)
		assert.Equal(t, ErrGroupNotFound, err)
	})
}

func TestGroupObjectAttributes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	// Test the internal Object struct functionality through groups
	t.Run("object inheritance", func(t *testing.T) {
		testData := tc.GetTestData()
		group, err := client.FindGroupByDN(testData.ValidGroupDN)
		require.NoError(t, err)
		require.NotNil(t, group)

		// Group embeds Object, so it should have DN() and CN() methods
		assert.Implements(t, (*interface{ DN() string })(nil), group)
		assert.Implements(t, (*interface{ CN() string })(nil), group)
	})
}

func TestGroupSearchScopes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	t.Run("search from base DN", func(t *testing.T) {
		// FindGroups searches from BaseDN with subtree scope
		groups, err := client.FindGroups()
		require.NoError(t, err)

		// Should find groups in ou=groups,dc=example,dc=org
		foundGroupsOU := false
		for _, group := range groups {
			if strings.Contains(strings.ToLower(group.DN()), "ou=groups") {
				foundGroupsOU = true
				break
			}
		}
		assert.True(t, foundGroupsOU, "Should find groups in groups OU")
	})

	t.Run("search specific DN with base scope", func(t *testing.T) {
		// FindGroupByDN searches specific DN with base scope
		testData := tc.GetTestData()
		group, err := client.FindGroupByDN(testData.ValidGroupDN)
		require.NoError(t, err)

		// Should return exactly the requested group
		assert.Equal(t, strings.ToLower(testData.ValidGroupDN), strings.ToLower(group.DN()))
	})
}

func TestErrGroupNotFound(t *testing.T) {
	assert.Equal(t, "group not found", ErrGroupNotFound.Error())
}

func TestGroupIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	// Test the complete group workflow
	t.Run("complete group lookup workflow", func(t *testing.T) {
		// Step 1: List all groups
		allGroups, err := client.FindGroups()
		require.NoError(t, err)
		require.NotEmpty(t, allGroups)

		// Step 2: Find a specific group by DN
		firstGroup := allGroups[0]
		foundGroup, err := client.FindGroupByDN(firstGroup.DN())
		require.NoError(t, err)

		// Step 3: Verify they're the same
		assert.Equal(t, firstGroup.DN(), foundGroup.DN())
		assert.Equal(t, firstGroup.CN(), foundGroup.CN())
		assert.Equal(t, len(firstGroup.Members), len(foundGroup.Members))

		// Step 4: Examine group members
		if len(foundGroup.Members) > 0 {
			for _, member := range foundGroup.Members {
				// Verify member DN format
				assert.Contains(t, member, "=")
				assert.Contains(t, strings.ToLower(member), "dc=example,dc=org")
			}
		}
	})
}

func TestGroupCaseSensitivity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	t.Run("DN case sensitivity", func(t *testing.T) {
		testData := tc.GetTestData()

		// Original DN
		group1, err := client.FindGroupByDN(testData.ValidGroupDN)
		require.NoError(t, err)

		// Uppercase DN (might work depending on LDAP server config)
		upperDN := strings.ToUpper(testData.ValidGroupDN)
		group2, err := client.FindGroupByDN(upperDN)

		if err == nil {
			// If both succeed, they should be the same group
			assert.Equal(t, strings.ToLower(group1.DN()), strings.ToLower(group2.DN()))
			assert.Equal(t, group1.CN(), group2.CN())
		} else {
			// Case sensitivity varies by LDAP server implementation
			assert.Error(t, err)
		}
	})
}

// Benchmark tests
func BenchmarkFindGroupByDN(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})
	testData := tc.GetTestData()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.FindGroupByDN(testData.ValidGroupDN)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFindGroups(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.FindGroups()
		if err != nil {
			b.Fatal(err)
		}
	}
}
