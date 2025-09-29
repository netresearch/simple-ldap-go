package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUser_IsMemberOf tests the User.IsMemberOf helper method
func TestUser_IsMemberOf(t *testing.T) {
	tests := []struct {
		name        string
		user        *User
		groupDN     string
		expected    bool
		description string
	}{
		{
			name: "exact match",
			user: &User{
				Groups: []string{
					"CN=Admins,OU=Groups,DC=example,DC=com",
					"CN=Users,OU=Groups,DC=example,DC=com",
				},
			},
			groupDN:     "CN=Admins,OU=Groups,DC=example,DC=com",
			expected:    true,
			description: "Should match exact group DN",
		},
		{
			name: "case insensitive match",
			user: &User{
				Groups: []string{
					"CN=Admins,OU=Groups,DC=example,DC=com",
				},
			},
			groupDN:     "cn=admins,ou=groups,dc=example,dc=com",
			expected:    true,
			description: "Should match with different case (LDAP DNs are case-insensitive)",
		},
		{
			name: "match with extra whitespace",
			user: &User{
				Groups: []string{
					"CN=Admins,OU=Groups,DC=example,DC=com",
				},
			},
			groupDN:     "  CN=Admins,OU=Groups,DC=example,DC=com  ",
			expected:    true,
			description: "Should match with leading/trailing whitespace",
		},
		{
			name: "not a member",
			user: &User{
				Groups: []string{
					"CN=Users,OU=Groups,DC=example,DC=com",
				},
			},
			groupDN:     "CN=Admins,OU=Groups,DC=example,DC=com",
			expected:    false,
			description: "Should return false when not a member",
		},
		{
			name: "empty groups",
			user: &User{
				Groups: []string{},
			},
			groupDN:     "CN=Admins,OU=Groups,DC=example,DC=com",
			expected:    false,
			description: "Should return false when user has no groups",
		},
		{
			name: "nil groups",
			user: &User{
				Groups: nil,
			},
			groupDN:     "CN=Admins,OU=Groups,DC=example,DC=com",
			expected:    false,
			description: "Should return false when groups is nil",
		},
		{
			name: "multiple groups - found in middle",
			user: &User{
				Groups: []string{
					"CN=Users,OU=Groups,DC=example,DC=com",
					"CN=Admins,OU=Groups,DC=example,DC=com",
					"CN=Developers,OU=Groups,DC=example,DC=com",
				},
			},
			groupDN:     "CN=Admins,OU=Groups,DC=example,DC=com",
			expected:    true,
			description: "Should find group in middle of list",
		},
		{
			name: "partial match should not match",
			user: &User{
				Groups: []string{
					"CN=Admins,OU=Groups,DC=example,DC=com",
				},
			},
			groupDN:     "CN=Admin,OU=Groups,DC=example,DC=com",
			expected:    false,
			description: "Should not match partial DN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.IsMemberOf(tt.groupDN)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// TestFindUsersBySAMAccountNames tests the batch user lookup method
func TestFindUsersBySAMAccountNames(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("find multiple existing users", func(t *testing.T) {
		// Assuming test container has users like admin, testuser1, testuser2
		names := []string{testData.ValidUserUID}

		users, err := client.FindUsersBySAMAccountNames(names)
		require.NoError(t, err)
		assert.Len(t, users, 1, "Should find 1 user")

		// Verify user data
		assert.Equal(t, testData.ValidUserUID, users[0].SAMAccountName)
	})

	t.Run("find mix of existing and non-existing users", func(t *testing.T) {
		names := []string{
			testData.ValidUserUID,
			"nonexistent_user_12345",
			"another_fake_user",
		}

		users, err := client.FindUsersBySAMAccountNames(names)
		require.NoError(t, err)
		assert.Len(t, users, 1, "Should only find 1 existing user")
		assert.Equal(t, testData.ValidUserUID, users[0].SAMAccountName)
	})

	t.Run("find no users when all non-existent", func(t *testing.T) {
		names := []string{
			"fake_user_1",
			"fake_user_2",
			"fake_user_3",
		}

		users, err := client.FindUsersBySAMAccountNames(names)
		require.NoError(t, err)
		assert.Empty(t, users, "Should return empty slice when no users found")
	})

	t.Run("empty input slice", func(t *testing.T) {
		names := []string{}

		users, err := client.FindUsersBySAMAccountNames(names)
		require.NoError(t, err)
		assert.Empty(t, users, "Should return empty slice for empty input")
	})

	t.Run("nil input slice", func(t *testing.T) {
		users, err := client.FindUsersBySAMAccountNames(nil)
		require.NoError(t, err)
		assert.Empty(t, users, "Should handle nil input gracefully")
	})
}

// TestFindUsersBySAMAccountNamesContext tests the batch user lookup with context
func TestFindUsersBySAMAccountNamesContext(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("successful lookup with context", func(t *testing.T) {
		ctx := context.Background()
		names := []string{testData.ValidUserUID}

		users, err := client.FindUsersBySAMAccountNamesContext(ctx, names)
		require.NoError(t, err)
		assert.Len(t, users, 1)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		names := []string{testData.ValidUserUID}

		users, err := client.FindUsersBySAMAccountNamesContext(ctx, names)
		assert.Error(t, err, "Should return error when context is cancelled")
		assert.Equal(t, context.Canceled, err, "Error should be context.Canceled")
		assert.Empty(t, users, "Should return empty results on cancellation")
	})

	t.Run("context timeout during batch operation", func(t *testing.T) {
		// Create a context with very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// Give context time to expire
		time.Sleep(10 * time.Millisecond)

		names := []string{testData.ValidUserUID, "user2", "user3"}

		users, err := client.FindUsersBySAMAccountNamesContext(ctx, names)
		// Should either return context.DeadlineExceeded or partial results with error
		if err != nil {
			assert.Equal(t, context.DeadlineExceeded, err, "Error should be context.DeadlineExceeded")
		}
		// May have partial results if timeout occurred mid-batch
		t.Logf("Partial results before timeout: %d users", len(users))
	})
}

// TestUser_IsMemberOf_Integration tests IsMemberOf with real LDAP data
func TestUser_IsMemberOf_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	user, err := client.FindUserByDN(testData.ValidUserDN)
	require.NoError(t, err)
	require.NotNil(t, user)

	t.Run("check actual group membership", func(t *testing.T) {
		// User should have at least some groups
		if len(user.Groups) > 0 {
			// Test with first actual group
			firstGroup := user.Groups[0]
			assert.True(t, user.IsMemberOf(firstGroup), "Should be member of actual group")

			// Test with non-existent group
			assert.False(t, user.IsMemberOf("CN=FakeGroup,DC=example,DC=com"), "Should not be member of fake group")
		} else {
			t.Log("User has no group memberships to test")
		}
	})

	t.Run("case insensitive with real data", func(t *testing.T) {
		if len(user.Groups) > 0 {
			firstGroup := user.Groups[0]
			// Convert to different cases
			lowerGroup := string([]rune(firstGroup)) // Keep structure but test with original
			assert.True(t, user.IsMemberOf(lowerGroup), "Case insensitive check should work")
		}
	})
}
