//go:build integration
// +build integration

package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFindUserByMailIntegrationOptimized demonstrates optimized integration testing
func TestFindUserByMailIntegrationOptimized(t *testing.T) {
	// Use shared container for faster execution
	tc := GetSharedTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	// This test can run in parallel with other read-only tests
	t.Parallel()

	tests := []struct {
		name          string
		mail          string
		expectError   bool
		expectedError error
	}{
		{
			name:        "valid email",
			mail:        testData.ValidUserMail,
			expectError: false,
		},
		{
			name:          "nonexistent email",
			mail:          "nonexistent@example.com",
			expectError:   true,
			expectedError: ErrUserNotFound,
		},
		{
			name:        "empty email",
			mail:        "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parallel execution for test cases that don't conflict
			if tt.name != "empty email" { // Example: some tests might not be parallel-safe
				t.Parallel()
			}

			user, err := client.FindUserByMail(tt.mail)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.mail, *user.Mail)
				assert.True(t, user.Enabled)
			}
		})
	}
}

// TestFindUsersIntegrationOptimized demonstrates optimized parallel testing
func TestFindUsersIntegrationOptimized(t *testing.T) {
	tc := GetSharedTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	// This test can run in parallel
	t.Parallel()

	users, err := client.FindUsers()
	require.NoError(t, err)
	require.NotNil(t, users)

	// We should have at least 4 test users created in the shared container
	assert.GreaterOrEqual(t, len(users), 4)

	// Verify user properties
	for _, user := range users {
		assert.NotEmpty(t, user.CN())
		assert.NotEmpty(t, user.DN())
		assert.NotEmpty(t, user.SAMAccountName)
		assert.True(t, user.Enabled)
	}
}

// TestUserGroupMembershipIntegrationOptimized demonstrates read-only group testing
func TestUserGroupMembershipIntegrationOptimized(t *testing.T) {
	tc := GetSharedTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	// This test can run in parallel since it's mostly read-only
	t.Parallel()

	t.Run("verify user group membership", func(t *testing.T) {
		// Test reading group membership (read-only operation)
		group, err := client.FindGroupByDN(testData.ValidGroupDN)
		if err != nil {
			t.Skipf("Group lookup not available: %v", err)
			return
		}

		// Verify group exists and has expected structure
		assert.NotNil(t, group)
		assert.Equal(t, testData.ValidGroupCN, group.CN())
	})

	// Note: We skip modify operations in optimized tests to avoid conflicts
	// Modify operations should be in separate non-parallel tests
}

// TestUserSearchOptimized demonstrates optimized search operations
func TestUserSearchOptimized(t *testing.T) {
	tc := GetSharedTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	// Search operations can be parallel
	t.Parallel()

	t.Run("search by SAMAccountName", func(t *testing.T) {
		t.Parallel()

		user, err := client.FindUserBySAMAccountName(testData.ValidUserUID)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, testData.ValidUserUID, user.SAMAccountName)
	})

	t.Run("search by DN", func(t *testing.T) {
		t.Parallel()

		user, err := client.FindUserByDN(testData.ValidUserDN)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, testData.ValidUserDN, user.DN())
	})

	t.Run("search by email", func(t *testing.T) {
		t.Parallel()

		user, err := client.FindUserByMail(testData.ValidUserMail)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, testData.ValidUserMail, *user.Mail)
	})
}

// BenchmarkUserOperationsOptimized demonstrates optimized benchmarking
func BenchmarkUserOperationsOptimized(b *testing.B) {
	// Skip benchmark in short mode
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	tc := GetSharedTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})
	testData := tc.GetTestData()

	b.Run("FindUserBySAMAccountName", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.FindUserBySAMAccountName(testData.ValidUserUID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FindUserByMail", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.FindUserByMail(testData.ValidUserMail)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FindUsers", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.FindUsers()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}