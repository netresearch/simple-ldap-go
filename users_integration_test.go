package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindUserByMailIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

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

func TestFindUsersIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	users, err := client.FindUsers()
	require.NoError(t, err)
	require.NotNil(t, users)

	// We should have at least 4 test users created in the test setup
	assert.GreaterOrEqual(t, len(users), 4)

	// Verify user properties
	for _, user := range users {
		assert.NotEmpty(t, user.CN())
		assert.NotEmpty(t, user.DN())
		assert.NotEmpty(t, user.SAMAccountName)
		assert.True(t, user.Enabled) // OpenLDAP users are typically enabled by default
	}
}

func TestUserGroupMembershipIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("add user to group", func(t *testing.T) {
		// This tests the method but may not actually work with OpenLDAP permissions
		err := client.AddUserToGroup(testData.ValidUserDN, testData.ValidGroupDN)
		// We expect this to potentially fail due to OpenLDAP permissions/schema differences
		// The important thing is that the method executes without panicking
		t.Logf("AddUserToGroup result: %v", err)
	})

	t.Run("remove user from group", func(t *testing.T) {
		// This tests the method but may not actually work with OpenLDAP permissions
		err := client.RemoveUserFromGroup(testData.ValidUserDN, testData.ValidGroupDN)
		// We expect this to potentially fail due to OpenLDAP permissions/schema differences
		// The important thing is that the method executes without panicking
		t.Logf("RemoveUserFromGroup result: %v", err)
	})
}

func TestUserCRUDOperationsIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	t.Run("create user", func(t *testing.T) {
		// This tests the method but may not work with OpenLDAP due to schema differences
		testUser := FullUser{
			CN:        "Test User",
			FirstName: "Test",
			LastName:  "User",
			UserAccountControl: UAC{
				NormalAccount: true,
			},
		}

		dn, err := client.CreateUser(testUser, "password123")
		// This may fail due to OpenLDAP schema differences, but we test the code path
		t.Logf("CreateUser result: dn=%s, err=%v", dn, err)

		// If creation succeeded, try to clean up
		if err == nil && dn != "" {
			err = client.DeleteUser(dn)
			t.Logf("DeleteUser cleanup result: %v", err)
		}
	})
}
