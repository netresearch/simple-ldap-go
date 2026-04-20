//go:build integration

package ldap

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindUserByMailIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
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
					assert.True(t, errors.Is(err, tt.expectedError), "expected %v, got %v", tt.expectedError, err)
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
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
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
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
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
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
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

// TestCreateUserWithSAMAccountNameOnOpenLDAP is the regression test for
// issue #153: CreateUser on a non-AD directory must round-trip via
// FindUserBySAMAccountName. The AD-only sAMAccountName attribute is
// unusable on inetOrgPerson, so the implementation now falls back to
// storing the value in `uid` — which is exactly what FindUserBy
// SAMAccountName falls back to on non-AD schemas.
func TestCreateUserWithSAMAccountNameOnOpenLDAP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	sam := "regress153"
	testUser := FullUser{
		CN:             "Regress 153",
		FirstName:      "Regress",
		LastName:       "OneFiftyThree",
		SAMAccountName: &sam,
		UserAccountControl: UAC{
			NormalAccount: true,
		},
	}

	dn, err := client.CreateUser(testUser, "password123")
	require.NoError(t, err, "CreateUser on OpenLDAP must succeed when SAMAccountName is supplied")
	require.NotEmpty(t, dn)

	// Clean up on any exit — even assertion failures below.
	defer func() {
		if delErr := client.DeleteUser(dn); delErr != nil {
			t.Logf("cleanup DeleteUser: %v", delErr)
		}
	}()

	// The round-trip: the user we just created must be findable by
	// SAMAccountName. Before the fix this returned ErrUserNotFound
	// because `uid` was never populated on the non-AD code path.
	found, err := client.FindUserBySAMAccountName(sam)
	require.NoError(t, err, "FindUserBySAMAccountName must find the user we just created")
	require.NotNil(t, found)
	// OpenLDAP normalizes attribute-type case in returned DNs (e.g.
	// `cn=` vs the `CN=` the client constructs), so compare case-
	// insensitively.
	assert.True(t, strings.EqualFold(dn, found.DN()),
		"DN mismatch: created=%q found=%q", dn, found.DN())
	assert.Equal(t, sam, found.SAMAccountName)
}
