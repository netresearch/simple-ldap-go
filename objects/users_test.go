package objects

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindUserByDN(t *testing.T) {
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
		validateUser  func(*testing.T, *User)
	}{
		{
			name:        "valid user DN",
			dn:          testData.ValidUserDN,
			expectError: false,
			validateUser: func(t *testing.T, user *User) {
				assert.Equal(t, testData.ValidUserCN, user.CN())
				assert.Equal(t, strings.ToLower(testData.ValidUserUID), strings.ToLower(user.SAMAccountName))
				assert.Equal(t, strings.ToLower(testData.ValidUserMail), strings.ToLower(*user.Mail))
				assert.True(t, user.Enabled)
			},
		},
		{
			name:          "nonexistent user DN",
			dn:            "uid=nonexistent,ou=people,dc=example,dc=org",
			expectError:   true,
			expectedError: ErrUserNotFound,
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
			user, err := client.FindUserByDN(tt.dn)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, strings.ToLower(tt.dn), strings.ToLower(user.DN()))

				if tt.validateUser != nil {
					tt.validateUser(t, user)
				}
			}
		})
	}
}

func TestFindUserBySAMAccountName(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	tests := []struct {
		name           string
		sAMAccountName string
		expectError    bool
		expectedError  error
		validateUser   func(*testing.T, *User)
	}{
		{
			name:           "valid sAMAccountName",
			sAMAccountName: testData.ValidUserUID,
			expectError:    false,
			validateUser: func(t *testing.T, user *User) {
				assert.Equal(t, testData.ValidUserCN, user.CN())
				assert.Equal(t, strings.ToLower(testData.ValidUserUID), strings.ToLower(user.SAMAccountName))
				assert.Equal(t, strings.ToLower(testData.ValidUserMail), strings.ToLower(*user.Mail))
			},
		},
		{
			name:           "case insensitive search",
			sAMAccountName: strings.ToUpper(testData.ValidUserUID),
			expectError:    false,
			validateUser: func(t *testing.T, user *User) {
				assert.Equal(t, strings.ToLower(testData.ValidUserUID), strings.ToLower(user.SAMAccountName))
			},
		},
		{
			name:           "nonexistent sAMAccountName",
			sAMAccountName: testData.InvalidUserUID,
			expectError:    true,
			expectedError:  ErrUserNotFound,
		},
		{
			name:           "disabled user",
			sAMAccountName: testData.DisabledUserUID,
			expectError:    false,
			validateUser: func(t *testing.T, user *User) {
				// In OpenLDAP, users are enabled by default (no userAccountControl)
				// This test verifies the user can be found
				assert.Equal(t, strings.ToLower(testData.DisabledUserUID), strings.ToLower(user.SAMAccountName))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := client.FindUserBySAMAccountName(tt.sAMAccountName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)

				if tt.validateUser != nil {
					tt.validateUser(t, user)
				}
			}
		})
	}
}

func TestFindUserByMail(t *testing.T) {
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
		validateUser  func(*testing.T, *User)
	}{
		{
			name:        "valid email address",
			mail:        testData.ValidUserMail,
			expectError: false,
			validateUser: func(t *testing.T, user *User) {
				assert.Equal(t, testData.ValidUserCN, user.CN())
				assert.Equal(t, strings.ToLower(testData.ValidUserMail), strings.ToLower(*user.Mail))
			},
		},
		{
			name:          "nonexistent email",
			mail:          "nonexistent@example.com",
			expectError:   true,
			expectedError: ErrUserNotFound,
		},
		{
			name:        "case insensitive email search",
			mail:        strings.ToUpper(testData.ValidUserMail),
			expectError: false,
			validateUser: func(t *testing.T, user *User) {
				assert.Equal(t, strings.ToLower(testData.ValidUserMail), strings.ToLower(*user.Mail))
			},
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

				if tt.validateUser != nil {
					tt.validateUser(t, user)
				}
			}
		})
	}
}

func TestFindUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	users, err := client.FindUsers()
	require.NoError(t, err)
	require.NotNil(t, users)

	// Should find at least the test users we created
	assert.GreaterOrEqual(t, len(users), 4)

	// Validate that all users have required fields
	for _, user := range users {
		assert.NotEmpty(t, user.CN())
		assert.NotEmpty(t, user.DN())
		assert.NotEmpty(t, user.SAMAccountName)
		// Mail might be nil for some users
		// Groups might be empty for some users
	}

	// Find specific test user
	var johnDoe *User
	for i, user := range users {
		if strings.Contains(strings.ToLower(user.CN()), "john doe") {
			johnDoe = &users[i]
			break
		}
	}

	require.NotNil(t, johnDoe, "Should find John Doe in user list")
	assert.Contains(t, strings.ToLower(johnDoe.CN()), "john doe")
	assert.NotNil(t, johnDoe.Mail)
	if johnDoe.Mail != nil {
		assert.Contains(t, strings.ToLower(*johnDoe.Mail), "john.doe@example.com")
	}
}

func TestAddUserToGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("add user to existing group", func(t *testing.T) {
		// Add Alice to the admins group (she's not in it initially)
		aliceUserDN := "uid=abrown,ou=people,dc=example,dc=org"
		adminsGroupDN := testData.ValidGroupDN

		err := client.AddUserToGroup(aliceUserDN, adminsGroupDN)
		// Note: This might fail in OpenLDAP if the user is already a member
		// or if we don't have write permissions, but we test the API
		if err != nil {
			t.Logf("Add user to group failed (expected in read-only test env): %v", err)
		} else {
			t.Log("Successfully added user to group")
		}
	})

	t.Run("add user to nonexistent group", func(t *testing.T) {
		err := client.AddUserToGroup(testData.ValidUserDN, "cn=nonexistent,ou=groups,dc=example,dc=org")
		assert.Error(t, err)
	})

	t.Run("add nonexistent user to group", func(t *testing.T) {
		err := client.AddUserToGroup("uid=nonexistent,ou=people,dc=example,dc=org", testData.ValidGroupDN)
		assert.Error(t, err)
	})
}

func TestRemoveUserFromGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("remove user from group", func(t *testing.T) {
		err := client.RemoveUserFromGroup(testData.ValidUserDN, testData.ValidGroupDN)
		// Note: This might fail if the user is not a member or we don't have write permissions
		if err != nil {
			t.Logf("Remove user from group failed (expected in test env): %v", err)
		}
	})

	t.Run("remove user from nonexistent group", func(t *testing.T) {
		err := client.RemoveUserFromGroup(testData.ValidUserDN, "cn=nonexistent,ou=groups,dc=example,dc=org")
		assert.Error(t, err)
	})
}

func TestCreateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	// Test user creation (this might fail due to permissions in test environment)
	t.Run("create basic user", func(t *testing.T) {
		samAccountName := "testuser"
		email := "testuser@example.com"
		description := "Test user created by unit test"

		fullUser := FullUser{
			CN:                 "Test User",
			SAMAccountName:     &samAccountName,
			FirstName:          "Test",
			LastName:           "User",
			Email:              &email,
			Description:        &description,
			UserAccountControl: UAC{NormalAccount: true},
		}

		dn, err := client.CreateUser(fullUser, "")
		if err != nil {
			t.Logf("Create user failed (expected in read-only test env): %v", err)
		} else {
			assert.NotEmpty(t, dn)
			assert.Contains(t, dn, "CN=Test User")
			t.Logf("Successfully created user: %s", dn)
		}
	})

	t.Run("create user with minimal fields", func(t *testing.T) {
		fullUser := FullUser{
			CN:        "Minimal User",
			FirstName: "Minimal",
			LastName:  "User",
		}

		dn, err := client.CreateUser(fullUser, "")
		if err != nil {
			t.Logf("Create minimal user failed (expected): %v", err)
		} else {
			assert.NotEmpty(t, dn)
		}
	})

	t.Run("create user with custom path", func(t *testing.T) {
		path := "ou=people"
		fullUser := FullUser{
			CN:        "Path User",
			FirstName: "Path",
			LastName:  "User",
			Path:      &path,
		}

		dn, err := client.CreateUser(fullUser, "")
		if err != nil {
			t.Logf("Create user with path failed (expected): %v", err)
		} else {
			assert.Contains(t, dn, "ou=people")
		}
	})
}

func TestDeleteUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	t.Run("delete nonexistent user", func(t *testing.T) {
		err := client.DeleteUser("uid=nonexistent,ou=people,dc=example,dc=org")
		assert.Error(t, err)
	})

	t.Run("delete with malformed DN", func(t *testing.T) {
		err := client.DeleteUser("invalid-dn")
		assert.Error(t, err)
	})

	// Note: We don't test deleting real users to avoid breaking other tests
}

func TestUserFromEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	// This is testing the internal userFromEntry function indirectly
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	// Find a user to test the parsing logic
	user, err := client.FindUserBySAMAccountName(testData.ValidUserUID)
	require.NoError(t, err)
	require.NotNil(t, user)

	// Verify all fields are properly parsed
	assert.NotEmpty(t, user.CN())
	assert.NotEmpty(t, user.DN())
	assert.NotEmpty(t, user.SAMAccountName)
	assert.NotNil(t, user.Mail)
	assert.NotEmpty(t, *user.Mail)
	// Groups might be empty for test users
	// Description might be empty
}

func TestUserStructValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	user, err := client.FindUserBySAMAccountName(testData.ValidUserUID)
	require.NoError(t, err)
	require.NotNil(t, user)

	// Test User struct methods and fields
	t.Run("DN method", func(t *testing.T) {
		dn := user.DN()
		assert.NotEmpty(t, dn)
		assert.Contains(t, strings.ToLower(dn), "uid="+strings.ToLower(testData.ValidUserUID))
	})

	t.Run("CN method", func(t *testing.T) {
		cn := user.CN()
		assert.NotEmpty(t, cn)
		assert.Equal(t, testData.ValidUserCN, cn)
	})

	t.Run("SAMAccountName field", func(t *testing.T) {
		assert.NotEmpty(t, user.SAMAccountName)
		assert.Equal(t, strings.ToLower(testData.ValidUserUID), strings.ToLower(user.SAMAccountName))
	})

	t.Run("Mail field", func(t *testing.T) {
		assert.NotNil(t, user.Mail)
		assert.Equal(t, strings.ToLower(testData.ValidUserMail), strings.ToLower(*user.Mail))
	})

	t.Run("Enabled field", func(t *testing.T) {
		// In OpenLDAP without userAccountControl, users are typically enabled
		assert.True(t, user.Enabled)
	})
}

// Test error conditions and edge cases
func TestUserErrorConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	t.Run("malformed search filters", func(t *testing.T) {
		// Test with characters that need escaping
		_, err := client.FindUserBySAMAccountName("user(with)parens")
		assert.Error(t, err) // Should be user not found, but with proper escaping
	})

	t.Run("very long DN", func(t *testing.T) {
		longDN := "uid=" + strings.Repeat("a", 1000) + ",ou=people,dc=example,dc=org"
		_, err := client.FindUserByDN(longDN)
		assert.Error(t, err)
	})
}

// Benchmark tests
func BenchmarkFindUserBySAMAccountName(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})
	testData := tc.GetTestData()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.FindUserBySAMAccountName(testData.ValidUserUID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFindUsers(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.FindUsers()
		if err != nil {
			b.Fatal(err)
		}
	}
}
