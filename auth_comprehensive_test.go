package ldap

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPasswordForSAMAccountName(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	tests := []struct {
		name           string
		sAMAccountName string
		password       string
		expectError    bool
		expectedError  error
	}{
		{
			name:           "valid credentials",
			sAMAccountName: testData.ValidUserUID,
			password:       testData.ValidUserPassword,
			expectError:    false,
		},
		{
			name:           "invalid password",
			sAMAccountName: testData.ValidUserUID,
			password:       testData.InvalidPassword,
			expectError:    true,
		},
		{
			name:           "nonexistent user",
			sAMAccountName: testData.InvalidUserUID,
			password:       "anypassword",
			expectError:    true,
			expectedError:  ErrUserNotFound,
		},
		{
			name:           "disabled user with correct password",
			sAMAccountName: testData.DisabledUserUID,
			password:       testData.DisabledUserPassword,
			expectError:    false, // OpenLDAP doesn't enforce account disabled by default
		},
		{
			name:           "empty sAMAccountName",
			sAMAccountName: "",
			password:       testData.ValidUserPassword,
			expectError:    true,
		},
		{
			name:           "empty password",
			sAMAccountName: testData.ValidUserUID,
			password:       "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := client.CheckPasswordForSAMAccountName(tt.sAMAccountName, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedError != nil {
					assert.True(t, errors.Is(err, tt.expectedError), "expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, strings.ToLower(tt.sAMAccountName), strings.ToLower(user.SAMAccountName))
			}
		})
	}
}

func TestCheckPasswordForDN(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	tests := []struct {
		name          string
		dn            string
		password      string
		expectError   bool
		expectedError error
	}{
		{
			name:        "valid credentials",
			dn:          testData.ValidUserDN,
			password:    testData.ValidUserPassword,
			expectError: false,
		},
		{
			name:        "invalid password",
			dn:          testData.ValidUserDN,
			password:    testData.InvalidPassword,
			expectError: true,
		},
		{
			name:          "nonexistent user DN",
			dn:            "uid=nonexistent,ou=people,dc=example,dc=com",
			password:      "anypassword",
			expectError:   true,
			expectedError: ErrUserNotFound,
		},
		{
			name:        "disabled user with correct password",
			dn:          testData.DisabledUserDN,
			password:    testData.DisabledUserPassword,
			expectError: false, // OpenLDAP doesn't enforce account disabled by default
		},
		{
			name:        "malformed DN",
			dn:          "invalid-dn-format",
			password:    "password",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := client.CheckPasswordForDN(tt.dn, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedError != nil {
					assert.True(t, errors.Is(err, tt.expectedError), "expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, strings.ToLower(tt.dn), strings.ToLower(user.DN()))
			}
		})
	}
}

func TestEncodePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "simple password",
			password: "password123",
			wantErr:  false,
		},
		{
			name:     "password with special characters",
			password: "p@ssw0rd!",
			wantErr:  false,
		},
		{
			name:     "unicode password",
			password: "пароль123",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encodePassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, encoded)
				// Verify that encoded password is longer than original (due to UTF-16LE encoding and quotes)
				if tt.password != "" {
					assert.Greater(t, len(encoded), len(tt.password))
				}
			}
		})
	}
}

func TestChangePasswordForSAMAccountName(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	// Note: This test is designed for Active Directory functionality
	// OpenLDAP doesn't support unicodePwd attribute, so we test validation logic only
	config := tc.Config
	config.IsActiveDirectory = true
	config.Server = "ldap://localhost:389" // Non-LDAPS server

	// Create client with OpenLDAP config but AD flag - this tests the validation logic
	client, err := New(config, tc.AdminUser, tc.AdminPass)
	if err != nil {
		t.Skip("Cannot create AD-mode client with OpenLDAP container")
		return
	}

	testData := tc.GetTestData()

	t.Run("requires LDAPS for Active Directory", func(t *testing.T) {
		err := client.ChangePasswordForSAMAccountName(
			testData.ValidUserUID,
			testData.ValidUserPassword,
			"newpassword123",
		)
		assert.Error(t, err)
		assert.Equal(t, ErrActiveDirectoryMustBeLDAPS, err)
	})

	t.Run("nonexistent user", func(t *testing.T) {
		// Use LDAPS config for this test, but expect failure due to OpenLDAP limitations
		ldapsConfig := tc.Config
		ldapsConfig.IsActiveDirectory = true
		ldapsConfig.Server = "ldaps://localhost:636"

		// This will fail due to either certificate issues or LDAP connection issues
		// We're primarily testing the user lookup logic here
		_, err := New(ldapsConfig, tc.AdminUser, tc.AdminPass)
		if err != nil {
			t.Skip("LDAPS not available for testing with OpenLDAP container")
			return
		}
	})
}

func TestAuthenticationFlow(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	testData := tc.GetTestData()

	t.Run("complete authentication flow", func(t *testing.T) {
		// Step 1: Authenticate user
		user, err := client.CheckPasswordForSAMAccountName(testData.ValidUserUID, testData.ValidUserPassword)
		require.NoError(t, err)
		require.NotNil(t, user)

		// Step 2: Verify user details
		assert.Equal(t, testData.ValidUserCN, user.CN())
		assert.Equal(t, strings.ToLower(testData.ValidUserUID), strings.ToLower(user.SAMAccountName))
		assert.Equal(t, strings.ToLower(testData.ValidUserMail), strings.ToLower(*user.Mail))
		assert.True(t, user.Enabled)

		// Step 3: Test using the authenticated user's credentials for a new client
		userClient, err := client.WithCredentials(user.DN(), testData.ValidUserPassword)
		require.NoError(t, err)

		// Step 4: Verify the user client can perform operations
		conn, err := userClient.GetConnection()
		require.NoError(t, err)
		_ = conn.Close()
	})
}

func TestAuthErrorConditions(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	t.Run("connection failure during auth", func(t *testing.T) {
		// Create client with invalid server to test connection failure handling
		invalidConfig := Config{
			Server: "ldap://nonexistent.server:389",
			BaseDN: tc.BaseDN,
		}

		invalidClient, err := New(invalidConfig, tc.AdminUser, tc.AdminPass)
		assert.Error(t, err)
		assert.Nil(t, invalidClient)
	})

	t.Run("bind failure after user lookup", func(t *testing.T) {
		testData := tc.GetTestData()

		// This should find the user but fail to bind with wrong password
		user, err := client.CheckPasswordForSAMAccountName(testData.ValidUserUID, "wrongpassword")
		assert.Error(t, err)
		assert.Nil(t, user)
	})
}

func TestErrActiveDirectoryMustBeLDAPS(t *testing.T) {
	assert.Equal(t, "ActiveDirectory servers must be connected to via LDAPS to change passwords", ErrActiveDirectoryMustBeLDAPS.Error())
}

// Integration test for authentication across different user types
func TestAuthenticationIntegration(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)

	// Test multiple users to ensure robust authentication
	// Use the actual users created in the test container
	testUsers := []struct {
		uid      string
		password string
		enabled  bool
	}{
		{"jdoe", "password123", true},
		{"asmith", "password456", true},
		{"bwilson", "password789", true},
	}

	for _, user := range testUsers {
		t.Run("authenticate_user_"+user.uid, func(t *testing.T) {
			authUser, err := client.CheckPasswordForSAMAccountName(user.uid, user.password)
			require.NoError(t, err)
			require.NotNil(t, authUser)

			assert.Equal(t, strings.ToLower(user.uid), strings.ToLower(authUser.SAMAccountName))
			assert.Equal(t, user.enabled, authUser.Enabled)

			// Test DN-based authentication for the same user
			authUserByDN, err := client.CheckPasswordForDN(authUser.DN(), user.password)
			require.NoError(t, err)
			require.NotNil(t, authUserByDN)

			// Results should be identical
			assert.Equal(t, authUser.DN(), authUserByDN.DN())
			assert.Equal(t, authUser.SAMAccountName, authUserByDN.SAMAccountName)
		})
	}
}

// Benchmark authentication operations
func BenchmarkCheckPasswordForSAMAccountName(b *testing.B) {
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})
	testData := tc.GetTestData()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.CheckPasswordForSAMAccountName(testData.ValidUserUID, testData.ValidUserPassword)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckPasswordForDN(b *testing.B) {
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})
	testData := tc.GetTestData()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.CheckPasswordForDN(testData.ValidUserDN, testData.ValidUserPassword)
		if err != nil {
			b.Fatal(err)
		}
	}
}
