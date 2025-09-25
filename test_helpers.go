package ldap

import (
	"testing"
)

// TestContainer is a stub for test container setup
type TestContainer struct {
	Config      Config
	AdminUser   string
	AdminPass   string
	BaseDN      string
	UsersOU     string
	GroupsOU    string
	ComputersOU string
}

// Close closes the test container
func (tc *TestContainer) Close(t *testing.T) {}

// GetLDAPClient returns a test LDAP client
func (tc *TestContainer) GetLDAPClient(t *testing.T) *LDAP {
	client, err := New(&tc.Config, tc.AdminUser, tc.AdminPass)
	if err != nil {
		t.Fatalf("Failed to create LDAP client: %v", err)
	}
	return client
}

// TestData represents test data
type TestData struct {
	TestUserDN           string
	TestUserSAM          string
	TestUserPass         string
	TestGroupDN          string
	TestGroupName        string
	ValidUserDN          string
	ValidUserUID         string
	ValidUserCN          string
	ValidUserMail        string
	ValidUserPassword    string
	InvalidUserUID       string
	InvalidPassword      string
	DisabledUserUID      string
	DisabledUserDN       string
	DisabledUserPassword string
}

// GetTestData returns test data
func (tc *TestContainer) GetTestData() TestData {
	return TestData{
		TestUserDN:           "cn=testuser,ou=users," + tc.BaseDN,
		TestUserSAM:          "testuser",
		TestUserPass:         "testpass",
		TestGroupDN:          "cn=testgroup,ou=groups," + tc.BaseDN,
		TestGroupName:        "testgroup",
		ValidUserDN:          "cn=testuser,ou=users," + tc.BaseDN,
		ValidUserUID:         "testuser",
		ValidUserCN:          "testuser",
		ValidUserMail:        "testuser@example.com",
		ValidUserPassword:    "testpass",
		InvalidUserUID:       "nonexistentuser",
		InvalidPassword:      "wrongpassword",
		DisabledUserUID:      "disableduser",
		DisabledUserDN:       "cn=disableduser,ou=users," + tc.BaseDN,
		DisabledUserPassword: "disabledpass",
	}
}

// SetupTestContainer creates a test container
// This is a stub implementation - actual integration tests require Docker
func SetupTestContainer(t *testing.T) *TestContainer {
	t.Skip("Integration tests require Docker container setup")
	return &TestContainer{
		Config: Config{
			Server: "ldap://localhost:389",
			BaseDN: "dc=example,dc=com",
		},
		AdminUser: "cn=admin,dc=example,dc=com",
		AdminPass: "admin",
		BaseDN:    "dc=example,dc=com",
	}
}

// Note: LDAPError and related functions are now defined in errors.go

// Note: Error helper functions are now defined in errors.go
