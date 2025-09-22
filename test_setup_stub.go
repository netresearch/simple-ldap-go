//go:build !integration
// +build !integration

package ldap

import (
	"testing"
)

// TestContainer is a stub for non-integration builds
type TestContainer struct {
	Config      Config
	AdminUser   string
	AdminPass   string
	BaseDN      string
	UsersOU     string
	GroupsOU    string
	ComputersOU string
}

// TestData is a stub for non-integration builds
type TestData struct {
	Users     []TestUser
	Groups    []TestGroup
	Computers []TestComputer

	// Authentication test data
	ValidUserDN       string
	ValidUserCN       string
	ValidUserUID      string
	ValidUserMail     string
	ValidUserPassword string
	InvalidUserUID       string
	InvalidPassword      string
	DisabledUserUID      string
	DisabledUserDN       string
	DisabledUserPassword string

	// Computer test data
	ValidComputerDN string
	ValidComputerCN string

	// Group test data
	ValidGroupDN string
	ValidGroupCN string
}

// TestUser is a stub for non-integration builds
type TestUser struct {
	CN             string
	SAMAccountName string
	Email          string
	Password       string
	DN             string
}

// TestGroup is a stub for non-integration builds
type TestGroup struct {
	CN      string
	DN      string
	Members []string
}

// TestComputer is a stub for non-integration builds
type TestComputer struct {
	CN             string
	SAMAccountName string
	DN             string
}

// SetupTestContainer is a stub that skips if called without integration build tag
func SetupTestContainer(t *testing.T) *TestContainer {
	t.Skip("SetupTestContainer requires integration build tag")
	return nil
}

// GetLDAPClient is a stub method
func (tc *TestContainer) GetLDAPClient(t *testing.T) *LDAP {
	t.Skip("GetLDAPClient requires integration build tag")
	return nil
}

// GetTestData is a stub method
func (tc *TestContainer) GetTestData() *TestData {
	return &TestData{
		ValidUserDN:       "uid=testuser,ou=users,dc=example,dc=org",
		ValidUserCN:       "Test User",
		ValidUserUID:      "testuser",
		ValidUserMail:     "test@example.com",
		ValidUserPassword: "testpass",
		InvalidUserUID:       "nonexistent",
		InvalidPassword:      "wrongpass",
		DisabledUserUID:      "disabled",
		DisabledUserDN:       "uid=disabled,ou=users,dc=example,dc=org",
		DisabledUserPassword: "disabledpass",
		ValidComputerDN: "cn=TESTPC,ou=computers,dc=example,dc=org",
		ValidComputerCN: "TESTPC",
		ValidGroupDN: "cn=testgroup,ou=groups,dc=example,dc=org",
		ValidGroupCN: "testgroup",
	}
}

// Close is a stub method
func (tc *TestContainer) Close(t *testing.T) {
	// No-op stub
}

// Cleanup is a stub method
func (tc *TestContainer) Cleanup() {
	// No-op stub
}