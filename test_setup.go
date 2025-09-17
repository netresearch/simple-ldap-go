package ldap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/openldap"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestContainer wraps the OpenLDAP container and provides test data
type TestContainer struct {
	Container   *openldap.OpenLDAPContainer
	Config      Config
	AdminUser   string
	AdminPass   string
	BaseDN      string
	UsersOU     string
	GroupsOU    string
	ComputersOU string
	ctx         context.Context
}

// SetupTestContainer creates and configures an OpenLDAP container for testing
func SetupTestContainer(t *testing.T) *TestContainer {
	ctx := context.Background()

	// Create container using generic container approach for better control
	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp", "636/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":    "Example Org",
			"LDAP_DOMAIN":          "example.org",
			"LDAP_ADMIN_PASSWORD":  "admin123",
			"LDAP_CONFIG_PASSWORD": "config123",
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("slapd starting").WithStartupTimeout(120*time.Second).WithPollInterval(2*time.Second),
			wait.ForListeningPort("389/tcp").WithStartupTimeout(120*time.Second).WithPollInterval(2*time.Second),
		),
	}

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	// Convert to OpenLDAP container type
	container := &openldap.OpenLDAPContainer{
		Container: genericContainer,
	}
	require.NoError(t, err)

	// Get connection details using generic container methods
	host, err := genericContainer.Host(ctx)
	require.NoError(t, err)

	mappedPort, err := genericContainer.MappedPort(ctx, "389/tcp")
	require.NoError(t, err)

	port := mappedPort.Port()
	connStr := fmt.Sprintf("ldap://%s:%s", host, port)

	testContainer := &TestContainer{
		Container:   container,
		AdminUser:   "cn=admin,dc=example,dc=org",
		AdminPass:   "admin123",
		BaseDN:      "dc=example,dc=org",
		UsersOU:     "ou=people,dc=example,dc=org",
		GroupsOU:    "ou=groups,dc=example,dc=org",
		ComputersOU: "ou=computers,dc=example,dc=org",
		ctx:         ctx,
		Config: Config{
			Server:            connStr,
			BaseDN:            "dc=example,dc=org",
			IsActiveDirectory: false,
		},
	}

	// Wait additional time for LDAP server to be fully ready
	time.Sleep(5 * time.Second)

	// Wait for container to be ready and populate test data
	testContainer.populateTestData(t)

	return testContainer
}

// populateTestData sets up test users, groups, and computers
func (tc *TestContainer) populateTestData(t *testing.T) {
	// Retry connection setup with backoff
	var conn *ldap.Conn
	var err error

	for i := 0; i < 5; i++ {
		conn, err = ldap.DialURL(tc.Config.Server)
		if err == nil {
			break
		}
		t.Logf("Connection attempt %d failed: %v, retrying...", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	require.NoError(t, err, "Failed to connect to LDAP after 5 attempts")
	defer conn.Close()

	err = conn.Bind(tc.AdminUser, tc.AdminPass)
	require.NoError(t, err, "Failed to bind as admin")

	// Create organizational units
	tc.createOU(t, conn, "people", "People", tc.BaseDN)
	tc.createOU(t, conn, "groups", "Groups", tc.BaseDN)
	tc.createOU(t, conn, "computers", "Computers", tc.BaseDN)

	// Create test users
	tc.createTestUsers(t, conn)

	// Create test groups
	tc.createTestGroups(t, conn)

	// Create test computers
	tc.createTestComputers(t, conn)
}

// createOU creates an organizational unit
func (tc *TestContainer) createOU(t *testing.T, conn *ldap.Conn, ou, description, baseDN string) {
	dn := fmt.Sprintf("ou=%s,%s", ou, baseDN)

	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"organizationalUnit"})
	addReq.Attribute("ou", []string{ou})
	addReq.Attribute("description", []string{description})

	err := conn.Add(addReq)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Logf("Warning: Failed to create OU %s: %v", ou, err)
	}
}

// createTestUsers creates test user accounts
func (tc *TestContainer) createTestUsers(t *testing.T, conn *ldap.Conn) {
	users := []struct {
		uid         string
		cn          string
		sn          string
		givenName   string
		mail        string
		password    string
		description string
	}{
		{
			uid:         "jdoe",
			cn:          "John Doe",
			sn:          "Doe",
			givenName:   "John",
			mail:        "john.doe@example.com",
			password:    "password123",
			description: "Test user - John Doe",
		},
		{
			uid:         "asmith",
			cn:          "Alice Smith",
			sn:          "Smith",
			givenName:   "Alice",
			mail:        "alice.smith@example.com",
			password:    "password456",
			description: "Test user - Alice Smith",
		},
		{
			uid:         "bwilson",
			cn:          "Bob Wilson",
			sn:          "Wilson",
			givenName:   "Bob",
			mail:        "bob.wilson@example.com",
			password:    "password789",
			description: "Test user - Bob Wilson",
		},
		{
			uid:         "abrown",
			cn:          "Alice Brown",
			sn:          "Brown",
			givenName:   "Alice",
			mail:        "alice.brown@example.com",
			password:    "passwordabc",
			description: "Test user - Alice Brown (disabled)",
		},
	}

	for _, user := range users {
		dn := fmt.Sprintf("uid=%s,%s", user.uid, tc.UsersOU)

		addReq := ldap.NewAddRequest(dn, nil)
		addReq.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "shadowAccount"})
		addReq.Attribute("uid", []string{user.uid})
		// Note: OpenLDAP uses uid instead of sAMAccountName
		addReq.Attribute("cn", []string{user.cn})
		addReq.Attribute("sn", []string{user.sn})
		addReq.Attribute("givenName", []string{user.givenName})
		addReq.Attribute("mail", []string{user.mail})
		addReq.Attribute("userPassword", []string{user.password})
		addReq.Attribute("description", []string{user.description})
		addReq.Attribute("uidNumber", []string{fmt.Sprintf("100%d", len(user.uid))})
		addReq.Attribute("gidNumber", []string{"1000"})
		addReq.Attribute("homeDirectory", []string{fmt.Sprintf("/home/%s", user.uid)})

		err := conn.Add(addReq)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Logf("Warning: Failed to create user %s: %v", user.uid, err)
		}
	}
}

// createTestGroups creates test group accounts
func (tc *TestContainer) createTestGroups(t *testing.T, conn *ldap.Conn) {
	groups := []struct {
		cn          string
		description string
		members     []string
	}{
		{
			cn:          "admins",
			description: "System Administrators",
			members:     []string{fmt.Sprintf("uid=jdoe,%s", tc.UsersOU)},
		},
		{
			cn:          "users",
			description: "Regular Users",
			members: []string{
				fmt.Sprintf("uid=asmith,%s", tc.UsersOU),
				fmt.Sprintf("uid=bwilson,%s", tc.UsersOU),
			},
		},
		{
			cn:          "developers",
			description: "Software Developers",
			members: []string{
				fmt.Sprintf("uid=jdoe,%s", tc.UsersOU),
				fmt.Sprintf("uid=bwilson,%s", tc.UsersOU),
			},
		},
	}

	for _, group := range groups {
		dn := fmt.Sprintf("cn=%s,%s", group.cn, tc.GroupsOU)

		addReq := ldap.NewAddRequest(dn, nil)
		addReq.Attribute("objectClass", []string{"groupOfNames"})
		addReq.Attribute("cn", []string{group.cn})
		addReq.Attribute("description", []string{group.description})

		// Add members
		if len(group.members) > 0 {
			addReq.Attribute("member", group.members)
		} else {
			// GroupOfNames requires at least one member, use admin as placeholder
			addReq.Attribute("member", []string{tc.AdminUser})
		}

		err := conn.Add(addReq)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Logf("Warning: Failed to create group %s: %v", group.cn, err)
		}
	}
}

// createTestComputers creates test computer accounts (as device objects for OpenLDAP compatibility)
func (tc *TestContainer) createTestComputers(t *testing.T, conn *ldap.Conn) {
	computers := []struct {
		cn          string
		description string
	}{
		{
			cn:          "WORKSTATION01",
			description: "Test workstation computer",
		},
		{
			cn:          "SERVER01",
			description: "Test server computer",
		},
	}

	for _, computer := range computers {
		dn := fmt.Sprintf("cn=%s,%s", computer.cn, tc.ComputersOU)

		addReq := ldap.NewAddRequest(dn, nil)
		addReq.Attribute("objectClass", []string{"device"})
		addReq.Attribute("cn", []string{computer.cn})
		addReq.Attribute("description", []string{computer.description})

		err := conn.Add(addReq)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Logf("Warning: Failed to create computer %s: %v", computer.cn, err)
		}
	}
}

// GetLDAPClient returns a configured LDAP client for testing
func (tc *TestContainer) GetLDAPClient(t *testing.T) *LDAP {
	client, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)
	return client
}

// GetTestData returns test data references
func (tc *TestContainer) GetTestData() *TestData {
	return &TestData{
		ValidUserDN:       fmt.Sprintf("uid=jdoe,%s", tc.UsersOU),
		ValidUserCN:       "John Doe",
		ValidUserUID:      "jdoe",
		ValidUserMail:     "john.doe@example.com",
		ValidUserPassword: "password123",

		InvalidUserUID:       "nonexistent",
		InvalidPassword:      "wrongpassword",
		DisabledUserUID:      "abrown",
		DisabledUserDN:       fmt.Sprintf("uid=abrown,%s", tc.UsersOU),
		DisabledUserPassword: "passwordabc",

		ValidGroupDN: fmt.Sprintf("cn=admins,%s", tc.GroupsOU),
		ValidGroupCN: "admins",

		ValidComputerDN: fmt.Sprintf("cn=WORKSTATION01,%s", tc.ComputersOU),
		ValidComputerCN: "WORKSTATION01",
	}
}

// TestData contains references to test objects
type TestData struct {
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

	ValidGroupDN string
	ValidGroupCN string

	ValidComputerDN string
	ValidComputerCN string
}

// Close cleans up the test container
func (tc *TestContainer) Close(t *testing.T) {
	err := tc.Container.Terminate(tc.ctx)
	if err != nil {
		t.Logf("Warning: Failed to terminate container: %v", err)
	}
}
