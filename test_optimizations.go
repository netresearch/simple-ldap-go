//go:build integration
// +build integration

package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/openldap"
	"github.com/testcontainers/testcontainers-go/wait"
)

// SharedTestContainer manages a reusable test container across multiple tests
type SharedTestContainer struct {
	container   *openldap.OpenLDAPContainer
	config      Config
	adminUser   string
	adminPass   string
	baseDN      string
	usersOU     string
	groupsOU    string
	computersOU string
	ctx         context.Context
	testData    *TestData
	mu          sync.RWMutex
	refCount    int
	initialized bool
}

var (
	sharedContainer *SharedTestContainer
	containerMu     sync.Mutex
)

// GetSharedTestContainer returns a shared test container, creating it if necessary
func GetSharedTestContainer(t *testing.T) *SharedTestContainer {
	// Skip integration tests in short mode or CI without Docker
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if Docker is available
	if !isDockerAvailable() {
		t.Skip("Docker not available, skipping integration test")
	}

	containerMu.Lock()
	defer containerMu.Unlock()

	if sharedContainer == nil {
		sharedContainer = createSharedContainer(t)
	}

	sharedContainer.mu.Lock()
	sharedContainer.refCount++
	sharedContainer.mu.Unlock()

	return sharedContainer
}

// createSharedContainer creates a new shared container with optimized settings
func createSharedContainer(t *testing.T) *SharedTestContainer {
	ctx := context.Background()

	// Optimized container request with faster startup
	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":    "Example Org",
			"LDAP_DOMAIN":          "example.org",
			"LDAP_ADMIN_PASSWORD":  "admin123",
			"LDAP_CONFIG_PASSWORD": "config123",
			"LDAP_LOG_LEVEL":       "256", // Reduce logging for faster startup
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("slapd starting").WithStartupTimeout(60*time.Second).WithPollInterval(1*time.Second),
			wait.ForListeningPort("389/tcp").WithStartupTimeout(60*time.Second).WithPollInterval(1*time.Second),
		),
	}

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	container := &openldap.OpenLDAPContainer{
		Container: genericContainer,
	}

	host, err := genericContainer.Host(ctx)
	require.NoError(t, err)

	mappedPort, err := genericContainer.MappedPort(ctx, "389/tcp")
	require.NoError(t, err)

	port := mappedPort.Port()
	connStr := fmt.Sprintf("ldap://%s:%s", host, port)

	sharedContainer := &SharedTestContainer{
		container:   container,
		adminUser:   "cn=admin,dc=example,dc=org",
		adminPass:   "admin123",
		baseDN:      "dc=example,dc=org",
		usersOU:     "ou=people,dc=example,dc=org",
		groupsOU:    "ou=groups,dc=example,dc=org",
		computersOU: "ou=computers,dc=example,dc=org",
		ctx:         ctx,
		config: Config{
			Server:            connStr,
			BaseDN:            "dc=example,dc=org",
			IsActiveDirectory: false,
			Logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		},
	}

	// Reduced wait time for faster test execution
	time.Sleep(2 * time.Second)

	// Initialize test data once
	sharedContainer.populateTestDataOnce(t)

	return sharedContainer
}

// populateTestDataOnce populates test data only once for the shared container
func (stc *SharedTestContainer) populateTestDataOnce(t *testing.T) {
	stc.mu.Lock()
	defer stc.mu.Unlock()

	if stc.initialized {
		return
	}

	// Optimized connection with shorter retry cycle
	var conn *ldap.Conn
	var err error

	for i := 0; i < 3; i++ { // Reduced retries
		conn, err = ldap.DialURL(stc.config.Server)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond) // Shorter delays
	}
	require.NoError(t, err, "Failed to connect to shared LDAP container")
	defer conn.Close()

	err = conn.Bind(stc.adminUser, stc.adminPass)
	require.NoError(t, err, "Failed to bind as admin to shared container")

	// Create organizational units
	stc.createOU(t, conn, "people", "People", stc.baseDN)
	stc.createOU(t, conn, "groups", "Groups", stc.baseDN)
	stc.createOU(t, conn, "computers", "Computers", stc.baseDN)

	// Create test data
	stc.createTestUsers(t, conn)
	stc.createTestGroups(t, conn)
	stc.createTestComputers(t, conn)

	// Cache test data
	stc.testData = &TestData{
		ValidUserDN:       fmt.Sprintf("uid=jdoe,%s", stc.usersOU),
		ValidUserCN:       "John Doe",
		ValidUserUID:      "jdoe",
		ValidUserMail:     "john.doe@example.com",
		ValidUserPassword: "password123",

		InvalidUserUID:       "nonexistent",
		InvalidPassword:      "wrongpassword",
		DisabledUserUID:      "abrown",
		DisabledUserDN:       fmt.Sprintf("uid=abrown,%s", stc.usersOU),
		DisabledUserPassword: "passwordabc",

		ValidGroupDN: fmt.Sprintf("cn=admins,%s", stc.groupsOU),
		ValidGroupCN: "admins",

		ValidComputerDN: fmt.Sprintf("cn=WORKSTATION01,%s", stc.computersOU),
		ValidComputerCN: "WORKSTATION01",
	}

	stc.initialized = true
}

// Helper methods (same implementation as TestContainer but optimized)
func (stc *SharedTestContainer) createOU(t *testing.T, conn *ldap.Conn, ou, description, baseDN string) {
	dn := fmt.Sprintf("ou=%s,%s", ou, baseDN)

	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"organizationalUnit"})
	addReq.Attribute("ou", []string{ou})
	addReq.Attribute("description", []string{description})

	err := conn.Add(addReq)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		// Don't fail on OU creation errors in shared container
		t.Logf("Note: OU creation for %s: %v", ou, err)
	}
}

func (stc *SharedTestContainer) createTestUsers(t *testing.T, conn *ldap.Conn) {
	users := []struct {
		uid         string
		cn          string
		sn          string
		givenName   string
		mail        string
		password    string
		description string
	}{
		{"jdoe", "John Doe", "Doe", "John", "john.doe@example.com", "password123", "Test user - John Doe"},
		{"asmith", "Alice Smith", "Smith", "Alice", "alice.smith@example.com", "password456", "Test user - Alice Smith"},
		{"bwilson", "Bob Wilson", "Wilson", "Bob", "bob.wilson@example.com", "password789", "Test user - Bob Wilson"},
		{"abrown", "Alice Brown", "Brown", "Alice", "alice.brown@example.com", "passwordabc", "Test user - Alice Brown (disabled)"},
	}

	for _, user := range users {
		dn := fmt.Sprintf("uid=%s,%s", user.uid, stc.usersOU)

		addReq := ldap.NewAddRequest(dn, nil)
		addReq.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "shadowAccount"})
		addReq.Attribute("uid", []string{user.uid})
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
			t.Logf("Note: User creation for %s: %v", user.uid, err)
		}
	}
}

func (stc *SharedTestContainer) createTestGroups(t *testing.T, conn *ldap.Conn) {
	groups := []struct {
		cn          string
		description string
		members     []string
	}{
		{"admins", "System Administrators", []string{fmt.Sprintf("uid=jdoe,%s", stc.usersOU)}},
		{"users", "Regular Users", []string{fmt.Sprintf("uid=asmith,%s", stc.usersOU), fmt.Sprintf("uid=bwilson,%s", stc.usersOU)}},
		{"developers", "Software Developers", []string{fmt.Sprintf("uid=jdoe,%s", stc.usersOU), fmt.Sprintf("uid=bwilson,%s", stc.usersOU)}},
	}

	for _, group := range groups {
		dn := fmt.Sprintf("cn=%s,%s", group.cn, stc.groupsOU)

		addReq := ldap.NewAddRequest(dn, nil)
		addReq.Attribute("objectClass", []string{"groupOfNames"})
		addReq.Attribute("cn", []string{group.cn})
		addReq.Attribute("description", []string{group.description})

		if len(group.members) > 0 {
			addReq.Attribute("member", group.members)
		} else {
			addReq.Attribute("member", []string{stc.adminUser})
		}

		err := conn.Add(addReq)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Logf("Note: Group creation for %s: %v", group.cn, err)
		}
	}
}

func (stc *SharedTestContainer) createTestComputers(t *testing.T, conn *ldap.Conn) {
	computers := []struct {
		cn          string
		description string
	}{
		{"WORKSTATION01", "Test workstation computer"},
		{"SERVER01", "Test server computer"},
	}

	for _, computer := range computers {
		dn := fmt.Sprintf("cn=%s,%s", computer.cn, stc.computersOU)

		addReq := ldap.NewAddRequest(dn, nil)
		addReq.Attribute("objectClass", []string{"device"})
		addReq.Attribute("cn", []string{computer.cn})
		addReq.Attribute("description", []string{computer.description})

		err := conn.Add(addReq)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Logf("Note: Computer creation for %s: %v", computer.cn, err)
		}
	}
}

// GetLDAPClient returns a configured LDAP client for testing
func (stc *SharedTestContainer) GetLDAPClient(t *testing.T) *LDAP {
	client, err := New(&stc.config, stc.adminUser, stc.adminPass)
	require.NoError(t, err)
	return client
}

// GetTestData returns cached test data
func (stc *SharedTestContainer) GetTestData() *TestData {
	stc.mu.RLock()
	defer stc.mu.RUnlock()
	return stc.testData
}

// GetConfig returns the container configuration
func (stc *SharedTestContainer) GetConfig() Config {
	stc.mu.RLock()
	defer stc.mu.RUnlock()
	return stc.config
}

// GetAdminCredentials returns admin credentials
func (stc *SharedTestContainer) GetAdminCredentials() (string, string) {
	stc.mu.RLock()
	defer stc.mu.RUnlock()
	return stc.adminUser, stc.adminPass
}

// GetBaseDN returns the base DN
func (stc *SharedTestContainer) GetBaseDN() string {
	stc.mu.RLock()
	defer stc.mu.RUnlock()
	return stc.baseDN
}

// Close decrements reference count and cleans up if no more references
func (stc *SharedTestContainer) Close(t *testing.T) {
	stc.mu.Lock()
	stc.refCount--
	shouldCleanup := stc.refCount <= 0
	stc.mu.Unlock()

	// Only cleanup when all tests are done (handled by test cleanup)
	if shouldCleanup {
		t.Cleanup(func() {
			containerMu.Lock()
			defer containerMu.Unlock()
			if sharedContainer != nil && sharedContainer.refCount <= 0 {
				stc.cleanup(t)
				sharedContainer = nil
			}
		})
	}
}

// cleanup terminates the container
func (stc *SharedTestContainer) cleanup(t *testing.T) {
	if stc.container != nil {
		err := stc.container.Terminate(stc.ctx)
		if err != nil {
			t.Logf("Warning: Failed to terminate shared container: %v", err)
		}
	}
}

// isDockerAvailable checks if Docker is available
func isDockerAvailable() bool {
	// Check for Docker socket or environment
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return true
	}

	// Check for Docker environment variables
	if os.Getenv("DOCKER_HOST") != "" {
		return true
	}

	return false
}

// FastTestConfig provides optimized configuration for fast unit tests
type FastTestConfig struct {
	UseInMemoryCache bool
	SkipValidation   bool
	DisableLogging   bool
}

// NewFastTestClient creates an LDAP client optimized for unit testing
func NewFastTestClient() *LDAP {
	config := Config{
		Server:            "ldap://mock:389", // Mock server for unit tests
		BaseDN:            "dc=test,dc=com",
		IsActiveDirectory: false,
		Logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	// Create client without actual connection for unit tests
	client := &LDAP{
		config:   &config,
		user:     "cn=admin,dc=test,dc=com",
		password: "testpass",
		logger:   config.Logger,
		// No pool, cache, or perfMonitor for unit tests
	}

	return client
}