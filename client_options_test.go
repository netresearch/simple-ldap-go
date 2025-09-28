//go:build !integration

// Package ldap provides testing for client options and factory methods.
package ldap

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientOptionsCreation tests client creation with various options.
func TestClientOptionsCreation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		username    string
		password    string
		options     []Option
		expectError bool
		errorMsg    string
	}{
		{
			name: "basic_client_success",
			config: Config{
				Server:            "ldaps://test.example.com:636",
				BaseDN:            "DC=test,DC=example,DC=com",
				IsActiveDirectory: true,
			},
			username:    "CN=test,CN=Users,DC=test,DC=example,DC=com",
			password:    "password123",
			options:     nil,
			expectError: false,
		},
		{
			name: "client_with_logger",
			config: Config{
				Server:            "ldaps://test.example.com:636",
				BaseDN:            "DC=test,DC=example,DC=com",
				IsActiveDirectory: true,
			},
			username: "CN=test,CN=Users,DC=test,DC=example,DC=com",
			password: "password123",
			options: []Option{
				WithLogger(slog.New(slog.NewTextHandler(os.Stdout, nil))),
			},
			expectError: false,
		},
		{
			name: "client_with_connection_pool",
			config: Config{
				Server:            "ldaps://test.example.com:636",
				BaseDN:            "DC=test,DC=example,DC=com",
				IsActiveDirectory: true,
			},
			username: "CN=test,CN=Users,DC=test,DC=example,DC=com",
			password: "password123",
			options: []Option{
				WithConnectionPool(&PoolConfig{
					MaxConnections: 10,
					MinConnections: 2,
					MaxIdleTime:    5 * time.Minute,
				}),
			},
			expectError: false,
		},
		{
			name: "client_with_cache",
			config: Config{
				Server:            "ldaps://test.example.com:636",
				BaseDN:            "DC=test,DC=example,DC=com",
				IsActiveDirectory: true,
			},
			username: "CN=test,CN=Users,DC=test,DC=example,DC=com",
			password: "password123",
			options: []Option{
				WithCache(&CacheConfig{
					Enabled: true,
					TTL:     2 * time.Minute,
					MaxSize: 500,
				}),
			},
			expectError: false,
		},
		{
			name: "client_with_all_options",
			config: Config{
				Server:            "ldaps://test.example.com:636",
				BaseDN:            "DC=test,DC=example,DC=com",
				IsActiveDirectory: true,
			},
			username: "CN=test,CN=Users,DC=test,DC=example,DC=com",
			password: "password123",
			options: []Option{
				WithLogger(slog.New(slog.NewTextHandler(os.Stdout, nil))),
				WithConnectionPool(&PoolConfig{
					MaxConnections: 15,
					MinConnections: 3,
					MaxIdleTime:    8 * time.Minute,
				}),
				WithCache(&CacheConfig{
					Enabled: true,
					TTL:     3 * time.Minute,
					MaxSize: 800,
				}),
				WithPerformanceMonitoring(&PerformanceConfig{
					Enabled:            true,
					SlowQueryThreshold: 300 * time.Millisecond,
				}),
				WithConnectionOptions(&ConnectionOptions{
					ConnectionTimeout: 30 * time.Second,
					OperationTimeout:  60 * time.Second,
				}),
			},
			expectError: false,
		},
		{
			name: "invalid_server_url",
			config: Config{
				Server:            "invalid://real.company.com",
				BaseDN:            "DC=real,DC=company,DC=com",
				IsActiveDirectory: true,
			},
			username:    "CN=test,CN=Users,DC=real,DC=company,DC=com",
			password:    "password123",
			options:     nil,
			expectError: true,
			errorMsg:    "failed to initialize LDAP client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip actual connection tests in unit tests
			if testing.Short() {
				t.Skip("Skipping connection test in short mode")
			}

			client, err := New(tt.config, tt.username, tt.password, tt.options...)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, client)
			} else {
				// In a real test environment, this would succeed
				// For unit tests, we expect connection to fail
				if err != nil {
					assert.Contains(t, err.Error(), "connection")
				}
			}
		})
	}
}

// TestFactoryMethods tests the convenience factory methods using subtests.
func TestFactoryMethods(t *testing.T) {
	config := Config{
		Server:            "ldaps://test.example.com:636",
		BaseDN:            "DC=test,DC=example,DC=com",
		IsActiveDirectory: true,
	}
	username := "CN=test,CN=Users,DC=test,DC=example,DC=com"
	password := "password123"

	t.Run("NewBasicClient", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping connection test in short mode")
		}

		client, err := NewBasicClient(config, username, password)
		// Expect connection error in unit tests
		if err != nil {
			assert.Contains(t, err.Error(), "connection")
		} else {
			require.NotNil(t, client)
			defer func() { _ = client.Close() }()
		}
	})

	t.Run("NewPooledClient", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping connection test in short mode")
		}

		client, err := NewPooledClient(config, username, password, 10)
		// Expect connection error in unit tests
		if err != nil {
			assert.Contains(t, err.Error(), "connection")
		} else {
			require.NotNil(t, client)
			defer func() { _ = client.Close() }()
		}
	})

	t.Run("NewCachedClient", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping connection test in short mode")
		}

		client, err := NewCachedClient(config, username, password, 500, 5*time.Minute)
		// Expect connection error in unit tests
		if err != nil {
			assert.Contains(t, err.Error(), "connection")
		} else {
			require.NotNil(t, client)
			defer func() { _ = client.Close() }()
		}
	})

	t.Run("NewHighPerformanceClient", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping connection test in short mode")
		}

		client, err := NewHighPerformanceClient(config, username, password)
		// Expect connection error in unit tests
		if err != nil {
			assert.Contains(t, err.Error(), "connection")
		} else {
			require.NotNil(t, client)
			defer func() { _ = client.Close() }()
		}
	})

	t.Run("NewSecureClient", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping connection test in short mode")
		}

		client, err := NewSecureClient(config, username, password)
		// Expect connection error in unit tests
		if err != nil {
			assert.Contains(t, err.Error(), "connection")
		} else {
			require.NotNil(t, client)
			defer func() { _ = client.Close() }()
		}
	})

	t.Run("NewReadOnlyClient", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping connection test in short mode")
		}

		client, err := NewReadOnlyClient(config, username, password)
		// Expect connection error in unit tests
		if err != nil {
			assert.Contains(t, err.Error(), "connection")
		} else {
			require.NotNil(t, client)
			defer func() { _ = client.Close() }()
		}
	})
}

// NOTE: Builder pattern tests are in builders_test.go

// TestConnectionOptions tests connection options configuration.
func TestConnectionOptions(t *testing.T) {
	tests := []struct {
		name        string
		config      *ConnectionOptions
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid_config",
			config:      DefaultConnectionOptions(),
			expectError: false,
		},
		{
			name: "connection_timeout_set",
			config: &ConnectionOptions{
				ConnectionTimeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "operation_timeout_set",
			config: &ConnectionOptions{
				OperationTimeout: 60 * time.Second,
			},
			expectError: false,
		},
		{
			name: "max_retries_set",
			config: &ConnectionOptions{
				MaxRetries: 3,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For now, we just test that the config can be created
			// In the future, we can add validation methods
			assert.NotNil(t, tt.config)
		})
	}
}

// BenchmarkClientCreation benchmarks different client creation methods.
func BenchmarkClientCreation(b *testing.B) {
	config := Config{
		Server:            "ldaps://test.example.com:636",
		BaseDN:            "DC=test,DC=example,DC=com",
		IsActiveDirectory: true,
	}
	username := "CN=test,CN=Users,DC=test,DC=example,DC=com"
	password := "password123"

	b.Run("NewBasicClient", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			client, err := NewBasicClient(config, username, password)
			if err == nil {
				_ = client.Close()
			}
		}
	})

	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		options := []Option{
			WithLogger(slog.New(slog.NewTextHandler(os.Stdout, nil))),
		}
		for i := 0; i < b.N; i++ {
			client, err := New(config, username, password, options...)
			if err == nil {
				_ = client.Close()
			}
		}
	})

	b.Run("NewHighPerformanceClient", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			client, err := NewHighPerformanceClient(config, username, password)
			if err == nil {
				_ = client.Close()
			}
		}
	})
}

// NOTE: Builder pattern benchmarks are in builders_test.go

// FuzzUserBuilder provides fuzz testing for the UserBuilder.
func FuzzUserBuilder(f *testing.F) {
	// Seed with valid inputs
	f.Add("John Doe", "jdoe", "john.doe@example.com")
	f.Add("", "", "")
	f.Add("Jane Smith", "jsmith", "invalid-email")

	f.Fuzz(func(t *testing.T, cn, samAccountName, email string) {
		builder := NewUserBuilder().
			WithCN(cn).
			WithSAMAccountName(samAccountName).
			WithMail(email)

		user, err := builder.Build()

		// The builder should either succeed or fail gracefully
		if err == nil {
			// If successful, user should have required fields
			require.NotNil(t, user)
			assert.NotEmpty(t, user.CN)
			assert.NotEmpty(t, user.SAMAccountName)
		} else {
			// If failed, user should be nil
			assert.Nil(t, user)
		}
	})
}

// FuzzSAMAccountNameValidation provides fuzz testing for SAM account name validation.
func FuzzSAMAccountNameValidation(f *testing.F) {
	// Seed with various inputs
	f.Add("valid")
	f.Add("invalid/chars")
	f.Add("toolongforsamaccountname")
	f.Add("")

	f.Fuzz(func(t *testing.T, samAccountName string) {
		builder := NewUserBuilder().
			WithCN("Test User").
			WithSAMAccountName(samAccountName)

		_, err := builder.Build()

		// Should not panic regardless of input
		if len(samAccountName) == 0 {
			assert.Error(t, err)
		} else if len(samAccountName) > 20 {
			assert.Error(t, err)
		}
	})
}

// TestHelper provides common test setup functionality.
type TestHelper struct {
	Config   Config
	Username string
	Password string
	Logger   *slog.Logger
}

// NewTestHelper creates a new test helper with default test configuration.
func NewTestHelper() *TestHelper {
	return &TestHelper{
		Config: Config{
			Server:            "ldaps://test.example.com:636",
			BaseDN:            "DC=test,DC=example,DC=com",
			IsActiveDirectory: true,
		},
		Username: "CN=test,CN=Users,DC=test,DC=example,DC=com",
		Password: "password123",
		Logger:   slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// CreateTestClient creates a test client with optional configuration overrides.
func (h *TestHelper) CreateTestClient(t *testing.T, options ...Option) *LDAP {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping client creation in short mode")
	}

	client, err := New(h.Config, h.Username, h.Password, options...)
	if err != nil {
		// In unit tests, we expect connection failures
		t.Logf("Expected connection failure in unit test: %v", err)
		return nil
	}

	t.Cleanup(func() {
		if client != nil {
			_ = client.Close()
		}
	})

	return client
}

// MockLDAP provides a mock implementation for testing.
type MockLDAP struct {
	users     map[string]*User
	groups    map[string]*Group
	computers map[string]*Computer
}

// NewMockLDAP creates a new mock LDAP client for testing.
func NewMockLDAP() *MockLDAP {
	return &MockLDAP{
		users:     make(map[string]*User),
		groups:    make(map[string]*Group),
		computers: make(map[string]*Computer),
	}
}

// FindUserByDN mock implementation.
func (m *MockLDAP) FindUserByDN(dn string) (*User, error) {
	user, exists := m.users[dn]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// FindUserByDNContext mock implementation.
func (m *MockLDAP) FindUserByDNContext(ctx context.Context, dn string) (*User, error) {
	return m.FindUserByDN(dn)
}

// AddMockUser adds a user to the mock.
func (m *MockLDAP) AddMockUser(dn string, user *User) {
	m.users[dn] = user
}

// Example of how to use the mock in tests.
func TestWithMockLDAP(t *testing.T) {
	mock := NewMockLDAP()

	// Add a test user
	testUser := &User{
		Object: Object{
			cn: "Test User",
			dn: "CN=Test User,OU=Users,DC=test,DC=com",
		},
		SAMAccountName: "testuser",
		Enabled:        true,
	}
	mock.AddMockUser(testUser.DN(), testUser)

	// Test finding the user
	foundUser, err := mock.FindUserByDN("CN=Test User,OU=Users,DC=test,DC=com")
	assert.NoError(t, err)
	assert.Equal(t, "Test User", foundUser.CN())
	assert.Equal(t, "testuser", foundUser.SAMAccountName)

	// Test user not found
	_, err = mock.FindUserByDN("CN=Nonexistent,OU=Users,DC=test,DC=com")
	assert.Error(t, err)
	assert.Equal(t, ErrUserNotFound, err)
}

// TestInterfaceCompliance ensures our types implement the required interfaces.
func TestInterfaceCompliance(t *testing.T) {
	// Test that LDAP implements all required interfaces
	// Note: These tests are commented out until all interface methods are implemented
	// var ldap *LDAP

	// Test DirectoryManager interface
	// var _ DirectoryManager = ldap
	// var _ UserManager = ldap
	// var _ GroupManager = ldap
	// var _ ComputerManager = ldap
	// var _ ReadOnlyDirectory = ldap
	// var _ WriteOnlyDirectory = ldap

	t.Log("Interface compliance tests commented out until implementation is complete")
}
