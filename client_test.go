package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	tests := []struct {
		name        string
		config      Config
		user        string
		password    string
		expectError bool
	}{
		{
			name:        "valid configuration",
			config:      tc.Config,
			user:        tc.AdminUser,
			password:    tc.AdminPass,
			expectError: false,
		},
		{
			name: "invalid server URL",
			config: Config{
				Server: "ldap://nonexistent:389",
				BaseDN: tc.BaseDN,
			},
			user:        tc.AdminUser,
			password:    tc.AdminPass,
			expectError: true,
		},
		{
			name:        "invalid credentials",
			config:      tc.Config,
			user:        tc.AdminUser,
			password:    "wrongpassword",
			expectError: true,
		},
		{
			name:        "empty credentials",
			config:      tc.Config,
			user:        "",
			password:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(&tt.config, tt.user, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.config.Server, client.config.Server)
				assert.Equal(t, tt.config.BaseDN, client.config.BaseDN)
				assert.Equal(t, tt.user, client.user)
				assert.Equal(t, tt.password, client.password)
			}
		})
	}
}

func TestWithCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	// Create initial client
	client := tc.GetLDAPClient(t)
	require.NotNil(t, client)

	testData := tc.GetTestData()

	tests := []struct {
		name        string
		dn          string
		password    string
		expectError bool
	}{
		{
			name:        "valid user credentials",
			dn:          testData.ValidUserDN,
			password:    testData.ValidUserPassword,
			expectError: false,
		},
		{
			name:        "invalid password",
			dn:          testData.ValidUserDN,
			password:    "wrongpassword",
			expectError: true,
		},
		{
			name:        "nonexistent user",
			dn:          "uid=nonexistent,ou=people,dc=example,dc=org",
			password:    "password",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newClient, err := client.WithCredentials(tt.dn, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, newClient)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, newClient)
				assert.Equal(t, tt.dn, newClient.user)
				assert.Equal(t, tt.password, newClient.password)
				assert.Equal(t, client.config, newClient.config)
			}
		})
	}
}

func TestGetConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	require.NotNil(t, client)

	t.Run("successful connection", func(t *testing.T) {
		conn, err := client.GetConnection()
		require.NoError(t, err)
		require.NotNil(t, conn)

		// Test that connection is actually authenticated by performing a search
		searchReq := ldap.NewSearchRequest(
			tc.BaseDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		)

		result, err := conn.Search(searchReq)
		assert.NoError(t, err)
		assert.NotNil(t, result)

		_ = conn.Close()
	})

	t.Run("connection with dial options", func(t *testing.T) {
		configWithOpts := tc.Config
		configWithOpts.DialOptions = []ldap.DialOpt{
			ldap.DialWithDialer(nil),
		}

		clientWithOpts, err := New(&configWithOpts, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		conn, err := clientWithOpts.GetConnection()
		require.NoError(t, err)
		require.NotNil(t, conn)

		_ = conn.Close()
	})
}

func TestConfigValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid LDAP config",
			config: Config{
				Server: tc.Config.Server,
				BaseDN: tc.BaseDN,
			},
			wantErr: false,
		},
		{
			name: "Active Directory config",
			config: Config{
				Server:            "ldaps://ad.example.com:636",
				BaseDN:            "DC=example,DC=com",
				IsActiveDirectory: true,
			},
			wantErr: true, // Will fail because server doesn't exist
		},
		{
			name: "invalid server format",
			config: Config{
				Server: "not-a-valid-url",
				BaseDN: tc.BaseDN,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(&tt.config, tc.AdminUser, tc.AdminPass)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsActiveDirectoryFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("IsActiveDirectory false", func(t *testing.T) {
		config := tc.Config
		config.IsActiveDirectory = false

		client, err := New(&config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		assert.False(t, client.config.IsActiveDirectory)
	})

	t.Run("IsActiveDirectory true", func(t *testing.T) {
		config := tc.Config
		config.IsActiveDirectory = true

		client, err := New(&config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		assert.True(t, client.config.IsActiveDirectory)
	})
}

func TestErrDNDuplicated(t *testing.T) {
	assert.Equal(t, "DN is not unique", ErrDNDuplicated.Error())
}

// Benchmark tests for performance monitoring
func BenchmarkNewConnection(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := New(&tc.Config, tc.AdminUser, tc.AdminPass)
		if err != nil {
			b.Fatal(err)
		}
		_ = client
	}
}

func BenchmarkGetConnection(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}
	tc := SetupTestContainer(&testing.T{})
	defer tc.Close(&testing.T{})

	client := tc.GetLDAPClient(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := client.GetConnection()
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}
