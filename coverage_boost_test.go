//go:build !integration

package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// client.go coverage
// =============================================================================

func TestClientNewWithExampleServers(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{"example.com", "ldap://example.com:389"},
		{"localhost", "ldap://localhost:389"},
		{"enterprise.com", "ldap://enterprise.com:636"},
		{"test.com", "ldap://test.com:389"},
		{"test.server", "ldap://test.server:389"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(Config{
				Server: tt.server,
				BaseDN: "dc=example,dc=com",
			}, "user", "pass")
			require.NoError(t, err)
			require.NotNil(t, client)
			assert.True(t, client.isExampleServer())
		})
	}
}

func TestClientNewValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		user     string
		pass     string
		errorMsg string
	}{
		{
			name:     "empty server",
			config:   Config{Server: "", BaseDN: "dc=test,dc=com"},
			user:     "user",
			pass:     "pass",
			errorMsg: "server URL cannot be empty",
		},
		{
			name:     "empty baseDN",
			config:   Config{Server: "ldap://example.com", BaseDN: ""},
			user:     "user",
			pass:     "pass",
			errorMsg: "base DN cannot be empty",
		},
		{
			name:     "empty username",
			config:   Config{Server: "ldap://example.com", BaseDN: "dc=test,dc=com"},
			user:     "",
			pass:     "pass",
			errorMsg: "username cannot be empty",
		},
		{
			name:     "empty password",
			config:   Config{Server: "ldap://example.com", BaseDN: "dc=test,dc=com"},
			user:     "user",
			pass:     "",
			errorMsg: "password cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.config, tt.user, tt.pass)
			assert.Error(t, err)
			assert.Nil(t, client)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestClientWithCredentialsExampleServer(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "admin", "adminpass")
	require.NoError(t, err)

	// WithCredentials on example server should succeed (no real connection)
	newClient, err := client.WithCredentials("cn=newuser,dc=example,dc=com", "newpass")
	require.NoError(t, err)
	require.NotNil(t, newClient)
	assert.Equal(t, "cn=newuser,dc=example,dc=com", newClient.user)
	assert.Equal(t, "newpass", newClient.password)
}

func TestClientWithCredentialsEmptyCreds(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "admin", "adminpass")
	require.NoError(t, err)

	// Empty username should fail
	newClient, err := client.WithCredentials("", "pass")
	assert.Error(t, err)
	assert.Nil(t, newClient)

	// Empty password should fail
	newClient, err = client.WithCredentials("user", "")
	assert.Error(t, err)
	assert.Nil(t, newClient)
}

func TestClientReleaseConnectionNil(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
	}
	err := client.ReleaseConnection(nil)
	assert.NoError(t, err)
}

func TestClientCloseNoResources(t *testing.T) {
	client := &LDAP{
		config:         &Config{Server: "ldap://test:389"},
		logger:         slog.Default(),
		connPool:       nil,
		cache:          nil,
		perfMonitor:    nil,
		circuitBreaker: nil,
	}
	err := client.Close()
	assert.NoError(t, err)
}

func TestClientCloseWithCache(t *testing.T) {
	cache, err := NewLRUCache(&CacheConfig{
		Enabled: true,
		MaxSize: 10,
		TTL:     time.Minute,
	}, slog.Default())
	require.NoError(t, err)

	client := &LDAP{
		config: &Config{Server: "ldap://test:389"},
		logger: slog.Default(),
		cache:  cache,
	}
	err = client.Close()
	assert.NoError(t, err)
}

func TestClientCloseWithPerfMonitor(t *testing.T) {
	perfConfig := DefaultPerformanceConfig()
	perfConfig.Enabled = true
	monitor := NewPerformanceMonitor(perfConfig, slog.Default())

	client := &LDAP{
		config:      &Config{Server: "ldap://test:389"},
		logger:      slog.Default(),
		perfMonitor: monitor,
	}
	err := client.Close()
	assert.NoError(t, err)
}

func TestClientGetPerformanceStatsExampleServer(t *testing.T) {
	t.Run("example server without pool", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass")
		require.NoError(t, err)

		stats := client.GetPerformanceStats()
		assert.Equal(t, 0, stats.ActiveConnections)
		assert.Equal(t, 0, stats.IdleConnections)
		assert.Equal(t, 0, stats.TotalConnections)
		assert.Equal(t, int64(0), stats.PoolHits)
		assert.Equal(t, int64(0), stats.PoolMisses)
	})

	t.Run("example server with pool config", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 10,
				MinConnections: 2,
			},
		}, "user", "pass")
		require.NoError(t, err)

		stats := client.GetPerformanceStats()
		assert.Equal(t, 5, stats.IdleConnections)
		assert.Equal(t, 5, stats.TotalConnections)
		assert.Equal(t, int64(1), stats.PoolHits)
		assert.Equal(t, int64(1), stats.PoolMisses)
	})

	t.Run("non-example server without perfMonitor", func(t *testing.T) {
		// Directly create client without initializing perfMonitor
		client := &LDAP{
			config:      &Config{Server: "ldap://real-ldap.corp.net:389", BaseDN: "dc=corp,dc=net"},
			logger:      slog.Default(),
			perfMonitor: nil,
		}
		stats := client.GetPerformanceStats()
		assert.Equal(t, 0, stats.ActiveConnections)
	})
}

func TestClientGetPoolStats(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	stats := client.GetPoolStats()
	assert.Equal(t, client.GetPerformanceStats(), stats)
}

func TestClientNewBasicClient(t *testing.T) {
	client, err := NewBasicClient(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestClientNewPooledClient(t *testing.T) {
	// Example server, pool won't actually be initialized
	client, err := NewPooledClient(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass", 5)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.config.Pool)
	assert.Equal(t, 5, client.config.Pool.MaxConnections)
}

func TestClientNewCachedClient(t *testing.T) {
	client, err := NewCachedClient(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass", 500, 3*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.config.Cache)
	assert.Equal(t, 500, client.config.Cache.MaxSize)
	assert.Equal(t, 3*time.Minute, client.config.Cache.TTL)
}

func TestClientNewHighPerformanceClient(t *testing.T) {
	client, err := NewHighPerformanceClient(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.config.Pool)
	assert.NotNil(t, client.config.Cache)
	assert.NotNil(t, client.config.Performance)
}

func TestClientNewSecureClient(t *testing.T) {
	t.Run("without TLS config", func(t *testing.T) {
		client, err := NewSecureClient(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass")
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("with TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client, err := NewSecureClient(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", tlsConfig)
		require.NoError(t, err)
		require.NotNil(t, client)
		assert.NotEmpty(t, client.config.DialOptions)
	})

	t.Run("with nil TLS config", func(t *testing.T) {
		client, err := NewSecureClient(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}

func TestClientNewReadOnlyClient(t *testing.T) {
	client, err := NewReadOnlyClient(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.config.Cache)
	assert.Equal(t, 5000, client.config.Cache.MaxSize)
	assert.Equal(t, 10*time.Minute, client.config.Cache.TTL)
}

func TestClientBulkFindEmptyList(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	result, err := client.BulkFindUsersBySAMAccountName(context.Background(), []string{}, nil)
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestClientBulkFindWithBatchSize(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	// This will fail to find users (example server) but exercises the concurrency code
	names := []string{"user1", "user2", "user3"}
	result, err := client.BulkFindUsersBySAMAccountName(context.Background(), names, &BulkSearchOptions{
		BatchSize:       2,
		ContinueOnError: true,
	})
	// With ContinueOnError, we get partial results
	assert.NotNil(t, result)
	// Errors from example server lookups
	assert.Error(t, err)
}

func TestClientBulkFindWithoutContinueOnError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	names := []string{"user1"}
	result, err := client.BulkFindUsersBySAMAccountName(context.Background(), names, nil)
	// Without ContinueOnError, should still get errors for example server
	assert.NotNil(t, result)
	assert.Error(t, err)
}

func TestClientNewWithCircuitBreakerConfig(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
		Resilience: &ResilienceConfig{
			EnableCircuitBreaker: true,
			CircuitBreaker: &CircuitBreakerConfig{
				MaxFailures: 3,
				Timeout:     30 * time.Second,
			},
		},
	}, "user", "pass")
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.circuitBreaker)
}

func TestClientNewWithCustomLogger(t *testing.T) {
	logger := slog.Default().With("component", "test")
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
		Logger: logger,
	}, "user", "pass")
	require.NoError(t, err)
	require.NotNil(t, client)
}

// =============================================================================
// options.go coverage
// =============================================================================

func TestOptionWithTLS(t *testing.T) {
	t.Run("with valid TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithTLS(tlsConfig))
		require.NoError(t, err)
		assert.NotEmpty(t, client.config.DialOptions)
	})

	t.Run("with nil TLS config", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithTLS(nil))
		require.NoError(t, err)
		// nil TLS config should be a no-op
		assert.NotNil(t, client)
	})
}

func TestOptionWithCache(t *testing.T) {
	t.Run("with valid cache config", func(t *testing.T) {
		cacheConfig := &CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		}
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithCache(cacheConfig))
		require.NoError(t, err)
		assert.NotNil(t, client.config.Cache)
	})

	t.Run("with nil cache config", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithCache(nil))
		require.NoError(t, err)
		assert.Nil(t, client.config.Cache)
	})
}

func TestOptionWithConnectionOptions(t *testing.T) {
	t.Run("with connection timeout", func(t *testing.T) {
		connOpts := &ConnectionOptions{
			ConnectionTimeout: 15 * time.Second,
		}
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithConnectionOptions(connOpts))
		require.NoError(t, err)
		assert.NotEmpty(t, client.config.DialOptions)
	})

	t.Run("with zero timeout", func(t *testing.T) {
		connOpts := &ConnectionOptions{
			ConnectionTimeout: 0,
		}
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithConnectionOptions(connOpts))
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("with nil connection options", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithConnectionOptions(nil))
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestOptionWithPerformanceMonitoring(t *testing.T) {
	t.Run("with valid config", func(t *testing.T) {
		perfConfig := &PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 500 * time.Millisecond,
		}
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithPerformanceMonitoring(perfConfig))
		require.NoError(t, err)
		assert.NotNil(t, client.config.Performance)
	})

	t.Run("with nil config", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithPerformanceMonitoring(nil))
		require.NoError(t, err)
		assert.Nil(t, client.config.Performance)
	})
}

func TestOptionWithDialOptions(t *testing.T) {
	t.Run("with dial options", func(t *testing.T) {
		dialOpt := ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithDialOptions(dialOpt))
		require.NoError(t, err)
		assert.NotEmpty(t, client.config.DialOptions)
	})

	t.Run("with empty dial options", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithDialOptions())
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestOptionWithLogger(t *testing.T) {
	t.Run("with nil logger", func(t *testing.T) {
		client, err := New(Config{
			Server: "ldap://example.com",
			BaseDN: "dc=example,dc=com",
		}, "user", "pass", WithLogger(nil))
		require.NoError(t, err)
		// nil logger should be ignored, default used
		assert.NotNil(t, client.logger)
	})
}

func TestOptionWithCircuitBreakerNilConfig(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass", WithCircuitBreaker(nil))
	require.NoError(t, err)
	// Should use default circuit breaker config
	assert.NotNil(t, client.circuitBreaker)
	assert.NotNil(t, client.config.Resilience)
	assert.True(t, client.config.Resilience.EnableCircuitBreaker)
}

// =============================================================================
// utils.go coverage
// =============================================================================

func TestUtilsParseLastLogonTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected int64
	}{
		{
			name:     "empty string",
			value:    "",
			expected: 0,
		},
		{
			name:     "zero string",
			value:    "0",
			expected: 0,
		},
		{
			name:     "invalid string",
			value:    "notanumber",
			expected: 0,
		},
		{
			name:     "negative value",
			value:    "-100",
			expected: 0,
		},
		{
			name:  "valid AD timestamp (2024-01-01T00:00:00Z approx)",
			value: "133480608000000000",
			// (133480608000000000 - 116444736000000000) * 100 / 1e9 = 1703548800
			expected: func() int64 {
				const epochDiff int64 = 116444736000000000
				filetime := int64(133480608000000000)
				unixNano := (filetime - epochDiff) * 100
				return unixNano / 1e9
			}(),
		},
		{
			name:  "AD epoch (Jan 1, 1601)",
			value: "0",
			// Zero should return 0 early
			expected: 0,
		},
		{
			name:     "very small positive value",
			value:    "1",
			expected: func() int64 {
				const epochDiff int64 = 116444736000000000
				filetime := int64(1)
				unixNano := (filetime - epochDiff) * 100
				return unixNano / 1e9
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLastLogonTimestamp(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUtilsEncodePasswordPair(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://example.com"},
		logger: slog.Default(),
	}

	t.Run("valid password pair", func(t *testing.T) {
		oldCred, err := NewSecureCredentialSimple("user", "oldpass")
		require.NoError(t, err)
		newCred, err := NewSecureCredentialSimple("user", "newpass")
		require.NoError(t, err)

		oldEnc, newEnc, err := client.encodePasswordPair(oldCred, newCred, "testuser")
		assert.NoError(t, err)
		assert.NotEmpty(t, oldEnc)
		assert.NotEmpty(t, newEnc)
		assert.NotEqual(t, oldEnc, newEnc)
	})
}

func TestUtilsCheckContextCancellation(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://example.com"},
		logger: slog.Default(),
	}

	t.Run("context not cancelled", func(t *testing.T) {
		err := client.checkContextCancellation(context.Background(), "Search", "test-id", "start")
		assert.NoError(t, err)
	})

	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := client.checkContextCancellation(ctx, "Search", "test-id", "start")
		assert.Error(t, err)
	})

	t.Run("context deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		time.Sleep(time.Millisecond)
		err := client.checkContextCancellation(ctx, "Search", "test-id", "bind")
		assert.Error(t, err)
	})
}

// =============================================================================
// uac.go coverage - UAC.String() with all flags
// =============================================================================

func TestUACStringAllFlags(t *testing.T) {
	uac := UAC{
		LogonScript:                        true,
		AccountDisabled:                    true,
		HomeDirRequired:                    true,
		Lockout:                            true,
		PasswordNotRequired:                true,
		PasswordCantChange:                 true,
		EncryptedTextPasswordAllowed:       true,
		TempDuplicateAccount:               true,
		NormalAccount:                      true,
		InterdomainTrustAccount:            true,
		WorkstationTrustAccount:            true,
		ServerTrustAccount:                 true,
		NoPasswordExpiration:               true,
		MNSLogonAccount:                    true,
		SmartCardRequired:                  true,
		TrustedForDelegation:               true,
		NotDelegated:                       true,
		UseDESKeyOnly:                      true,
		DontRequirePreauth:                 true,
		PasswordExpired:                    true,
		TrustedToAuthenticateForDelegation: true,
	}

	str := uac.String()

	expectedFlags := []string{
		"LogonScript",
		"AccountDisabled",
		"HomeDirRequired",
		"Lockout",
		"PasswordNotRequired",
		"PasswordCantChange",
		"EncryptedTextPasswordAllowed",
		"TempDuplicateAccount",
		"NormalAccount",
		"InterdomainTrustAccount",
		"WorkstationTrustAccount",
		"ServerTrustAccount",
		"NoPasswordExpiration",
		"MNSLogonAccount",
		"SmartCardRequired",
		"TrustedForDelegation",
		"NotDelegated",
		"UseDESKeyOnly",
		"DontRequirePreauth",
		"PasswordExpired",
		"TrustedToAuthenticateForDelegation",
	}

	for _, flag := range expectedFlags {
		assert.Contains(t, str, flag, "String() should contain %s", flag)
	}
	// No trailing separator
	assert.NotRegexp(t, `, $`, str)
}

func TestUACStringIndividualFlags(t *testing.T) {
	// Test each flag individually to ensure String() covers every branch
	flagTests := []struct {
		uac      UAC
		expected string
	}{
		{UAC{LogonScript: true}, "LogonScript"},
		{UAC{AccountDisabled: true}, "AccountDisabled"},
		{UAC{HomeDirRequired: true}, "HomeDirRequired"},
		{UAC{Lockout: true}, "Lockout"},
		{UAC{PasswordNotRequired: true}, "PasswordNotRequired"},
		{UAC{PasswordCantChange: true}, "PasswordCantChange"},
		{UAC{EncryptedTextPasswordAllowed: true}, "EncryptedTextPasswordAllowed"},
		{UAC{TempDuplicateAccount: true}, "TempDuplicateAccount"},
		{UAC{NormalAccount: true}, "NormalAccount"},
		{UAC{InterdomainTrustAccount: true}, "InterdomainTrustAccount"},
		{UAC{WorkstationTrustAccount: true}, "WorkstationTrustAccount"},
		{UAC{ServerTrustAccount: true}, "ServerTrustAccount"},
		{UAC{NoPasswordExpiration: true}, "NoPasswordExpiration"},
		{UAC{MNSLogonAccount: true}, "MNSLogonAccount"},
		{UAC{SmartCardRequired: true}, "SmartCardRequired"},
		{UAC{TrustedForDelegation: true}, "TrustedForDelegation"},
		{UAC{NotDelegated: true}, "NotDelegated"},
		{UAC{UseDESKeyOnly: true}, "UseDESKeyOnly"},
		{UAC{DontRequirePreauth: true}, "DontRequirePreauth"},
		{UAC{PasswordExpired: true}, "PasswordExpired"},
		{UAC{TrustedToAuthenticateForDelegation: true}, "TrustedToAuthenticateForDelegation"},
	}

	for _, tt := range flagTests {
		t.Run(tt.expected, func(t *testing.T) {
			str := tt.uac.String()
			assert.Equal(t, tt.expected, str)
		})
	}
}

// =============================================================================
// iterators.go coverage
// =============================================================================

func TestIteratorSearchIterConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	searchReq := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)

	var iterErr error
	for _, err := range client.SearchIter(ctx, searchReq) {
		if err != nil {
			iterErr = err
			break
		}
	}
	assert.Error(t, iterErr)
	assert.Contains(t, iterErr.Error(), "connection to example server not available")
}

func TestIteratorSearchPagedIterConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	searchReq := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)

	var iterErr error
	for _, err := range client.SearchPagedIter(ctx, searchReq, 10) {
		if err != nil {
			iterErr = err
			break
		}
	}
	assert.Error(t, iterErr)
	assert.Contains(t, iterErr.Error(), "connection to example server not available")
}

func TestIteratorGroupMembersIterConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	var iterErr error
	for _, err := range client.GroupMembersIter(ctx, "cn=group,dc=example,dc=com") {
		if err != nil {
			iterErr = err
			break
		}
	}
	assert.Error(t, iterErr)
	assert.Contains(t, iterErr.Error(), "connection to example server not available")
}

func TestIteratorWithCancelledContext(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	searchReq := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)

	t.Run("SearchIter cancelled context", func(t *testing.T) {
		var iterErr error
		for _, err := range client.SearchIter(ctx, searchReq) {
			if err != nil {
				iterErr = err
				break
			}
		}
		assert.Error(t, iterErr)
	})

	t.Run("SearchPagedIter cancelled context", func(t *testing.T) {
		var iterErr error
		for _, err := range client.SearchPagedIter(ctx, searchReq, 10) {
			if err != nil {
				iterErr = err
				break
			}
		}
		assert.Error(t, iterErr)
	})

	t.Run("GroupMembersIter cancelled context", func(t *testing.T) {
		var iterErr error
		for _, err := range client.GroupMembersIter(ctx, "cn=group,dc=example,dc=com") {
			if err != nil {
				iterErr = err
				break
			}
		}
		assert.Error(t, iterErr)
	})
}

// =============================================================================
// generics.go coverage
// =============================================================================

func TestGenericSearchConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	// Use a type that implements search methods
	result, err := Search[*MockSearchableLDAPObject](ctx, client, "(objectClass=*)", "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get connection")
}

func TestGenericSearchEmptyBaseDN(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	// Empty baseDN should use config's BaseDN
	result, err := Search[*MockSearchableLDAPObject](ctx, client, "(objectClass=*)", "")
	// Will fail on connection, but the baseDN logic is exercised
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGenericSearchCustomBaseDN(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	result, err := Search[*MockSearchableLDAPObject](ctx, client, "(objectClass=*)", "ou=users,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGenericCreateConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	obj := &MockCreatableLDAPObject{
		MockLDAPObject: MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		},
	}
	dn, err := Create(ctx, client, obj)
	assert.Error(t, err)
	assert.Empty(t, dn)
	assert.Contains(t, err.Error(), "failed to get connection")
}

func TestGenericCreateValidationFailure(t *testing.T) {
	client := &LDAP{
		config: &Config{Server: "ldap://test:389", BaseDN: "dc=test,dc=com"},
		logger: slog.Default(),
	}

	ctx := context.Background()
	obj := &MockCreatableLDAPObject{
		MockLDAPObject:           MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"},
		shouldFailValidation: true,
	}
	dn, err := Create(ctx, client, obj)
	assert.Error(t, err)
	assert.Empty(t, dn)
	assert.Contains(t, err.Error(), "object validation failed")
}

func TestGenericModifyConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	obj := &MockModifiableLDAPObject{
		MockLDAPObject: MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		},
	}
	changes := map[string][]string{"cn": {"new name"}}
	err = Modify(ctx, client, obj, changes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get connection")
}

func TestGenericDeleteConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	obj := &MockLDAPObject{
		dn: "cn=test,dc=example,dc=com",
		cn: "test",
	}
	err = Delete(ctx, client, obj)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get connection")
}

func TestGenericDeleteByDNConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	err = DeleteByDN(ctx, client, "cn=test,dc=example,dc=com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get connection")
}

func TestGenericFindByDNConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	result, err := FindByDN[*MockSearchableLDAPObject](ctx, client, "cn=test,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get connection")
}

func TestGenericBatchProcessCreate(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	obj := &MockCreatableLDAPObject{
		MockLDAPObject: MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		},
	}

	operations := []BatchOperation[*MockCreatableLDAPObject]{
		{Operation: "create", Object: obj},
	}

	results, err := BatchProcess(ctx, client, operations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error, "create should fail due to connection error")
}

func TestGenericBatchProcessModify(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	obj := &MockModifiableLDAPObject{
		MockLDAPObject: MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		},
	}

	operations := []BatchOperation[*MockModifiableLDAPObject]{
		{
			Operation: "modify",
			Object:    obj,
			Changes:   map[string][]string{"cn": {"new name"}},
		},
	}

	results, err := BatchProcess(ctx, client, operations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error, "modify should fail due to interface mismatch or connection")
}

func TestGenericBatchProcessDelete(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	obj := &MockLDAPObject{
		dn: "cn=test,dc=example,dc=com",
		cn: "test",
	}

	operations := []BatchOperation[*MockLDAPObject]{
		{Operation: "delete", Object: obj},
	}

	results, err := BatchProcess(ctx, client, operations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error, "delete should fail due to connection error")
}

func TestGenericBatchProcessContextCancelled(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	obj := &MockLDAPObject{
		dn: "cn=test,dc=example,dc=com",
		cn: "test",
	}

	operations := []BatchOperation[*MockLDAPObject]{
		{Operation: "delete", Object: obj},
		{Operation: "delete", Object: obj},
	}

	results, err := BatchProcess(ctx, client, operations)
	// First op will fail, context check should detect cancellation
	assert.NotNil(t, results)
	// Batch should detect context cancellation
	if err != nil {
		assert.Equal(t, context.Canceled, err)
	}
}

func TestGenericOperationPipelineDelete(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	ctx := context.Background()
	obj := &MockLDAPObject{
		dn: "cn=test,dc=example,dc=com",
		cn: "test",
	}

	// Test delete pipeline operation (hits connection error path)
	pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)
	pipeline.Delete(obj)
	err = pipeline.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pipeline failed")
}

// =============================================================================
// shared_search.go coverage
// =============================================================================

func TestSearchFindByDNContextConnectionError(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	params := dnSearchParams{
		operation:   "FindUserByDN",
		filter:      "(objectClass=user)",
		attributes:  []string{"cn", "sAMAccountName"},
		notFoundErr: ErrUserNotFound,
		logPrefix:   "user_",
	}

	ctx := context.Background()
	result, err := client.findByDNContext(ctx, "cn=test,dc=example,dc=com", params)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get connection")
}

func TestSearchFindByDNContextCancelledContext(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)

	params := dnSearchParams{
		operation:   "FindGroupByDN",
		filter:      "(objectClass=group)",
		attributes:  []string{"cn", "member"},
		notFoundErr: ErrGroupNotFound,
		logPrefix:   "group_",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := client.findByDNContext(ctx, "cn=test,dc=example,dc=com", params)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// =============================================================================
// error_helpers.go coverage
// =============================================================================

func TestErrorHelperAuthenticationError(t *testing.T) {
	t.Run("with non-LDAP error", func(t *testing.T) {
		err := authenticationError("Bind", "cn=user,dc=example,dc=com", errors.New("connection refused"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
		assert.Contains(t, err.Error(), "cn=user,dc=example,dc=com")
	})

	t.Run("with LDAP error", func(t *testing.T) {
		ldapErr := &LDAPError{
			Op:     "Bind",
			Server: "ldap://example.com",
			Err:    errors.New("invalid credentials"),
		}
		err := authenticationError("Bind", "cn=user,dc=example,dc=com", ldapErr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
		assert.Contains(t, err.Error(), "cn=user,dc=example,dc=com")
	})
}

func TestErrorHelperConnectionError(t *testing.T) {
	err := connectionError("search", "users", fmt.Errorf("dial timeout"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get connection for search users")
	assert.Contains(t, err.Error(), "dial timeout")
}

// =============================================================================
// Additional client.go edge cases
// =============================================================================

func TestClientGetConnectionContextWithConnPool(t *testing.T) {
	// Test the code path where connPool is nil and creates direct connection
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)
	assert.Nil(t, client.connPool)

	ctx := context.Background()
	conn, err := client.GetConnectionContext(ctx)
	assert.Error(t, err) // example server
	assert.Nil(t, conn)
}

func TestClientGetConnectionProtectedContextNoCB(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com",
		BaseDN: "dc=example,dc=com",
	}, "user", "pass")
	require.NoError(t, err)
	assert.Nil(t, client.circuitBreaker)

	// Should fall back to regular GetConnectionContext
	conn, err := client.GetConnectionProtectedContext(context.Background())
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestClientIsExampleServerMethod(t *testing.T) {
	tests := []struct {
		server   string
		expected bool
	}{
		{"ldap://example.com:389", true},
		{"ldap://test.server:389", true},
		{"ldap://real-corp.internal:389", false},
		{"ldap://mycompany.org:636", false},
	}

	for _, tt := range tests {
		t.Run(tt.server, func(t *testing.T) {
			client := &LDAP{
				config: &Config{Server: tt.server},
				logger: slog.Default(),
			}
			assert.Equal(t, tt.expected, client.isExampleServer())
		})
	}
}

func TestClientCreateDirectConnectionCancelledContext(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://real-corp.internal:389",
			BaseDN: "dc=corp,dc=internal",
		},
		logger: slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := client.createDirectConnection(ctx)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Equal(t, context.Canceled, err)
}
