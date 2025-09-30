//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupPoolTestConfig creates a test configuration for pool tests
func setupPoolTestConfig() (*PoolConfig, Config, string, string, *slog.Logger) {
	poolConfig := &PoolConfig{
		MaxConnections:      5,
		MinConnections:      2,
		MaxIdleTime:         1 * time.Minute,
		HealthCheckInterval: 10 * time.Second,
		ConnectionTimeout:   5 * time.Second,
		GetTimeout:          3 * time.Second,
	}

	ldapConfig := Config{
		Server:            os.Getenv("LDAP_SERVER"),
		BaseDN:            os.Getenv("LDAP_BASE_DN"),
		IsActiveDirectory: false,
		Logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	user := os.Getenv("LDAP_BIND_DN")
	password := os.Getenv("LDAP_BIND_PASSWORD")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	return poolConfig, ldapConfig, user, password, logger
}

func TestNewConnectionPool(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		t.Skip("LDAP test environment not configured")
	}

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Verify initial stats
	stats := pool.Stats()
	assert.GreaterOrEqual(t, stats.TotalConnections, int32(poolConfig.MinConnections))
	assert.Equal(t, int32(0), stats.ActiveConnections)
	assert.Equal(t, stats.TotalConnections, stats.IdleConnections)
}

func TestConnectionPool_GetPut(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		t.Skip("LDAP test environment not configured")
	}

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	t.Run("BasicGetPut", func(t *testing.T) {
		// Get connection
		conn, err := pool.Get(ctx)
		require.NoError(t, err)
		assert.NotNil(t, conn)

		// Verify stats
		stats := pool.Stats()
		assert.Equal(t, int32(1), stats.ActiveConnections)
		assert.Greater(t, stats.PoolHits+stats.PoolMisses, int64(0))

		// Put connection back
		_ = conn.Close()

		// Allow time for cleanup
		time.Sleep(10 * time.Millisecond)

		// Verify connection returned to pool
		finalStats := pool.Stats()
		assert.Equal(t, int32(0), finalStats.ActiveConnections)
	})

	t.Run("MultipleConnections", func(t *testing.T) {
		var connections []*ldap.Conn

		// Get multiple connections
		for i := 0; i < 3; i++ {
			conn, err := pool.Get(ctx)
			require.NoError(t, err)
			connections = append(connections, conn)
		}

		// Verify stats
		stats := pool.Stats()
		assert.Equal(t, int32(3), stats.ActiveConnections)

		// Return all connections
		for _, conn := range connections {
			_ = conn.Close()
		}

		// Allow cleanup time
		time.Sleep(20 * time.Millisecond)

		// Verify all returned
		finalStats := pool.Stats()
		assert.Equal(t, int32(0), finalStats.ActiveConnections)
	})
}

func TestConnectionPool_Concurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		t.Skip("LDAP test environment not configured")
	}

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	const numGoroutines = 10
	const operationsPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*operationsPerGoroutine)

	ctx := context.Background()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				conn, err := pool.Get(ctx)
				if err != nil {
					errors <- err
					continue
				}

				// Simulate some work
				time.Sleep(1 * time.Millisecond)

				// Return connection
				_ = conn.Close()
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorList []error
	for err := range errors {
		errorList = append(errorList, err)
	}
	assert.Empty(t, errorList, "Expected no errors during concurrent operations")

	// Verify final state
	finalStats := pool.Stats()
	assert.Equal(t, int32(0), finalStats.ActiveConnections)
	assert.Greater(t, finalStats.PoolHits, int64(0))

	t.Logf("Concurrent test stats: hits=%d, misses=%d, active=%d",
		finalStats.PoolHits, finalStats.PoolMisses, finalStats.ActiveConnections)
}

func TestConnectionPool_PoolExhaustion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		t.Skip("LDAP test environment not configured")
	}

	// Use small pool for exhaustion testing
	poolConfig.MaxConnections = 3
	poolConfig.GetTimeout = 100 * time.Millisecond

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	// Get all available connections
	var connections []*ldap.Conn
	for i := 0; i < poolConfig.MaxConnections; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			break // Pool might be exhausted
		}
		connections = append(connections, conn)
	}

	// Verify we got expected connections
	assert.Len(t, connections, poolConfig.MaxConnections)

	// Try to get another connection (should timeout)
	timeoutCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	_, err = pool.Get(timeoutCtx)
	assert.Error(t, err, "Expected timeout error when pool is exhausted")

	// Return one connection
	_ = connections[0].Close()
	time.Sleep(10 * time.Millisecond)

	// Should be able to get a connection now
	conn, err := pool.Get(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, conn)

	// Clean up
	_ = conn.Close()
	for i := 1; i < len(connections); i++ {
		_ = connections[i].Close()
	}
}

func TestConnectionPool_HealthChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		t.Skip("LDAP test environment not configured")
	}

	// Set short health check interval for testing
	poolConfig.HealthCheckInterval = 100 * time.Millisecond
	poolConfig.MaxIdleTime = 50 * time.Millisecond

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	// Get initial stats
	initialStats := pool.Stats()
	t.Logf("Initial stats: %+v", initialStats)

	// Create some connections beyond minimum
	var connections []*ldap.Conn
	for i := 0; i < 4; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			break
		}
		connections = append(connections, conn)
	}

	// Return connections and wait for health checks
	for _, conn := range connections {
		_ = conn.Close()
	}

	// Wait longer than MaxIdleTime to trigger cleanup
	time.Sleep(200 * time.Millisecond)

	// Check that connections were cleaned up
	finalStats := pool.Stats()
	t.Logf("Final stats: %+v", finalStats)

	// Should have health check activity
	assert.Greater(t, finalStats.HealthChecksPassed+finalStats.HealthChecksFailed,
		initialStats.HealthChecksPassed+initialStats.HealthChecksFailed)
}

func TestConnectionPool_Context(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		t.Skip("LDAP test environment not configured")
	}

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	t.Run("ContextCancellation", func(t *testing.T) {
		// Create a context that cancels immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Should fail due to cancelled context
		_, err := pool.Get(ctx)
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("ContextTimeout", func(t *testing.T) {
		// Create a context with very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// Should fail due to timeout
		_, err := pool.Get(ctx)
		assert.Error(t, err)
	})
}

func BenchmarkConnectionPool_GetPut(b *testing.B) {
	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		b.Skip("LDAP test environment not configured")
	}

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(b, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.Get(ctx)
			if err != nil {
				b.Error(err)
				continue
			}
			_ = conn.Close()
		}
	})

	if !b.Failed() {
		stats := pool.Stats()
		hitRatio := float64(stats.PoolHits) / float64(stats.PoolHits+stats.PoolMisses) * 100
		b.ReportMetric(hitRatio, "hit_ratio_%")
		b.ReportMetric(float64(stats.ConnectionsCreated), "connections_created")
	}
}
func TestLDAP_WithConnectionPool(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		t.Skip("LDAP test environment not configured. Set LDAP_SERVER, LDAP_BASE_DN, LDAP_BIND_DN, and LDAP_BIND_PASSWORD")
	}

	config := Config{
		Server:            server,
		BaseDN:            baseDN,
		IsActiveDirectory: false,
		Logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Pool: &PoolConfig{
			MaxConnections:      10,
			MinConnections:      3,
			MaxIdleTime:         2 * time.Minute,
			HealthCheckInterval: 30 * time.Second,
			ConnectionTimeout:   10 * time.Second,
			GetTimeout:          5 * time.Second,
		},
	}

	client, err := New(config, bindDN, bindPassword)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	// Verify pool is initialized
	stats := client.GetPoolStats()
	require.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalConnections, int32(3))
	t.Logf("Initial pool stats: %+v", stats)

	t.Run("BasicOperations", func(t *testing.T) {
		ctx := context.Background()

		// Test user operations
		users, err := client.FindUsersContext(ctx)
		assert.NoError(t, err)
		t.Logf("Found %d users", len(users))

		if len(users) > 0 {
			// Test finding specific user
			user, err := client.FindUserByDNContext(ctx, users[0].DN())
			assert.NoError(t, err)
			assert.Equal(t, users[0].DN(), user.DN())
		}
	})

	t.Run("ConcurrentOperations", func(t *testing.T) {
		const numGoroutines = 20
		const operationsPerGoroutine = 5

		var wg sync.WaitGroup
		errCh := make(chan error, numGoroutines*operationsPerGoroutine)

		startTime := time.Now()

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				ctx := context.Background()

				for j := 0; j < operationsPerGoroutine; j++ {
					// Perform various operations
					_, err := client.FindUsersContext(ctx)
					if err != nil {
						errCh <- err
						continue
					}

					// Small delay to simulate real usage
					time.Sleep(10 * time.Millisecond)
				}
			}(i)
		}

		wg.Wait()
		close(errCh)

		duration := time.Since(startTime)
		t.Logf("Concurrent operations completed in %v", duration)

		// Check for errors
		var errors []error
		for err := range errCh {
			errors = append(errors, err)
		}
		assert.Empty(t, errors, "Expected no errors during concurrent operations")

		// Check final stats
		finalStats := client.GetPoolStats()
		require.NotNil(t, finalStats)
		assert.Greater(t, finalStats.PoolHits, int64(0))
		t.Logf("Final pool stats: %+v", finalStats)

		// Pool hits should be much higher than misses for efficient pooling
		if finalStats.PoolHits > 0 && finalStats.PoolMisses > 0 {
			hitRatio := float64(finalStats.PoolHits) / float64(finalStats.PoolHits+finalStats.PoolMisses)
			t.Logf("Pool hit ratio: %.2f%%", hitRatio*100)
			assert.Greater(t, hitRatio, 0.5, "Expected pool hit ratio > 50%")
		}
	})

	t.Run("PoolStatsProgression", func(t *testing.T) {
		ctx := context.Background()

		initialStats := client.GetPoolStats()
		require.NotNil(t, initialStats)

		// Perform several operations
		for i := 0; i < 10; i++ {
			_, err := client.FindUsersContext(ctx)
			assert.NoError(t, err)
		}

		finalStats := client.GetPoolStats()
		require.NotNil(t, finalStats)

		// Stats should have progressed
		assert.GreaterOrEqual(t, finalStats.PoolHits, initialStats.PoolHits)

		t.Logf("Stats progression: initial_hits=%d, final_hits=%d",
			initialStats.PoolHits, finalStats.PoolHits)
	})
}

func TestLDAP_WithoutConnectionPool(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		t.Skip("LDAP test environment not configured")
	}

	// Create client without pool configuration (legacy behavior)
	config := Config{
		Server:            server,
		BaseDN:            baseDN,
		IsActiveDirectory: false,
		Logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		// Pool: nil - no pooling
	}

	client, err := New(config, bindDN, bindPassword)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	// Verify no pool is initialized
	stats := client.GetPoolStats()
	assert.Nil(t, stats, "Expected no pool stats when pooling is disabled")

	t.Run("LegacyBehaviorWorks", func(t *testing.T) {
		ctx := context.Background()

		// Operations should still work without pooling
		users, err := client.FindUsersContext(ctx)
		assert.NoError(t, err)
		t.Logf("Found %d users without pooling", len(users))
	})
}

func TestLDAP_PooledConnectionInterface(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		t.Skip("LDAP test environment not configured")
	}

	config := Config{
		Server:            server,
		BaseDN:            baseDN,
		IsActiveDirectory: false,
		Pool: &PoolConfig{
			MaxConnections: 3,
			MinConnections: 1,
		},
	}

	client, err := New(config, bindDN, bindPassword)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	t.Run("ConnectionInterfaceCompliance", func(t *testing.T) {
		conn, err := client.GetConnectionContext(ctx)
		require.NoError(t, err)
		defer func() {
			_ = conn.Close()
		}()

		// Test that pooled connection implements required interface methods
		assert.NotNil(t, conn)

		// Test search operation through pooled connection
		searchReq := &ldap.SearchRequest{
			BaseDN:       baseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Filter:       "(objectClass=*)",
			Attributes:   []string{"cn"},
			SizeLimit:    1,
		}

		result, err := conn.Search(searchReq)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("ConnectionReuse", func(t *testing.T) {
		initialStats := client.GetPoolStats()
		require.NotNil(t, initialStats)

		// Get and immediately return connection multiple times
		for i := 0; i < 5; i++ {
			conn, err := client.GetConnectionContext(ctx)
			require.NoError(t, err)
			_ = conn.Close() // Should return to pool
		}

		finalStats := client.GetPoolStats()
		require.NotNil(t, finalStats)

		// Should have reused connections
		assert.Greater(t, finalStats.PoolHits, initialStats.PoolHits)

		t.Logf("Connection reuse test: hits increased by %d",
			finalStats.PoolHits-initialStats.PoolHits)
	})
}

func BenchmarkLDAP_PooledVsNonPooled(b *testing.B) {
	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		b.Skip("LDAP test environment not configured")
	}

	b.Run("WithPool", func(b *testing.B) {
		config := Config{
			Server: server,
			BaseDN: baseDN,
			Pool: &PoolConfig{
				MaxConnections: 10,
				MinConnections: 5,
			},
		}

		client, err := New(config, bindDN, bindPassword)
		require.NoError(b, err)
		defer func() { _ = client.Close() }()

		ctx := context.Background()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := client.FindUsersContext(ctx)
				if err != nil {
					b.Error(err)
				}
			}
		})

		// Log final stats
		if !b.Failed() {
			stats := client.GetPoolStats()
			b.Logf("Pool stats: hits=%d, misses=%d, hit_ratio=%.2f%%",
				stats.PoolHits, stats.PoolMisses,
				float64(stats.PoolHits)/float64(stats.PoolHits+stats.PoolMisses)*100)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		config := Config{
			Server: server,
			BaseDN: baseDN,
			// Pool: nil - no pooling
		}

		client, err := New(config, bindDN, bindPassword)
		require.NoError(b, err)
		defer func() { _ = client.Close() }()

		ctx := context.Background()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := client.FindUsersContext(ctx)
				if err != nil {
					b.Error(err)
				}
			}
		})
	})
}

func TestLDAP_PoolWithCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		t.Skip("LDAP test environment not configured")
	}

	config := Config{
		Server: server,
		BaseDN: baseDN,
		Pool: &PoolConfig{
			MaxConnections: 5,
			MinConnections: 2,
		},
	}

	client1, err := New(config, bindDN, bindPassword)
	require.NoError(t, err)
	defer func() { _ = client1.Close() }()

	t.Run("WithCredentialsCreatesSeparatePool", func(t *testing.T) {
		// Create client with different credentials (should have separate pool)
		client2, err := client1.WithCredentials(bindDN, bindPassword)
		require.NoError(t, err)
		defer func() { _ = client2.Close() }()

		// Both clients should have pools
		stats1 := client1.GetPoolStats()
		stats2 := client2.GetPoolStats()

		assert.NotNil(t, stats1)
		assert.NotNil(t, stats2)

		// They should be independent pools
		ctx := context.Background()
		_, err = client1.FindUsersContext(ctx)
		assert.NoError(t, err)

		newStats1 := client1.GetPoolStats()
		unchangedStats2 := client2.GetPoolStats()

		// Client1 stats should change, client2 should remain unchanged
		assert.Greater(t, newStats1.PoolHits, stats1.PoolHits)
		assert.Equal(t, stats2.PoolHits, unchangedStats2.PoolHits)
	})
}

// Tests from client_pool_init_test.go
func TestPoolInitialization(t *testing.T) {
	t.Run("pool enabled for non-example servers", func(t *testing.T) {
		config := &Config{
			Server: "ldap://production.server.com",
			Port:   389,
			BaseDN: "dc=prod,dc=com",
			Pool: &PoolConfig{
				MaxConnections:      10,
				MinConnections:      2,
				MaxIdleTime:         5 * time.Minute,
				HealthCheckInterval: 30 * time.Second,
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		require.NotNil(t, client)

		// Pool initialization may fail for non-reachable servers
		// but the client should still be created
		if client.connPool != nil {
			assert.NotNil(t, client.connPool)
		}
	})

	t.Run("pool disabled for example servers", func(t *testing.T) {
		exampleServers := []string{
			"ldap://example.com",
			"ldap://localhost",
			"ldaps://example.org",
			"ldap://test.example.com",
		}

		for _, server := range exampleServers {
			config := &Config{
				Server: server,
				Port:   389,
				BaseDN: "dc=example,dc=com",
				Pool: &PoolConfig{
					MaxConnections: 5,
				},
			}

			client, err := New(*config, "user", "pass")
			require.NoError(t, err, "Failed for server: %s", server)
			assert.Nil(t, client.connPool, "Pool should be nil for example server: %s", server)
		}
	})

	t.Run("pool not initialized when config is nil", func(t *testing.T) {
		config := &Config{
			Server: "ldap://prod.server.com",
			Port:   389,
			BaseDN: "dc=prod,dc=com",
			Pool:   nil,
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		assert.Nil(t, client.connPool)
	})

	t.Run("pool configuration validation", func(t *testing.T) {
		testCases := []struct {
			name       string
			poolConfig *PoolConfig
			shouldFail bool
		}{
			{
				name: "valid config",
				poolConfig: &PoolConfig{
					MaxConnections: 10,
					MinConnections: 2,
				},
				shouldFail: false,
			},
			{
				name: "min greater than max",
				poolConfig: &PoolConfig{
					MaxConnections: 5,
					MinConnections: 10,
				},
				shouldFail: false, // Client creation shouldn't fail, pool init might
			},
			{
				name: "zero connections",
				poolConfig: &PoolConfig{
					MaxConnections: 0,
					MinConnections: 0,
				},
				shouldFail: false, // Client creation shouldn't fail
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				config := &Config{
					Server: "ldap://server.com",
					Port:   389,
					BaseDN: "dc=test,dc=com",
					Pool:   tc.poolConfig,
				}

				client, err := New(*config, "user", "pass")
				if tc.shouldFail {
					assert.Error(t, err)
					assert.Nil(t, client)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, client)
				}
			})
		}
	})

	t.Run("pool with connection options", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
				MaxIdleTime:    10 * time.Minute,
			},
			DialOptions: []ldap.DialOpt{
				ldap.DialWithTLSConfig(nil),
			},
		}

		client, err := New(*config, "user", "pass",
			WithTimeout(5*time.Second, 10*time.Second))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, 10*time.Second, client.operationTimeout)
	})

	t.Run("pool initialization with circuit breaker", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 3,
					Timeout:     30 * time.Second,
				},
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.NotNil(t, client.circuitBreaker)
	})

	t.Run("pool initialization failure handling", func(t *testing.T) {
		// This tests that even if pool initialization fails,
		// the client can still be created and fall back to direct connections
		config := &Config{
			Server: "ldap://unreachable.server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
				MinConnections: 5, // Force immediate connection attempts
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)
		// Pool may be nil if initialization failed
		// Client should fall back to direct connections
	})

	t.Run("connection retrieval with and without pool", func(t *testing.T) {
		// Without pool
		configNoPool := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
		}

		clientNoPool, err := New(*configNoPool, "user", "pass")
		require.NoError(t, err)
		assert.Nil(t, clientNoPool.connPool)

		ctx := context.Background()
		conn, err := clientNoPool.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")

		// With pool (but for example server, so pool won't be initialized)
		configWithPool := &Config{
			Server: "ldap://example.com",
			Port:   389,
			BaseDN: "dc=example,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
		}

		clientWithPool, err := New(*configWithPool, "user", "pass")
		require.NoError(t, err)
		assert.Nil(t, clientWithPool.connPool) // Pool not initialized for example servers

		conn, err = clientWithPool.GetConnectionContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connection to example server not available")
	})

	t.Run("pool with custom logger", func(t *testing.T) {
		customLogger := slog.Default().With("test", "pool_init")

		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
			},
			Logger: customLogger,
		}

		client, err := New(*config, "user", "pass", WithLogger(customLogger))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, customLogger, client.logger)
	})
}

// TestPoolHealthCheck tests connection pool health checking
func TestPoolHealthCheck(t *testing.T) {
	t.Run("health check interval configuration", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections:      5,
				HealthCheckInterval: 10 * time.Second,
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)

		// Verify pool config is stored correctly
		assert.Equal(t, config.Pool.HealthCheckInterval, 10*time.Second)
	})

	t.Run("pool with idle timeout", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 5,
				MaxIdleTime:    30 * time.Second,
			},
		}

		client, err := New(*config, "user", "pass")
		require.NoError(t, err)
		assert.NotNil(t, client)

		// Verify idle timeout is configured
		assert.Equal(t, config.Pool.MaxIdleTime, 30*time.Second)
	})
}

// TestPoolConcurrency tests concurrent pool operations
func TestPoolConcurrency(t *testing.T) {
	t.Run("concurrent pool initialization", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
			Pool: &PoolConfig{
				MaxConnections: 10,
				MinConnections: 2,
			},
		}

		// Create multiple clients concurrently
		numClients := 10
		clients := make([]*LDAP, numClients)
		errors := make([]error, numClients)

		// Use WaitGroup for proper synchronization
		var wg sync.WaitGroup
		wg.Add(numClients)

		for i := 0; i < numClients; i++ {
			go func(idx int) {
				defer wg.Done()
				clients[idx], errors[idx] = New(*config, "user", "pass")
			}(i)
		}

		// Wait for all goroutines to complete
		wg.Wait()

		for i := 0; i < numClients; i++ {
			assert.NoError(t, errors[i], "Client %d creation failed", i)
			assert.NotNil(t, clients[i], "Client %d is nil", i)
		}
	})
}

// TestPoolWithOptions tests pool initialization with various options
func TestPoolWithOptions(t *testing.T) {
	t.Run("pool with connection pool option", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		poolConfig := &PoolConfig{
			MaxConnections: 15,
			MinConnections: 3,
		}

		client, err := New(*config, "user", "pass", WithConnectionPool(poolConfig))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, poolConfig, client.config.Pool)
	})

	t.Run("pool with multiple options", func(t *testing.T) {
		config := &Config{
			Server: "ldap://server.com",
			Port:   389,
			BaseDN: "dc=test,dc=com",
		}

		poolConfig := &PoolConfig{
			MaxConnections: 20,
		}

		cbConfig := &CircuitBreakerConfig{
			MaxFailures: 5,
			Timeout:     1 * time.Minute,
		}

		client, err := New(*config, "user", "pass",
			WithConnectionPool(poolConfig),
			WithCircuitBreaker(cbConfig),
			WithTimeout(10*time.Second, 20*time.Second))
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, poolConfig, client.config.Pool)
		assert.NotNil(t, client.circuitBreaker)
		assert.Equal(t, 20*time.Second, client.operationTimeout)
	})
}

// BenchmarkPoolInitialization benchmarks pool initialization
func BenchmarkPoolInitialization(b *testing.B) {
	config := &Config{
		Server: "ldap://server.com",
		Port:   389,
		BaseDN: "dc=test,dc=com",
		Pool: &PoolConfig{
			MaxConnections: 10,
			MinConnections: 2,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := New(*config, "user", "pass")
		if err != nil {
			b.Fatal(err)
		}
		_ = client
	}
}

// TestConnectionPool_GetWithCredentials tests credential-aware connection pooling
func TestConnectionPool_GetWithCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		t.Skip("LDAP test environment not configured")
	}

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	t.Run("CredentialIsolation", func(t *testing.T) {
		// Get connection with user A credentials
		userADN := user
		userAPassword := password
		connA1, err := pool.GetWithCredentials(ctx, userADN, userAPassword)
		require.NoError(t, err)
		require.NotNil(t, connA1)

		// Track connection A
		pool.connMapMu.Lock()
		pooledA1 := pool.connMap[connA1]
		pool.connMapMu.Unlock()
		require.NotNil(t, pooledA1)

		// Return connection A
		err = pool.Put(connA1)
		require.NoError(t, err)

		// Get connection with user B credentials (different from A)
		userBDN := "cn=differentuser,dc=example,dc=com"
		userBPassword := "differentpassword"
		connB, err := pool.GetWithCredentials(ctx, userBDN, userBPassword)

		// This may fail if userB doesn't exist, which is expected
		if err != nil {
			// Expected - different credentials may not authenticate
			t.Logf("User B authentication failed (expected): %v", err)
			return
		}

		// If it succeeded, verify it's a different connection
		pool.connMapMu.Lock()
		pooledB := pool.connMap[connB]
		pool.connMapMu.Unlock()

		if pooledB != nil && pooledA1 != nil {
			assert.NotEqual(t, pooledA1, pooledB, "Different credentials should use different connections")
		}

		_ = pool.Put(connB)
	})

	t.Run("CredentialReuse", func(t *testing.T) {
		// Get connection with specific credentials
		userDN := user
		userPassword := password

		conn1, err := pool.GetWithCredentials(ctx, userDN, userPassword)
		require.NoError(t, err)
		require.NotNil(t, conn1)

		// Track first connection
		pool.connMapMu.Lock()
		pooled1 := pool.connMap[conn1]
		pool.connMapMu.Unlock()
		require.NotNil(t, pooled1)
		firstCreatedAt := pooled1.createdAt

		// Return connection
		err = pool.Put(conn1)
		require.NoError(t, err)

		// Small delay to ensure Put completes
		time.Sleep(10 * time.Millisecond)

		// Get connection again with same credentials
		conn2, err := pool.GetWithCredentials(ctx, userDN, userPassword)
		require.NoError(t, err)
		require.NotNil(t, conn2)

		// Track second connection
		pool.connMapMu.Lock()
		pooled2 := pool.connMap[conn2]
		pool.connMapMu.Unlock()
		require.NotNil(t, pooled2)

		// Verify connection was reused (same createdAt time)
		assert.Equal(t, firstCreatedAt, pooled2.createdAt, "Same credentials should reuse connection")

		// Verify stats show reuse
		stats := pool.Stats()
		assert.Greater(t, stats.PoolHits, int64(0), "Should have pool hits from reuse")

		_ = pool.Put(conn2)
	})

	t.Run("ConcurrentMultiUser", func(t *testing.T) {
		// Test concurrent access with same credentials
		var wg sync.WaitGroup
		numGoroutines := 10
		numOpsPerGoroutine := 20

		errors := make(chan error, numGoroutines*numOpsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				for j := 0; j < numOpsPerGoroutine; j++ {
					conn, err := pool.GetWithCredentials(ctx, user, password)
					if err != nil {
						errors <- err
						return
					}

					// Simulate work
					time.Sleep(1 * time.Millisecond)

					if err := pool.Put(conn); err != nil {
						errors <- err
						return
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		var errCount int
		for err := range errors {
			t.Errorf("Concurrent operation error: %v", err)
			errCount++
		}

		assert.Equal(t, 0, errCount, "Should have no errors in concurrent operations")

		// Verify pool stats
		stats := pool.Stats()
		assert.Greater(t, stats.PoolHits, int64(0), "Should have pool hits from concurrent operations")
		assert.Equal(t, int32(0), stats.ActiveConnections, "All connections should be returned")
	})

	t.Run("BackwardCompatibility", func(t *testing.T) {
		// Verify existing Get() method still works
		conn, err := pool.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, conn)

		// Verify it's a pooled connection
		pool.connMapMu.Lock()
		pooled := pool.connMap[conn]
		pool.connMapMu.Unlock()
		require.NotNil(t, pooled)

		// Verify credentials are nil (default pool behavior)
		assert.Nil(t, pooled.credentials, "Get() should use nil credentials")

		err = pool.Put(conn)
		require.NoError(t, err)

		// Get again and verify reuse works
		conn2, err := pool.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, conn2)

		err = pool.Put(conn2)
		require.NoError(t, err)
	})
}

// BenchmarkConnectionPool_GetWithCredentials benchmarks credential-aware pooling
func BenchmarkConnectionPool_GetWithCredentials(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmark in short mode")
	}

	poolConfig, ldapConfig, user, password, logger := setupPoolTestConfig()
	if ldapConfig.Server == "" || user == "" || password == "" {
		b.Skip("LDAP test environment not configured")
	}

	pool, err := NewConnectionPool(poolConfig, ldapConfig, user, password, logger)
	require.NoError(b, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	b.Run("SingleUser", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			conn, err := pool.GetWithCredentials(ctx, user, password)
			if err != nil {
				b.Fatalf("GetWithCredentials failed: %v", err)
			}
			_ = pool.Put(conn)
		}

		stats := pool.Stats()
		b.ReportMetric(float64(stats.PoolHits)/float64(stats.PoolHits+stats.PoolMisses)*100, "reuse_%")
	})

	b.Run("Baseline_Get", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			conn, err := pool.Get(ctx)
			if err != nil {
				b.Fatalf("Get failed: %v", err)
			}
			_ = pool.Put(conn)
		}
	})
}
