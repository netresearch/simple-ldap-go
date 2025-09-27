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

	client, err := New(&config, bindDN, bindPassword)
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

	client, err := New(&config, bindDN, bindPassword)
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

	client, err := New(&config, bindDN, bindPassword)
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

		client, err := New(&config, bindDN, bindPassword)
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

		client, err := New(&config, bindDN, bindPassword)
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

	client1, err := New(&config, bindDN, bindPassword)
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
