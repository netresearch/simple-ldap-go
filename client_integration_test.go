//go:build integration
// +build integration

package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegrationConnectionPool tests connection pooling with a real LDAP server
func TestIntegrationConnectionPool(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	container := SetupTestContainer(t)
	defer container.Close(t)

	t.Run("pool initialization and basic operations", func(t *testing.T) {
		config := &Config{
			Server: container.Config.Server,
			Port:   container.Config.Port,
			BaseDN: container.BaseDN,
			Pool: &PoolConfig{
				MaxConnections:      5,
				MinConnections:      2,
				MaxIdleTime:         5 * time.Minute,
				HealthCheckInterval: 30 * time.Second,
			},
		}

		client, err := New(*config, container.AdminUser, container.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Verify pool is initialized
		assert.NotNil(t, client.connPool)

		// Test getting a connection from pool
		conn, err := client.GetConnection()
		require.NoError(t, err)
		require.NotNil(t, conn)
		conn.Close()

		// Check pool statistics
		stats := client.GetPoolStats()
		assert.NotNil(t, stats)
	})

	t.Run("concurrent pool operations", func(t *testing.T) {
		config := &Config{
			Server: container.Config.Server,
			Port:   container.Config.Port,
			BaseDN: container.BaseDN,
			Pool: &PoolConfig{
				MaxConnections: 10,
				MinConnections: 3,
			},
		}

		client, err := New(*config, container.AdminUser, container.AdminPass)
		require.NoError(t, err)
		defer client.Close()

		// Run concurrent connection requests
		numGoroutines := 20
		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				conn, err := client.GetConnection()
				if err != nil {
					errChan <- err
					return
				}
				// Simulate some work
				time.Sleep(10 * time.Millisecond)
				conn.Close()
				errChan <- nil
			}()
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			assert.NoError(t, err)
		}
	})
}

// TestIntegrationCircuitBreaker tests circuit breaker with real network failures
func TestIntegrationCircuitBreaker(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	container := SetupTestContainer(t)
	defer container.Close(t)

	t.Run("circuit breaker protects against failures", func(t *testing.T) {
		// Create client with circuit breaker
		config := &Config{
			Server: container.Config.Server,
			Port:   container.Config.Port,
			BaseDN: container.BaseDN,
			Resilience: &ResilienceConfig{
				EnableCircuitBreaker: true,
				CircuitBreaker: &CircuitBreakerConfig{
					MaxFailures: 3,
					Timeout:     100 * time.Millisecond,
				},
			},
		}

		// Use wrong credentials to trigger failures
		client, err := New(*config, "wrong", "credentials")
		require.NoError(t, err)
		defer client.Close()

		// Attempt operations that will fail
		for i := 0; i < 3; i++ {
			_, err = client.GetConnection()
			assert.Error(t, err)
		}

		// Circuit should be open now
		stats := client.GetCircuitBreakerStats()
		assert.Equal(t, "OPEN", stats["state"])

		// Next attempt should fail fast
		start := time.Now()
		_, err = client.GetConnectionProtected()
		elapsed := time.Since(start)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circuit breaker")
		assert.Less(t, elapsed, 50*time.Millisecond)
	})
}

// TestIntegrationSearch tests search operations with real LDAP data
func TestIntegrationSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	container := SetupTestContainer(t)
	defer container.Close(t)

	// Add test data

	config := &Config{
		Server: container.Config.Server,
		Port:   container.Config.Port,
		BaseDN: container.BaseDN,
	}

	client, err := New(*config, container.AdminUser, container.AdminPass)
	require.NoError(t, err)
	defer client.Close()

	t.Run("SearchIter returns users", func(t *testing.T) {
		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			container.UsersOU,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=inetOrgPerson)",
			[]string{"cn", "sn", "mail"},
			nil,
		)

		count := 0
		for entry, err := range client.SearchIter(ctx, searchRequest) {
			if err != nil {
				t.Fatalf("Search iteration failed: %v", err)
			}
			assert.NotNil(t, entry)
			assert.NotEmpty(t, entry.DN)
			count++
		}
		assert.Greater(t, count, 0, "Should find at least one user")
	})

	t.Run("SearchPagedIter handles pagination", func(t *testing.T) {
		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			container.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		count := 0
		for entry, err := range client.SearchPagedIter(ctx, searchRequest, 2) {
			if err != nil {
				t.Fatalf("Paged search failed: %v", err)
			}
			assert.NotNil(t, entry)
			count++
		}
		assert.Greater(t, count, 0, "Should find entries")
	})

	t.Run("GroupMembersIter returns group members", func(t *testing.T) {
		ctx := context.Background()
		groupDN := fmt.Sprintf("cn=testgroup,%s", container.GroupsOU)

		count := 0
		for member, err := range client.GroupMembersIter(ctx, groupDN) {
			if err != nil {
				t.Fatalf("Group member iteration failed: %v", err)
			}
			assert.NotNil(t, member)
			assert.NotEmpty(t, member)
			count++
		}
		// We should have added members to the test group
		assert.Greater(t, count, 0, "Should find group members")
	})
}

// TestIntegrationAuthentication tests authentication flows
func TestIntegrationAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	container := SetupTestContainer(t)
	defer container.Close(t)

	// Add a test user

	t.Run("successful authentication", func(t *testing.T) {
		config := &Config{
			Server: container.Config.Server,
			Port:   container.Config.Port,
			BaseDN: container.BaseDN,
		}

		// Authenticate with test user
		userDN := fmt.Sprintf("cn=testuser,%s", container.UsersOU)
		client, err := New(*config, userDN, "testpass123")
		require.NoError(t, err)
		defer client.Close()

		// Verify we can perform operations
		conn, err := client.GetConnection()
		require.NoError(t, err)
		require.NotNil(t, conn)
		conn.Close()
	})

	t.Run("failed authentication", func(t *testing.T) {
		config := &Config{
			Server: container.Config.Server,
			Port:   container.Config.Port,
			BaseDN: container.BaseDN,
		}

		// Try with wrong password
		userDN := fmt.Sprintf("cn=testuser,%s", container.UsersOU)
		client, err := New(*config, userDN, "wrongpassword")
		require.NoError(t, err) // Client creation succeeds
		defer client.Close()

		// But connection should fail
		conn, err := client.GetConnection()
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "bind")
	})
}

// TestIntegrationContextHandling tests context cancellation and timeouts
func TestIntegrationContextHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	container := SetupTestContainer(t)
	defer container.Close(t)

	config := &Config{
		Server: container.Config.Server,
		Port:   container.Config.Port,
		BaseDN: container.BaseDN,
	}

	client, err := New(*config, container.AdminUser, container.AdminPass,
		WithTimeout(5*time.Second, 10*time.Second))
	require.NoError(t, err)
	defer client.Close()

	t.Run("context cancellation stops operations", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		searchRequest := ldap.NewSearchRequest(
			container.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		// Start search
		started := make(chan bool)
		errChan := make(chan error)

		go func() {
			started <- true
			for _, err := range client.SearchIter(ctx, searchRequest) {
				if err != nil {
					errChan <- err
					return
				}
			}
			errChan <- nil
		}()

		<-started
		cancel() // Cancel the context

		err := <-errChan
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("context timeout stops long operations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		searchRequest := ldap.NewSearchRequest(
			container.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"*"}, // Request all attributes to slow down
			nil,
		)

		start := time.Now()
		count := 0
		for _, err := range client.SearchPagedIter(ctx, searchRequest, 1) {
			if err != nil {
				elapsed := time.Since(start)
				assert.Contains(t, err.Error(), "deadline exceeded")
				assert.Less(t, elapsed, 200*time.Millisecond)
				break
			}
			count++
			// Simulate slow processing
			time.Sleep(50 * time.Millisecond)
		}
	})
}

// TestIntegrationPerformance runs performance benchmarks with real LDAP
func TestIntegrationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	container := SetupTestContainer(t)
	defer container.Close(t)

	// Add substantial test data

	t.Run("measure search performance", func(t *testing.T) {
		config := &Config{
			Server: container.Config.Server,
			Port:   container.Config.Port,
			BaseDN: container.BaseDN,
			Pool: &PoolConfig{
				MaxConnections: 10,
			},
			Performance: &PerformanceConfig{
				Enabled:            true,
				SlowQueryThreshold: 100 * time.Millisecond,
			},
		}

		client, err := New(*config, container.AdminUser, container.AdminPass,
			WithLogger(slog.Default()))
		require.NoError(t, err)
		defer client.Close()

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			container.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=inetOrgPerson)(cn=test*))",
			[]string{"cn", "sn", "mail"},
			nil,
		)

		// Warm up
		for i := 0; i < 5; i++ {
			for range client.SearchIter(ctx, searchRequest) {
				// Just iterate
			}
		}

		// Measure performance
		iterations := 10
		start := time.Now()
		for i := 0; i < iterations; i++ {
			count := 0
			for range client.SearchIter(ctx, searchRequest) {
				count++
			}
			assert.Greater(t, count, 0)
		}
		elapsed := time.Since(start)
		avgTime := elapsed / time.Duration(iterations)

		t.Logf("Average search time: %v", avgTime)
		assert.Less(t, avgTime, 500*time.Millisecond, "Search should be reasonably fast")

		// Check if performance monitoring was enabled
		if client.config.Performance != nil && client.config.Performance.Enabled {
			t.Logf("Performance monitoring enabled with threshold: %v", config.Performance.SlowQueryThreshold)
		}
	})
}

// BenchmarkIntegrationSearch benchmarks search operations
func BenchmarkIntegrationSearch(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	// SetupTestContainer expects *testing.T, so we convert
	t := &testing.T{}
	container := SetupTestContainer(t)
	defer container.Close(t)

	config := &Config{
		Server: container.Config.Server,
		Port:   container.Config.Port,
		BaseDN: container.BaseDN,
		Pool: &PoolConfig{
			MaxConnections: 10,
		},
	}

	client, err := New(*config, container.AdminUser, container.AdminPass)
	require.NoError(b, err)
	defer client.Close()

	ctx := context.Background()
	searchRequest := ldap.NewSearchRequest(
		container.UsersOU,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=inetOrgPerson)",
		[]string{"cn"},
		nil,
	)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			count := 0
			for range client.SearchIter(ctx, searchRequest) {
				count++
			}
			if count == 0 {
				b.Fatal("No results returned")
			}
		}
	})
}
