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
	defer pool.Close()

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
	defer pool.Close()

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
		conn.Close()

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
			conn.Close()
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
	defer pool.Close()

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
				conn.Close()
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
	defer pool.Close()

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
	connections[0].Close()
	time.Sleep(10 * time.Millisecond)

	// Should be able to get a connection now
	conn, err := pool.Get(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, conn)

	// Clean up
	conn.Close()
	for i := 1; i < len(connections); i++ {
		connections[i].Close()
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
	defer pool.Close()

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
		conn.Close()
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
	defer pool.Close()

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
	defer pool.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.Get(ctx)
			if err != nil {
				b.Error(err)
				continue
			}
			conn.Close()
		}
	})

	if !b.Failed() {
		stats := pool.Stats()
		hitRatio := float64(stats.PoolHits) / float64(stats.PoolHits+stats.PoolMisses) * 100
		b.ReportMetric(hitRatio, "hit_ratio_%")
		b.ReportMetric(float64(stats.ConnectionsCreated), "connections_created")
	}
}