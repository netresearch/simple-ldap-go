package ldap

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestFindGroupsContextNoLeak verifies FindGroupsContext properly returns connections to pool
func TestFindGroupsContextNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ldapClient := setupTestLDAP(t)
	defer ldapClient.Close()

	// Get initial stats
	initialStats := ldapClient.pool.Stats()

	// Call FindGroups multiple times (simulating cache refresh)
	iterations := 10
	for i := 0; i < iterations; i++ {
		_, err := ldapClient.FindGroupsContext(context.Background())
		if err != nil {
			t.Fatalf("FindGroups iteration %d failed: %v", i, err)
		}
	}

	// Give a moment for connections to be returned
	time.Sleep(100 * time.Millisecond)

	// Check stats - no active connections should remain
	finalStats := ldapClient.pool.Stats()
	
	if finalStats.ActiveConnections > 0 {
		t.Errorf("Connection leak detected: %d active connections remain after FindGroups calls",
			finalStats.ActiveConnections)
	}

	if finalStats.IdleConnections == 0 {
		t.Errorf("No idle connections available after FindGroups calls - possible leak")
	}

	t.Logf("Stats after %d FindGroups calls: Active=%d, Idle=%d, Total=%d",
		iterations,
		finalStats.ActiveConnections,
		finalStats.IdleConnections,
		finalStats.TotalConnections)
}

// TestFindByDNContextNoLeak verifies findByDNContext properly returns connections to pool
func TestFindByDNContextNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ldapClient := setupTestLDAP(t)
	defer ldapClient.Close()

	// First find a group to get a valid DN
	groups, err := ldapClient.FindGroups()
	if err != nil || len(groups) == 0 {
		t.Skip("No groups available for DN search test")
	}
	testDN := groups[0].DN

	// Get initial stats
	initialStats := ldapClient.pool.Stats()

	// Call FindGroupByDN multiple times
	iterations := 10
	for i := 0; i < iterations; i++ {
		_, err := ldapClient.FindGroupByDNContext(context.Background(), testDN)
		if err != nil {
			t.Fatalf("FindGroupByDN iteration %d failed: %v", i, err)
		}
	}

	// Give a moment for connections to be returned
	time.Sleep(100 * time.Millisecond)

	// Check stats - no active connections should remain
	finalStats := ldapClient.pool.Stats()
	
	if finalStats.ActiveConnections > 0 {
		t.Errorf("Connection leak detected: %d active connections remain after FindGroupByDN calls",
			finalStats.ActiveConnections)
	}

	if finalStats.IdleConnections == 0 {
		t.Errorf("No idle connections available after FindGroupByDN calls - possible leak")
	}

	t.Logf("Stats after %d FindGroupByDN calls: Active=%d, Idle=%d, Total=%d",
		iterations,
		finalStats.ActiveConnections,
		finalStats.IdleConnections,
		finalStats.TotalConnections)
}

// TestSelfHealingPoolDetectsLeaks tests that the self-healing pool detects leaked connections
func TestSelfHealingPoolDetectsLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create pool with very short leak detection thresholds for testing
	config := DefaultPoolConfig()
	config.MaxConnections = 5
	config.EnableSelfHealing = true
	config.LeakDetectionThreshold = 500 * time.Millisecond
	config.LeakEvictionThreshold = 1 * time.Second

	ldapClient := setupTestLDAPWithConfig(t, config)
	defer ldapClient.Close()

	// Deliberately leak connections by not calling Put()
	ctx := context.Background()
	leakedCount := 3

	for i := 0; i < leakedCount; i++ {
		conn, err := ldapClient.pool.Get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		// Deliberately NOT calling pool.Put(conn) to simulate leak
		_ = conn
	}

	// Verify connections are marked as active (leaked)
	stats := ldapClient.pool.Stats()
	if stats.ActiveConnections != int32(leakedCount) {
		t.Errorf("Expected %d active connections, got %d", leakedCount, stats.ActiveConnections)
	}

	// Wait for leak detection and recovery
	// Wait for eviction threshold + some buffer for processing
	time.Sleep(config.LeakEvictionThreshold + 500*time.Millisecond)

	// Check that self-healing recovered the leaked connections
	finalStats := ldapClient.pool.Stats()
	
	if finalStats.LeakedConnections != int64(leakedCount) {
		t.Errorf("Expected %d leaked connections detected, got %d",
			leakedCount, finalStats.LeakedConnections)
	}

	if finalStats.SelfHealingEvents != int64(leakedCount) {
		t.Errorf("Expected %d self-healing events, got %d",
			leakedCount, finalStats.SelfHealingEvents)
	}

	// Verify active connections were cleaned up
	if finalStats.ActiveConnections > 0 {
		t.Errorf("Expected 0 active connections after self-healing, got %d",
			finalStats.ActiveConnections)
	}

	t.Logf("Self-healing successfully detected and recovered %d leaked connections", leakedCount)
	t.Logf("Final stats: Active=%d, Leaked=%d, SelfHealing=%d",
		finalStats.ActiveConnections,
		finalStats.LeakedConnections,
		finalStats.SelfHealingEvents)
}

// TestSelfHealingDisabled verifies that leak detection can be disabled
func TestSelfHealingDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create pool with self-healing disabled
	config := DefaultPoolConfig()
	config.MaxConnections = 5
	config.EnableSelfHealing = false
	config.LeakDetectionThreshold = 500 * time.Millisecond
	config.LeakEvictionThreshold = 1 * time.Second

	ldapClient := setupTestLDAPWithConfig(t, config)
	defer ldapClient.Close()

	// Deliberately leak a connection
	ctx := context.Background()
	conn, err := ldapClient.pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	_ = conn // Deliberately NOT calling pool.Put(conn)

	// Wait past eviction threshold
	time.Sleep(config.LeakEvictionThreshold + 500*time.Millisecond)

	// Verify NO self-healing occurred
	stats := ldapClient.pool.Stats()
	
	if stats.LeakedConnections != 0 {
		t.Errorf("Expected 0 leaked connections (self-healing disabled), got %d",
			stats.LeakedConnections)
	}

	if stats.SelfHealingEvents != 0 {
		t.Errorf("Expected 0 self-healing events (self-healing disabled), got %d",
			stats.SelfHealingEvents)
	}

	// The connection should still be marked as active (leaked but not recovered)
	if stats.ActiveConnections != 1 {
		t.Errorf("Expected 1 active leaked connection, got %d", stats.ActiveConnections)
	}

	t.Logf("Verified self-healing is properly disabled when EnableSelfHealing=false")
}

// TestConcurrentFindGroupsNoLeak tests FindGroups under concurrent load
func TestConcurrentFindGroupsNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ldapClient := setupTestLDAP(t)
	defer ldapClient.Close()

	// Run concurrent FindGroups operations
	concurrency := 10
	iterations := 5
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, err := ldapClient.FindGroupsContext(context.Background())
				if err != nil {
					t.Errorf("Worker %d iteration %d failed: %v", workerID, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Give time for all connections to be returned
	time.Sleep(200 * time.Millisecond)

	// Verify no leaks under concurrent load
	stats := ldapClient.pool.Stats()
	
	if stats.ActiveConnections > 0 {
		t.Errorf("Connection leak under concurrent load: %d active connections remain", 
			stats.ActiveConnections)
	}

	t.Logf("Concurrent test completed: %d workers × %d iterations = %d total calls",
		concurrency, iterations, concurrency*iterations)
	t.Logf("Final stats: Active=%d, Idle=%d, PoolHits=%d",
		stats.ActiveConnections,
		stats.IdleConnections,
		stats.PoolHits)
}

// Helper function to create LDAP client with default config for testing
func setupTestLDAP(t *testing.T) *LDAP {
	config := DefaultPoolConfig()
	return setupTestLDAPWithConfig(t, config)
}

// Helper function to create LDAP client with custom pool config for testing
func setupTestLDAPWithConfig(t *testing.T, poolConfig *PoolConfig) *LDAP {
	// Use environment variables or test config for LDAP connection
	// This assumes LDAP_TEST_SERVER, LDAP_TEST_PORT, etc. are set
	cfg := &Config{
		Server:   getEnvOrDefault("LDAP_TEST_SERVER", "localhost"),
		Port:     getEnvOrDefaultInt("LDAP_TEST_PORT", 389),
		BaseDN:   getEnvOrDefault("LDAP_TEST_BASEDN", "dc=example,dc=com"),
		BindDN:   getEnvOrDefault("LDAP_TEST_BINDDN", "cn=admin,dc=example,dc=com"),
		Password: getEnvOrDefault("LDAP_TEST_PASSWORD", "admin"),
		UseSSL:   false,
		PoolConfig: poolConfig,
	}

	ldapClient, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create LDAP client: %v", err)
	}

	return ldapClient
}

func getEnvOrDefault(key, defaultValue string) string {
	// Simple helper - in real tests you'd use os.Getenv
	return defaultValue
}

func getEnvOrDefaultInt(key string, defaultValue int) int {
	// Simple helper - in real tests you'd use os.Getenv and strconv
	return defaultValue
}
