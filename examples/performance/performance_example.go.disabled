package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/netresearch/simple-ldap-go"
)

func main() {
	// Example demonstrating performance optimization features
	// including intelligent caching, performance monitoring, and bulk operations

	// Configure LDAP client with performance optimizations
	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,

		// Connection pooling for high-volume applications
		Pool: &ldap.PoolConfig{
			MaxConnections:      20,
			MinConnections:      5,
			MaxIdleTime:         10 * time.Minute,
			HealthCheckInterval: 30 * time.Second,
			ConnectionTimeout:   30 * time.Second,
			GetTimeout:          10 * time.Second,
		},

		// Intelligent caching for read-heavy workloads
		Cache: &ldap.CacheConfig{
			Enabled:              true,
			TTL:                  5 * time.Minute,
			MaxSize:              1000,
			RefreshInterval:      1 * time.Minute,
			RefreshOnAccess:      true,
			NegativeCacheTTL:     30 * time.Second,
			MaxMemoryMB:          64,
			CompressionEnabled:   false,
			CompressionThreshold: 1024,
		},

		// Performance monitoring
		Performance: &ldap.PerformanceConfig{
			Enabled:                true,
			MetricsRetentionPeriod: 1 * time.Hour,
			SlowQueryThreshold:     500 * time.Millisecond,
			SampleRate:             1.0, // Monitor 100% of operations
			MaxSearchResults:       0,   // No limit
			SearchTimeout:          30 * time.Second,
			EnablePrefetch:         false,
			EnableBulkOperations:   true,
		},
	}

	// Create LDAP client
	client, err := ldap.New(&config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		log.Fatalf("Failed to create LDAP client: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	// Demonstrate optimized user operations
	demonstrateUserOperations(client, ctx)

	// Demonstrate bulk operations
	demonstrateBulkOperations(client, ctx)

	// Demonstrate performance monitoring
	demonstratePerformanceMonitoring(client)

	// Demonstrate cache management
	demonstrateCacheManagement(client)

	// Demonstrate configuration examples for different use cases
	demonstrateConfigurationExamples()
}

func demonstrateUserOperations(client *ldap.LDAP, ctx context.Context) {
	fmt.Println("\n=== Optimized User Operations ===")

	// Configure search options
	searchOptions := &ldap.SearchOptions{
		RefreshStale:     true,
		UseNegativeCache: true,
		MaxResults:       100,
		Timeout:          10 * time.Second,
		AttributeFilter:  nil, // Get all attributes
	}

	// First lookup - will hit LDAP server and cache result
	start := time.Now()
	user, err := client.FindUserBySAMAccountNameOptimized(ctx, "jdoe", searchOptions)
	firstLookupDuration := time.Since(start)

	if err != nil {
		if err == ldap.ErrUserNotFound {
			fmt.Println("User 'jdoe' not found")
		} else {
			log.Printf("First lookup error: %v", err)
		}
	} else {
		fmt.Printf("First lookup (cache miss): %v - Found user %s (%s)\n",
			firstLookupDuration, user.CN(), user.SAMAccountName)
	}

	// Second lookup - should hit cache and be much faster
	start = time.Now()
	user, err = client.FindUserBySAMAccountNameOptimized(ctx, "jdoe", searchOptions)
	secondLookupDuration := time.Since(start)

	if err == nil && user != nil {
		fmt.Printf("Second lookup (cache hit): %v - Found user %s (%s)\n",
			secondLookupDuration, user.CN(), user.SAMAccountName)

		speedup := float64(firstLookupDuration) / float64(secondLookupDuration)
		fmt.Printf("Cache speedup: %.1fx faster\n", speedup)
	}

	// Lookup by DN (should also hit cache due to multi-key caching)
	if user != nil {
		start = time.Now()
		userByDN, err := client.FindUserByDNOptimized(ctx, user.DN(), searchOptions)
		dnLookupDuration := time.Since(start)

		if err == nil && userByDN != nil {
			fmt.Printf("DN lookup (cache hit): %v - Found user %s\n",
				dnLookupDuration, userByDN.CN())
		}
	}

	// Get all users with caching
	start = time.Now()
	users, err := client.FindUsersOptimized(ctx, searchOptions)
	if err != nil {
		log.Printf("Error finding users: %v", err)
	} else {
		duration := time.Since(start)
		fmt.Printf("Found %d users in %v\n", len(users), duration)
	}
}

func demonstrateBulkOperations(client *ldap.LDAP, ctx context.Context) {
	fmt.Println("\n=== Bulk Operations ===")

	// List of users to look up
	samAccountNames := []string{
		"jdoe", "asmith", "bwilson", "mjohnson", "djones",
		"kwilliams", "rbrown", "sdavis", "tmiller", "lwilson",
	}

	bulkOptions := &ldap.BulkSearchOptions{
		BatchSize:       3, // Process 3 at a time
		Timeout:         2 * time.Minute,
		ContinueOnError: true,
		UseCache:        true,
		CachePrefix:     "bulk_demo",
	}

	start := time.Now()
	results, err := client.BulkFindUsersBySAMAccountName(ctx, samAccountNames, bulkOptions)
	duration := time.Since(start)

	if err != nil {
		log.Printf("Bulk operation error: %v", err)
	}

	found := 0
	notFound := 0
	for samAccountName, user := range results {
		if user != nil {
			found++
			fmt.Printf("  ✓ Found %s: %s\n", samAccountName, user.CN())
		} else {
			notFound++
			fmt.Printf("  ✗ Not found: %s\n", samAccountName)
		}
	}

	fmt.Printf("Bulk lookup completed in %v: %d found, %d not found\n",
		duration, found, notFound)
}

func demonstratePerformanceMonitoring(client *ldap.LDAP) {
	fmt.Println("\n=== Performance Statistics ===")

	// Get comprehensive performance stats
	perfStats := client.GetPerformanceStats()

	fmt.Printf("Operations Total: %d\n", perfStats.OperationsTotal)
	fmt.Printf("Cache Hit Ratio: %.1f%%\n", perfStats.CacheHitRatio)
	fmt.Printf("Average Response Time: %v\n", perfStats.AvgResponseTime)
	fmt.Printf("P95 Response Time: %v\n", perfStats.P95ResponseTime)
	fmt.Printf("P99 Response Time: %v\n", perfStats.P99ResponseTime)
	fmt.Printf("Slow Queries: %d\n", perfStats.SlowQueries)
	fmt.Printf("Error Count: %d\n", perfStats.ErrorCount)
	fmt.Printf("Connection Pool Hit Ratio: %.1f%%\n", perfStats.ConnectionPoolRatio)

	// Operations by type
	fmt.Println("\nOperations by Type:")
	for opType, count := range perfStats.OperationsByType {
		fmt.Printf("  %s: %d operations\n", opType, count)
	}

	// Slow queries by type
	if len(perfStats.SlowQueriesByType) > 0 {
		fmt.Println("\nSlow Queries by Type:")
		for opType, count := range perfStats.SlowQueriesByType {
			fmt.Printf("  %s: %d slow queries\n", opType, count)
		}
	}

	// Recent slow operations
	if len(perfStats.TopSlowOperations) > 0 {
		fmt.Println("\nTop Slow Operations:")
		for i, op := range perfStats.TopSlowOperations {
			if i >= 5 { // Show top 5
				break
			}
			errorMsg := "success"
			if op.ErrorMessage != "" {
				errorMsg = op.ErrorMessage
			}
			fmt.Printf("  %d. %s - %v - %s\n", i+1, op.Operation, op.Duration, errorMsg)
		}
	}

	// Memory usage
	fmt.Printf("\nMemory Usage: %.1f MB\n", perfStats.MemoryUsageMB)
	fmt.Printf("Goroutine Count: %d\n", perfStats.GoroutineCount)
}

func demonstrateCacheManagement(client *ldap.LDAP) {
	fmt.Println("\n=== Cache Statistics ===")

	// Get cache statistics
	cacheStats := client.GetCacheStats()

	fmt.Printf("Cache Hits: %d\n", cacheStats.Hits)
	fmt.Printf("Cache Misses: %d\n", cacheStats.Misses)
	fmt.Printf("Hit Ratio: %.1f%%\n", cacheStats.HitRatio)
	fmt.Printf("Total Entries: %d\n", cacheStats.TotalEntries)
	fmt.Printf("Max Entries: %d\n", cacheStats.MaxEntries)
	fmt.Printf("Memory Usage: %.1f MB\n", cacheStats.MemoryUsageMB)
	fmt.Printf("Average Get Time: %v\n", cacheStats.AvgGetTime)
	fmt.Printf("Average Set Time: %v\n", cacheStats.AvgSetTime)
	fmt.Printf("Evictions: %d\n", cacheStats.Evictions)
	fmt.Printf("Expirations: %d\n", cacheStats.Expirations)
	fmt.Printf("Negative Hits: %d\n", cacheStats.NegativeHits)
	fmt.Printf("Negative Entries: %d\n", cacheStats.NegativeEntries)
	fmt.Printf("Background Refreshes: %d\n", cacheStats.RefreshOps)
	fmt.Printf("Background Cleanups: %d\n", cacheStats.CleanupOps)

	// Get connection pool statistics
	poolStats := client.GetPoolStats()
	fmt.Println("\n=== Connection Pool Statistics ===")
	fmt.Printf("Active Connections: %d\n", poolStats.ActiveConnections)
	fmt.Printf("Idle Connections: %d\n", poolStats.IdleConnections)
	fmt.Printf("Total Connections: %d\n", poolStats.TotalConnections)
	fmt.Printf("Pool Hits: %d\n", poolStats.PoolHits)
	fmt.Printf("Pool Misses: %d\n", poolStats.PoolMisses)
	fmt.Printf("Health Checks Passed: %d\n", poolStats.HealthChecksPassed)
	fmt.Printf("Health Checks Failed: %d\n", poolStats.HealthChecksFailed)
	fmt.Printf("Connections Created: %d\n", poolStats.ConnectionsCreated)
	fmt.Printf("Connections Closed: %d\n", poolStats.ConnectionsClosed)

	// Demonstrate cache clearing
	fmt.Println("\nClearing cache...")
	// ClearCache() method would be called here if implemented
	// client.ClearCache()

	// Show stats after clearing
	cacheStats = client.GetCacheStats()
	fmt.Printf("Cache entries after clear: %d\n", cacheStats.TotalEntries)
}

// Example showing configuration for different use cases
func demonstrateConfigurationExamples() {
	fmt.Println("\n=== Configuration Examples ===")

	// High-performance read-heavy workload
	highPerfConfig := ldap.Config{
		Server: "ldaps://ad.example.com:636",
		BaseDN: "DC=example,DC=com",

		Pool: &ldap.PoolConfig{
			MaxConnections: 50,
			MinConnections: 10,
			MaxIdleTime:    5 * time.Minute,
		},

		Cache: &ldap.CacheConfig{
			Enabled:              true,
			TTL:                  10 * time.Minute,
			MaxSize:              5000,
			RefreshOnAccess:      true,
			NegativeCacheTTL:     1 * time.Minute,
			MaxMemoryMB:          128,
			CompressionEnabled:   true,
			CompressionThreshold: 512,
		},

		Performance: &ldap.PerformanceConfig{
			Enabled:              true,
			SlowQueryThreshold:   200 * time.Millisecond,
			EnableBulkOperations: true,
			EnablePrefetch:       true,
		},
	}

	fmt.Printf("High-performance config: Pool=%d, Cache=%d entries, %d MB\n",
		highPerfConfig.Pool.MaxConnections,
		highPerfConfig.Cache.MaxSize,
		highPerfConfig.Cache.MaxMemoryMB)

	// Memory-constrained environment
	lowMemoryConfig := ldap.Config{
		Server: "ldap://internal.example.com:389",
		BaseDN: "DC=internal,DC=com",

		Pool: &ldap.PoolConfig{
			MaxConnections: 5,
			MinConnections: 2,
			MaxIdleTime:    2 * time.Minute,
		},

		Cache: &ldap.CacheConfig{
			Enabled:              true,
			TTL:                  2 * time.Minute,
			MaxSize:              100,
			MaxMemoryMB:          8,
			CompressionEnabled:   true,
			CompressionThreshold: 256,
		},

		Performance: &ldap.PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 1 * time.Second,
			SampleRate:         0.1, // Sample 10% to reduce overhead
		},
	}

	fmt.Printf("Low-memory config: Pool=%d, Cache=%d entries, %d MB\n",
		lowMemoryConfig.Pool.MaxConnections,
		lowMemoryConfig.Cache.MaxSize,
		lowMemoryConfig.Cache.MaxMemoryMB)

	// Write-heavy workload (minimal caching)
	writeHeavyConfig := ldap.Config{
		Server: "ldaps://ad.example.com:636",
		BaseDN: "DC=example,DC=com",

		Pool: &ldap.PoolConfig{
			MaxConnections: 20,
			MinConnections: 5,
		},

		Cache: &ldap.CacheConfig{
			Enabled:          true,
			TTL:              30 * time.Second, // Short TTL for write-heavy
			MaxSize:          500,
			NegativeCacheTTL: 10 * time.Second,
			MaxMemoryMB:      32,
		},

		Performance: &ldap.PerformanceConfig{
			Enabled:              true,
			SlowQueryThreshold:   100 * time.Millisecond,
			EnableBulkOperations: true,
		},
	}

	fmt.Printf("Write-heavy config: TTL=%v, Cache=%d entries\n",
		writeHeavyConfig.Cache.TTL,
		writeHeavyConfig.Cache.MaxSize)
}
