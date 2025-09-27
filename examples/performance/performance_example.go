package main

import (
	"context"
	"fmt"
	"log"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
	// Example demonstrating performance optimization features
	// including connection pooling, intelligent caching, and bulk operations

	// Configure LDAP client with performance optimizations
	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,

		// Enable optimizations through feature flags
		EnableOptimizations: true, // Enable all optimizations
		EnableCache:         true, // Enable caching
		EnableMetrics:       true, // Enable performance metrics
		EnableBulkOps:       true, // Enable bulk operations
	}

	// Create high-performance LDAP client with advanced features
	client, err := ldap.New(config, "CN=admin,CN=Users,DC=example,DC=com", "password",
		// Connection pooling for high-volume applications
		ldap.WithConnectionPool(&ldap.PoolConfig{
			MaxConnections: 20,
			MinConnections: 5,
			MaxIdleTime:    10 * time.Minute,
		}),

		// Intelligent caching for read-heavy workloads
		ldap.WithCache(&ldap.CacheConfig{
			Enabled:     true,
			TTL:         5 * time.Minute,
			MaxSize:     1000,
			MaxMemoryMB: 64,
		}),

		// Circuit breaker for resilience
		ldap.WithCircuitBreaker(&ldap.CircuitBreakerConfig{
			MaxFailures: 5,
			Timeout:     30 * time.Second,
		}),
	)

	if err != nil {
		log.Fatalf("Failed to create LDAP client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("Failed to close client: %v", err)
		}
	}()

	ctx := context.Background()

	// Demonstrate optimized user operations
	demonstrateUserOperations(client, ctx)

	// Demonstrate bulk operations
	demonstrateBulkOperations(client, ctx)

	// Demonstrate performance monitoring
	demonstratePerformanceMonitoring(client)

	// Demonstrate cache management
	demonstrateCacheManagement(client)

	// Demonstrate convenience methods for client creation
	demonstrateConvenienceMethods(ctx)

	// Demonstrate configuration examples for different use cases
	demonstrateConfigurationExamples()
}

func demonstrateUserOperations(client *ldap.LDAP, ctx context.Context) {
	fmt.Println("\n=== Optimized User Operations ===")
	fmt.Println("Note: Caching is transparently enabled via config.EnableCache")

	// First lookup - will hit LDAP server and cache result (if caching is enabled)
	start := time.Now()
	user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
	firstLookupDuration := time.Since(start)

	if err != nil {
		if err == ldap.ErrUserNotFound {
			fmt.Println("User 'jdoe' not found")
		} else {
			log.Printf("First lookup error: %v", err)
		}
	} else {
		fmt.Printf("First lookup: %v - Found user %s (%s)\n",
			firstLookupDuration, user.CN(), user.SAMAccountName)
	}

	// Second lookup - should hit cache and be much faster (if caching is enabled)
	start = time.Now()
	user, err = client.FindUserBySAMAccountNameContext(ctx, "jdoe")
	secondLookupDuration := time.Since(start)

	if err == nil && user != nil {
		fmt.Printf("Second lookup (likely cached): %v - Found user %s (%s)\n",
			secondLookupDuration, user.CN(), user.SAMAccountName)

		if secondLookupDuration > 0 && secondLookupDuration < firstLookupDuration {
			speedup := float64(firstLookupDuration) / float64(secondLookupDuration)
			fmt.Printf("Cache speedup: %.1fx faster\n", speedup)
		}
	}

	// Lookup by DN - uses transparent caching if enabled
	if user != nil {
		start = time.Now()
		userByDN, err := client.FindUserByDNContext(ctx, user.DN())
		dnLookupDuration := time.Since(start)

		if err == nil && userByDN != nil {
			fmt.Printf("DN lookup: %v - Found user %s\n",
				dnLookupDuration, userByDN.CN())
		}
	}

	// Get all users
	start = time.Now()
	users, err := client.FindUsers()
	if err != nil {
		log.Printf("Error finding users: %v", err)
	} else {
		duration := time.Since(start)
		fmt.Printf("Found %d users in %v\n", len(users), duration)
	}

}

func demonstrateConvenienceMethods(ctx context.Context) {
	fmt.Println("\n=== Convenience Client Constructors ===")

	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
	}

	// High-performance client with all optimizations
	fmt.Println("Creating high-performance client...")
	highPerfClient, err := ldap.NewHighPerformanceClient(config, "admin", "password")
	if err != nil {
		log.Printf("Failed to create high-performance client: %v", err)
	} else {
		defer func() {
			if err := highPerfClient.Close(); err != nil {
				log.Printf("Failed to close high-perf client: %v", err)
			}
		}()
		fmt.Println("✓ High-performance client created successfully")
	}

	// Cached client
	fmt.Println("Creating cached client...")
	cachedClient, err := ldap.NewCachedClient(config, "admin", "password", 1000, 5*time.Minute)
	if err != nil {
		log.Printf("Failed to create cached client: %v", err)
	} else {
		defer func() {
			if err := cachedClient.Close(); err != nil {
				log.Printf("Failed to close cached client: %v", err)
			}
		}()
		fmt.Println("✓ Cached client created successfully")
	}

	// Pooled client
	fmt.Println("Creating pooled client...")
	pooledClient, err := ldap.NewPooledClient(config, "admin", "password", 10)
	if err != nil {
		log.Printf("Failed to create pooled client: %v", err)
	} else {
		defer func() {
			if err := pooledClient.Close(); err != nil {
				log.Printf("Failed to close pooled client: %v", err)
			}
		}()
		fmt.Println("✓ Pooled client created successfully")
	}
}

func demonstrateBulkOperations(client *ldap.LDAP, ctx context.Context) {
	fmt.Println("\n=== Bulk Operations ===")

	// List of users to look up
	samAccountNames := []string{
		"admin", "user1", "user2", "nonexistent",
	}

	bulkOptions := &ldap.BulkSearchOptions{
		BatchSize:      2, // Process 2 at a time
		MaxConcurrency: 2,
		UseCache:       true,
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
	fmt.Println("\n=== Performance Features ===")

	fmt.Println("This client is configured with:")
	fmt.Println("✓ Connection pooling for efficient connection reuse")
	fmt.Println("✓ Intelligent caching for reduced LDAP server load")
	fmt.Println("✓ Circuit breaker for resilience during outages")
	fmt.Println("✓ Performance metrics collection")
	fmt.Println("✓ Bulk operations support")

	// Note: In a real implementation, you would have methods like:
	// - client.GetPerformanceStats()
	// - client.GetCacheStats()
	// - client.GetPoolStats()

	fmt.Println("\nPerformance monitoring includes:")
	fmt.Println("- Response time tracking")
	fmt.Println("- Cache hit/miss ratios")
	fmt.Println("- Connection pool utilization")
	fmt.Println("- Error rate monitoring")
	fmt.Println("- Slow query detection")
}

func demonstrateCacheManagement(client *ldap.LDAP) {
	fmt.Println("\n=== Cache Management ===")

	fmt.Println("Cache features enabled:")
	fmt.Println("✓ LRU (Least Recently Used) eviction")
	fmt.Println("✓ TTL (Time To Live) expiration")
	fmt.Println("✓ Memory usage limits")
	fmt.Println("✓ Multi-key caching (by DN, SAMAccountName, etc.)")
	fmt.Println("✓ Negative caching for 'not found' results")

	// Note: In a real implementation, you would have methods like:
	// - client.ClearCache()
	// - client.GetCacheStats()
	// - client.RefreshCacheEntry(key)
}

// Example showing configuration for different use cases
func demonstrateConfigurationExamples() {
	fmt.Println("\n=== Configuration Examples ===")

	baseConfig := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
	}

	// Example 1: High-performance read-heavy workload
	fmt.Println("\n1. High-Performance Configuration:")
	fmt.Println("   For read-heavy applications with many concurrent users")

	highPerfConfig := baseConfig
	highPerfConfig.EnableOptimizations = true
	highPerfConfig.EnableCache = true
	highPerfConfig.EnableMetrics = true
	highPerfConfig.EnableBulkOps = true

	// Would create with:
	// client, _ := ldap.New(highPerfConfig, username, password,
	//     ldap.WithConnectionPool(&ldap.PoolConfig{MaxConnections: 50}),
	//     ldap.WithCache(&ldap.CacheConfig{MaxSize: 5000, TTL: 10*time.Minute}),
	// )

	fmt.Println("   ✓ Connection pool: 50 connections")
	fmt.Println("   ✓ Large cache: 5000 entries, 10-minute TTL")
	fmt.Println("   ✓ All optimizations enabled")

	// Example 2: Memory-constrained environment
	fmt.Println("\n2. Memory-Constrained Configuration:")
	fmt.Println("   For resource-limited environments")

	lowMemoryConfig := baseConfig
	lowMemoryConfig.EnableCache = true // Selective optimization

	// Would create with:
	// client, _ := ldap.New(lowMemoryConfig, username, password,
	//     ldap.WithConnectionPool(&ldap.PoolConfig{MaxConnections: 5}),
	//     ldap.WithCache(&ldap.CacheConfig{MaxSize: 100, MaxMemoryMB: 8}),
	// )

	fmt.Println("   ✓ Small connection pool: 5 connections")
	fmt.Println("   ✓ Limited cache: 100 entries, 8MB limit")
	fmt.Println("   ✓ Selective optimizations")

	// Example 3: Write-heavy workload
	fmt.Println("\n3. Write-Heavy Configuration:")
	fmt.Println("   For applications with frequent updates")

	writeHeavyConfig := baseConfig
	writeHeavyConfig.EnableBulkOps = true // Only bulk operations

	// Would create with:
	// client, _ := ldap.New(writeHeavyConfig, username, password,
	//     ldap.WithConnectionPool(&ldap.PoolConfig{MaxConnections: 20}),
	//     ldap.WithCache(&ldap.CacheConfig{TTL: 30*time.Second}), // Short TTL
	// )

	fmt.Println("   ✓ Medium connection pool: 20 connections")
	fmt.Println("   ✓ Short-lived cache: 30-second TTL")
	fmt.Println("   ✓ Bulk operations for efficiency")

	// Example 4: Convenience constructors
	fmt.Println("\n4. Convenience Constructors:")
	fmt.Println("   Quick setup for common scenarios")

	fmt.Println("   - ldap.NewBasicClient()        → No optimizations")
	fmt.Println("   - ldap.NewCachedClient()       → With caching")
	fmt.Println("   - ldap.NewPooledClient()       → With connection pooling")
	fmt.Println("   - ldap.NewHighPerformanceClient() → All optimizations")
}
