package ldap_test

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"sync"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
)

// Example_connectionPooling demonstrates how to use connection pooling
// for high-performance LDAP operations
func Example_connectionPooling() {
	// Configure connection pooling for high-volume scenarios
	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
		Pool: &ldap.PoolConfig{
			MaxConnections:      20,               // Maximum concurrent connections
			MinConnections:      5,                // Keep 5 connections ready
			MaxIdleTime:         10 * time.Minute, // Close idle connections after 10min
			HealthCheckInterval: 30 * time.Second, // Check connection health every 30s
			ConnectionTimeout:   10 * time.Second, // Timeout for new connections
			GetTimeout:          5 * time.Second,  // Timeout for getting from pool
		},
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}

	// Create client with connection pooling
	client, err := ldap.New(&config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }() // Important: Close to cleanup all pooled connections

	// Perform operations - connections will be reused from the pool
	ctx := context.Background()

	// Single operation
	users, err := client.FindUsersContext(ctx)
	if err != nil {
		log.Printf("Error finding users: %v", err)
		return
	}
	fmt.Printf("Found %d users\n", len(users))

	// Check pool statistics
	stats := client.GetPoolStats()
	fmt.Printf("Pool stats: %d active, %d idle, %d total connections\n",
		stats.ActiveConnections, stats.IdleConnections, stats.TotalConnections)
	fmt.Printf("Pool efficiency: %d hits, %d misses (%.1f%% hit ratio)\n",
		stats.PoolHits, stats.PoolMisses,
		float64(stats.PoolHits)/float64(stats.PoolHits+stats.PoolMisses)*100)

	// Output:
	// Found 150 users
	// Pool stats: 0 active, 5 idle, 5 total connections
	// Pool efficiency: 1 hits, 1 misses (50.0% hit ratio)
}

// Example_concurrentOperations shows how connection pooling improves
// performance under high concurrency
func Example_concurrentOperations() {
	config := ldap.Config{
		Server: "ldap://localhost:389",
		BaseDN: "dc=example,dc=org",
		Pool: &ldap.PoolConfig{
			MaxConnections: 15,
			MinConnections: 3,
		},
	}

	client, err := ldap.New(&config, "cn=admin,dc=example,dc=org", "password")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	// Simulate high-concurrency scenario
	const numWorkers = 20
	const operationsPerWorker = 10

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			ctx := context.Background()
			for j := 0; j < operationsPerWorker; j++ {
				// Each operation will reuse connections from the pool
				users, err := client.FindUsersContext(ctx)
				if err != nil {
					log.Printf("Worker %d error: %v", workerID, err)
					continue
				}
				log.Printf("Worker %d found %d users (operation %d)", workerID, len(users), j+1)
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	// Display performance results
	fmt.Printf("Completed %d operations in %v\n", numWorkers*operationsPerWorker, duration)

	stats := client.GetPoolStats()
	fmt.Printf("Final pool stats:\n")
	fmt.Printf("  Total connections created: %d\n", stats.ConnectionsCreated)
	fmt.Printf("  Peak connections: %d\n", stats.TotalConnections)
	fmt.Printf("  Pool hits: %d, misses: %d\n", stats.PoolHits, stats.PoolMisses)

	if stats.PoolHits+stats.PoolMisses > 0 {
		hitRatio := float64(stats.PoolHits) / float64(stats.PoolHits+stats.PoolMisses) * 100
		fmt.Printf("  Hit ratio: %.1f%%\n", hitRatio)
	}

	// Calculate efficiency metrics
	totalOps := int64(numWorkers * operationsPerWorker)
	connectionsPerOp := float64(stats.ConnectionsCreated) / float64(totalOps)
	fmt.Printf("  Efficiency: %.3f connections per operation\n", connectionsPerOp)
	fmt.Printf("  Operations per second: %.1f\n", float64(totalOps)/duration.Seconds())

	// Expected output (performance will vary):
	// Completed 200 operations in 2.5s
	// Final pool stats:
	//   Total connections created: 15
	//   Peak connections: 15
	//   Pool hits: 185, misses: 15
	//   Hit ratio: 92.5%
	//   Efficiency: 0.075 connections per operation
	//   Operations per second: 80.0
}

// Example_poolMonitoring demonstrates how to monitor pool health and performance
func Example_poolMonitoring() {
	config := ldap.Config{
		Server: "ldap://localhost:389",
		BaseDN: "dc=example,dc=org",
		Pool: &ldap.PoolConfig{
			MaxConnections:      10,
			MinConnections:      2,
			HealthCheckInterval: 5 * time.Second, // Frequent health checks for demo
		},
	}

	client, err := ldap.New(&config, "cn=admin,dc=example,dc=org", "password")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	// Monitor pool statistics over time
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Println("Monitoring pool statistics:")
	fmt.Println("Time\t\tActive\tIdle\tTotal\tHits\tMisses\tHealth(P/F)")

	for {
		select {
		case <-ticker.C:
			stats := client.GetPoolStats()
			fmt.Printf("%s\t%d\t%d\t%d\t%d\t%d\t%d/%d\n",
				time.Now().Format("15:04:05"),
				stats.ActiveConnections,
				stats.IdleConnections,
				stats.TotalConnections,
				stats.PoolHits,
				stats.PoolMisses,
				stats.HealthChecksPassed,
				stats.HealthChecksFailed)

			// Perform some operations to generate activity
			go func() {
				if users, err := client.FindUsersContext(context.Background()); err == nil {
					_ = len(users) // Use result to avoid unused variable
				}
			}()

		case <-ctx.Done():
			fmt.Println("Monitoring complete")
			return
		}
	}

	// Expected output:
	// Monitoring pool statistics:
	// Time		Active	Idle	Total	Hits	Misses	Health(P/F)
	// 14:30:01	0	2	2	0	0	4/0
	// 14:30:03	0	2	2	1	1	8/0
	// 14:30:05	0	2	2	2	1	12/0
	// 14:30:07	0	2	2	3	1	16/0
	// Monitoring complete
}

// Example_backwardCompatibility shows that existing code works unchanged
// when pooling is not configured
func Example_backwardCompatibility() {
	// Existing code without pool configuration continues to work
	config := ldap.Config{
		Server: "ldap://localhost:389",
		BaseDN: "dc=example,dc=org",
		// Pool: nil - no pooling, legacy behavior
	}

	client, err := ldap.New(&config, "cn=admin,dc=example,dc=org", "password")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	// All existing operations work exactly as before
	ctx := context.Background()
	users, err := client.FindUsersContext(ctx)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d users using direct connections\n", len(users))

	// Pool stats will show no activity when pooling is disabled
	stats := client.GetPoolStats()
	if stats.PoolHits == 0 && stats.PoolMisses == 0 {
		fmt.Println("No connection pooling configured - using direct connections")
	}

	// Output:
	// Found 150 users using direct connections
	// No connection pooling configured - using direct connections
}

// Example_poolConfiguration demonstrates various pool configuration options
func Example_poolConfiguration() {
	// Minimal pool configuration (uses defaults for unspecified values)
	minimalConfig := ldap.Config{
		Server: "ldap://localhost:389",
		BaseDN: "dc=example,dc=org",
		Pool: &ldap.PoolConfig{
			MaxConnections: 15, // Only specify what you need to change
			// Other values will use defaults
		},
	}

	// Full pool configuration for fine-tuning
	fullConfig := ldap.Config{
		Server:            "ldaps://ad.enterprise.com:636",
		BaseDN:            "DC=enterprise,DC=com",
		IsActiveDirectory: true,
		Pool: &ldap.PoolConfig{
			MaxConnections:      50,               // High concurrency support
			MinConnections:      10,               // Keep 10 connections warm
			MaxIdleTime:         15 * time.Minute, // Allow longer idle time
			HealthCheckInterval: 45 * time.Second, // Less frequent health checks
			ConnectionTimeout:   20 * time.Second, // Longer connection timeout
			GetTimeout:          8 * time.Second,  // Generous pool timeout
		},
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}

	// High-performance configuration for maximum throughput
	highPerfConfig := ldap.Config{
		Server: "ldap://fast-server:389",
		BaseDN: "dc=fast,dc=org",
		Pool: &ldap.PoolConfig{
			MaxConnections:      100,              // Support very high concurrency
			MinConnections:      20,               // Many warm connections
			MaxIdleTime:         30 * time.Minute, // Keep connections longer
			HealthCheckInterval: 60 * time.Second, // Minimal health check overhead
			ConnectionTimeout:   5 * time.Second,  // Fast connection creation
			GetTimeout:          2 * time.Second,  // Fast pool access
		},
	}

	// Conservative configuration for resource-constrained environments
	conservativeConfig := ldap.Config{
		Server: "ldap://limited-server:389",
		BaseDN: "dc=limited,dc=org",
		Pool: &ldap.PoolConfig{
			MaxConnections:      3,                // Minimal resource usage
			MinConnections:      1,                // Just one warm connection
			MaxIdleTime:         2 * time.Minute,  // Cleanup idle connections quickly
			HealthCheckInterval: 15 * time.Second, // Frequent health monitoring
			ConnectionTimeout:   30 * time.Second, // Allow time for slow connections
			GetTimeout:          10 * time.Second, // Patient pool access
		},
	}

	configs := map[string]ldap.Config{
		"Minimal":      minimalConfig,
		"Full":         fullConfig,
		"HighPerf":     highPerfConfig,
		"Conservative": conservativeConfig,
	}

	// Iterate in deterministic order for consistent output
	configOrder := []string{"Minimal", "Full", "HighPerf", "Conservative"}
	for _, name := range configOrder {
		config := configs[name]
		fmt.Printf("%s Configuration:\n", name)
		fmt.Printf("  Max Connections: %d\n", config.Pool.MaxConnections)
		fmt.Printf("  Min Connections: %d\n", config.Pool.MinConnections)
		fmt.Printf("  Max Idle Time: %v\n", config.Pool.MaxIdleTime)
		fmt.Printf("  Health Check Interval: %v\n", config.Pool.HealthCheckInterval)
		fmt.Printf("  Connection Timeout: %v\n", config.Pool.ConnectionTimeout)
		fmt.Printf("  Get Timeout: %v\n", config.Pool.GetTimeout)
		fmt.Println()

		// Note: In real usage, you would create and use the client here
		// client, err := ldap.New(&config, bindDN, password)
		// if err != nil { ... }
		// defer client.Close()
	}

	// Output:
	// Minimal Configuration:
	//   Max Connections: 15
	//   Min Connections: 0
	//   Max Idle Time: 0s
	//   Health Check Interval: 0s
	//   Connection Timeout: 0s
	//   Get Timeout: 0s
	//
	// Full Configuration:
	//   Max Connections: 50
	//   Min Connections: 10
	//   Max Idle Time: 15m0s
	//   Health Check Interval: 45s
	//   Connection Timeout: 20s
	//   Get Timeout: 8s
	//
	// HighPerf Configuration:
	//   Max Connections: 100
	//   Min Connections: 20
	//   Max Idle Time: 30m0s
	//   Health Check Interval: 1m0s
	//   Connection Timeout: 5s
	//   Get Timeout: 2s
	//
	// Conservative Configuration:
	//   Max Connections: 3
	//   Min Connections: 1
	//   Max Idle Time: 2m0s
	//   Health Check Interval: 15s
	//   Connection Timeout: 30s
	//   Get Timeout: 10s
}
