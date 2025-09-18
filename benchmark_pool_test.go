package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// BenchmarkConnectionPoolPerformance provides comprehensive performance testing
// of the connection pooling implementation vs direct connections
func BenchmarkConnectionPoolPerformance(b *testing.B) {
	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		b.Skip("LDAP test environment not configured")
	}

	baseConfig := Config{
		Server: server,
		BaseDN: baseDN,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	// Test different pool configurations
	poolConfigs := map[string]*PoolConfig{
		"Small_Pool": {
			MaxConnections: 5,
			MinConnections: 2,
			GetTimeout:     1 * time.Second,
		},
		"Medium_Pool": {
			MaxConnections: 10,
			MinConnections: 3,
			GetTimeout:     1 * time.Second,
		},
		"Large_Pool": {
			MaxConnections: 20,
			MinConnections: 5,
			GetTimeout:     1 * time.Second,
		},
	}

	for name, poolConfig := range poolConfigs {
		b.Run(fmt.Sprintf("Pooled_%s", name), func(b *testing.B) {
			config := baseConfig
			config.Pool = poolConfig

			client, err := New(config, bindDN, bindPassword)
			require.NoError(b, err)
			defer func() { _ = client.Close() }()

			ctx := context.Background()

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					conn, err := client.GetConnectionContext(ctx)
					if err != nil {
						b.Error(err)
						continue
					}
					_ = conn.Close()
				}
			})

			if !b.Failed() {
				stats := client.GetPoolStats()
				if stats != nil {
					hitRatio := float64(stats.PoolHits) / float64(stats.PoolHits+stats.PoolMisses) * 100
					b.ReportMetric(hitRatio, "hit_ratio_%")
					b.ReportMetric(float64(stats.TotalConnections), "total_connections")
					b.ReportMetric(float64(stats.ConnectionsCreated), "connections_created")
				}
			}
		})
	}

	// Compare with non-pooled version
	b.Run("Direct_Connection", func(b *testing.B) {
		config := baseConfig
		// Pool is nil for direct connections

		client, err := New(config, bindDN, bindPassword)
		require.NoError(b, err)
		defer func() { _ = client.Close() }()

		ctx := context.Background()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				conn, err := client.GetConnectionContext(ctx)
				if err != nil {
					b.Error(err)
					continue
				}
				_ = conn.Close()
			}
		})
	})
}

// BenchmarkLDAPOperationsPooled tests real LDAP operations with pooling
func BenchmarkLDAPOperationsPooled(b *testing.B) {
	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		b.Skip("LDAP test environment not configured")
	}

	operations := map[string]func(*LDAP, context.Context) error{
		"FindUsers": func(client *LDAP, ctx context.Context) error {
			_, err := client.FindUsersContext(ctx)
			return err
		},
		"FindUserByDN": func(client *LDAP, ctx context.Context) error {
			// Use a test DN or skip if not available
			users, err := client.FindUsersContext(ctx)
			if err != nil || len(users) == 0 {
				return err
			}
			_, err = client.FindUserByDNContext(ctx, users[0].DN())
			return err
		},
	}

	for opName, operation := range operations {
		b.Run(fmt.Sprintf("%s_Pooled", opName), func(b *testing.B) {
			config := Config{
				Server: server,
				BaseDN: baseDN,
				Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
				Pool: &PoolConfig{
					MaxConnections: 10,
					MinConnections: 3,
				},
			}

			client, err := New(config, bindDN, bindPassword)
			require.NoError(b, err)
			defer func() { _ = client.Close() }()

			ctx := context.Background()

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					err := operation(client, ctx)
					if err != nil {
						b.Error(err)
					}
				}
			})

			if !b.Failed() {
				stats := client.GetPoolStats()
				if stats != nil {
					hitRatio := float64(stats.PoolHits) / float64(stats.PoolHits+stats.PoolMisses) * 100
					b.ReportMetric(hitRatio, "hit_ratio_%")
				}
			}
		})

		b.Run(fmt.Sprintf("%s_Direct", opName), func(b *testing.B) {
			config := Config{
				Server: server,
				BaseDN: baseDN,
				Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
				// Pool: nil - direct connections
			}

			client, err := New(config, bindDN, bindPassword)
			require.NoError(b, err)
			defer func() { _ = client.Close() }()

			ctx := context.Background()

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					err := operation(client, ctx)
					if err != nil {
						b.Error(err)
					}
				}
			})
		})
	}
}

// BenchmarkConcurrentLoad simulates high-concurrency scenarios
func BenchmarkConcurrentLoad(b *testing.B) {
	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		b.Skip("LDAP test environment not configured")
	}

	concurrencyLevels := []int{1, 5, 10, 20, 50}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Pooled_Concurrency_%d", concurrency), func(b *testing.B) {
			config := Config{
				Server: server,
				BaseDN: baseDN,
				Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
				Pool: &PoolConfig{
					MaxConnections: concurrency + 5, // Slightly more than concurrency
					MinConnections: min(3, concurrency),
				},
			}

			client, err := New(config, bindDN, bindPassword)
			require.NoError(b, err)
			defer func() { _ = client.Close() }()

			b.ResetTimer()

			// Run with specific concurrency
			var operations int64
			startTime := time.Now()

			var wg sync.WaitGroup
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx := context.Background()

					for j := 0; j < b.N/concurrency; j++ {
						_, err := client.FindUsersContext(ctx)
						if err == nil {
							atomic.AddInt64(&operations, 1)
						}
					}
				}()
			}
			wg.Wait()

			duration := time.Since(startTime)
			opsPerSecond := float64(operations) / duration.Seconds()

			b.ReportMetric(opsPerSecond, "ops/sec")

			if stats := client.GetPoolStats(); stats != nil {
				hitRatio := float64(stats.PoolHits) / float64(stats.PoolHits+stats.PoolMisses) * 100
				b.ReportMetric(hitRatio, "hit_ratio_%")
				b.ReportMetric(float64(stats.TotalConnections), "peak_connections")
			}
		})

		if concurrency <= 20 { // Only test direct for lower concurrency to avoid overwhelming server
			b.Run(fmt.Sprintf("Direct_Concurrency_%d", concurrency), func(b *testing.B) {
				config := Config{
					Server: server,
					BaseDN: baseDN,
					Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
					// Pool: nil - direct connections
				}

				client, err := New(config, bindDN, bindPassword)
				require.NoError(b, err)
				defer func() { _ = client.Close() }()

				b.ResetTimer()

				var operations int64
				startTime := time.Now()

				var wg sync.WaitGroup
				for i := 0; i < concurrency; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						ctx := context.Background()

						for j := 0; j < b.N/concurrency; j++ {
							_, err := client.FindUsersContext(ctx)
							if err == nil {
								atomic.AddInt64(&operations, 1)
							}
						}
					}()
				}
				wg.Wait()

				duration := time.Since(startTime)
				opsPerSecond := float64(operations) / duration.Seconds()

				b.ReportMetric(opsPerSecond, "ops/sec")
			})
		}
	}
}

// BenchmarkPoolEfficiency measures pool efficiency metrics
func BenchmarkPoolEfficiency(b *testing.B) {
	server := os.Getenv("LDAP_SERVER")
	baseDN := os.Getenv("LDAP_BASE_DN")
	bindDN := os.Getenv("LDAP_BIND_DN")
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	if server == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		b.Skip("LDAP test environment not configured")
	}

	scenarios := map[string]struct {
		poolConfig  *PoolConfig
		workPattern string
		operations  int
		concurrency int
	}{
		"HighReuse": {
			poolConfig: &PoolConfig{
				MaxConnections: 5,
				MinConnections: 3,
			},
			workPattern: "sequential_bursts",
			operations:  100,
			concurrency: 1,
		},
		"MediumContention": {
			poolConfig: &PoolConfig{
				MaxConnections: 8,
				MinConnections: 2,
			},
			workPattern: "concurrent_moderate",
			operations:  50,
			concurrency: 5,
		},
		"HighContention": {
			poolConfig: &PoolConfig{
				MaxConnections: 10,
				MinConnections: 2,
			},
			workPattern: "concurrent_high",
			operations:  30,
			concurrency: 15,
		},
	}

	for name, scenario := range scenarios {
		b.Run(name, func(b *testing.B) {
			config := Config{
				Server: server,
				BaseDN: baseDN,
				Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
				Pool:   scenario.poolConfig,
			}

			client, err := New(config, bindDN, bindPassword)
			require.NoError(b, err)
			defer func() { _ = client.Close() }()

			b.ResetTimer()

			var totalOperations int64
			startTime := time.Now()

			var wg sync.WaitGroup
			for i := 0; i < scenario.concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx := context.Background()

					for j := 0; j < scenario.operations; j++ {
						conn, err := client.GetConnectionContext(ctx)
						if err == nil {
							atomic.AddInt64(&totalOperations, 1)
							// Simulate some work
							time.Sleep(1 * time.Millisecond)
							_ = conn.Close()
						}
					}
				}()
			}
			wg.Wait()

			duration := time.Since(startTime)

			stats := client.GetPoolStats()
			if stats != nil {
				hitRatio := float64(stats.PoolHits) / float64(stats.PoolHits+stats.PoolMisses) * 100
				efficiency := float64(stats.PoolHits) / float64(totalOperations) * 100
				connectionsPerOp := float64(stats.ConnectionsCreated) / float64(totalOperations)

				b.ReportMetric(hitRatio, "hit_ratio_%")
				b.ReportMetric(efficiency, "efficiency_%")
				b.ReportMetric(connectionsPerOp, "conn_per_op")
				b.ReportMetric(float64(stats.TotalConnections), "peak_connections")
				b.ReportMetric(duration.Seconds(), "duration_sec")

				b.Logf("Scenario %s: %.1f%% hit ratio, %.1f%% efficiency, %.3f conn/op, peak=%d conn",
					name, hitRatio, efficiency, connectionsPerOp, stats.TotalConnections)
			}
		})
	}
}

// Helper function for minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
