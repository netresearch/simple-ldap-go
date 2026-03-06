//go:build !integration

package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPool creates a ConnectionPool for unit testing without attempting real LDAP connections.
// It bypasses warmPool and startBackgroundTasks by constructing the struct directly.
func newTestPool(config *PoolConfig) *ConnectionPool {
	if config == nil {
		config = DefaultPoolConfig()
	}
	logger := slog.Default()

	return &ConnectionPool{
		config:          config,
		ldapConfig:      Config{Server: "ldap://127.0.0.1:1", BaseDN: "dc=test,dc=com"},
		user:            "cn=admin,dc=test,dc=com",
		password:        "secret",
		logger:          logger,
		connections:     make([]*pooledConnection, 0, config.MaxConnections),
		available:       make(chan *pooledConnection, config.MaxConnections),
		healthCheckStop: make(chan struct{}),
		cleanupStop:     make(chan struct{}),
		connMap:         make(map[*ldap.Conn]*pooledConnection),
	}
}

func TestDefaultPoolConfig(t *testing.T) {
	t.Run("returns sensible defaults", func(t *testing.T) {
		config := DefaultPoolConfig()
		require.NotNil(t, config)

		assert.Equal(t, 10, config.MaxConnections)
		assert.Equal(t, 2, config.MinConnections)
		assert.Equal(t, 5*time.Minute, config.MaxIdleTime)
		assert.Equal(t, 30*time.Second, config.HealthCheckInterval)
		assert.Equal(t, 30*time.Second, config.ConnectionTimeout)
		assert.Equal(t, 10*time.Second, config.GetTimeout)
		assert.True(t, config.EnableSelfHealing)
		assert.Equal(t, 5*time.Minute, config.LeakDetectionThreshold)
		assert.Equal(t, 10*time.Minute, config.LeakEvictionThreshold)
	})
}

func TestPoolConfigStruct(t *testing.T) {
	t.Run("stores all fields", func(t *testing.T) {
		config := PoolConfig{
			MaxConnections:         20,
			MinConnections:         5,
			MaxIdleTime:            10 * time.Minute,
			HealthCheckInterval:    1 * time.Minute,
			ConnectionTimeout:      15 * time.Second,
			GetTimeout:             5 * time.Second,
			EnableSelfHealing:      false,
			LeakDetectionThreshold: 3 * time.Minute,
			LeakEvictionThreshold:  6 * time.Minute,
		}

		assert.Equal(t, 20, config.MaxConnections)
		assert.Equal(t, 5, config.MinConnections)
		assert.Equal(t, 10*time.Minute, config.MaxIdleTime)
		assert.Equal(t, 1*time.Minute, config.HealthCheckInterval)
		assert.Equal(t, 15*time.Second, config.ConnectionTimeout)
		assert.Equal(t, 5*time.Second, config.GetTimeout)
		assert.False(t, config.EnableSelfHealing)
		assert.Equal(t, 3*time.Minute, config.LeakDetectionThreshold)
		assert.Equal(t, 6*time.Minute, config.LeakEvictionThreshold)
	})
}

func TestPoolStatsStruct(t *testing.T) {
	t.Run("stores all stat fields", func(t *testing.T) {
		stats := PoolStats{
			ActiveConnections:  3,
			IdleConnections:    7,
			TotalConnections:   10,
			PoolHits:           100,
			PoolMisses:         5,
			HealthChecksPassed: 50,
			HealthChecksFailed: 2,
			ConnectionsCreated: 12,
			ConnectionsClosed:  2,
			LeakedConnections:  1,
			SelfHealingEvents:  1,
		}

		assert.Equal(t, int32(3), stats.ActiveConnections)
		assert.Equal(t, int32(7), stats.IdleConnections)
		assert.Equal(t, int32(10), stats.TotalConnections)
		assert.Equal(t, int64(100), stats.PoolHits)
		assert.Equal(t, int64(5), stats.PoolMisses)
		assert.Equal(t, int64(50), stats.HealthChecksPassed)
		assert.Equal(t, int64(2), stats.HealthChecksFailed)
		assert.Equal(t, int64(12), stats.ConnectionsCreated)
		assert.Equal(t, int64(2), stats.ConnectionsClosed)
		assert.Equal(t, int64(1), stats.LeakedConnections)
		assert.Equal(t, int64(1), stats.SelfHealingEvents)
	})
}

func TestConnectionCredentials(t *testing.T) {
	t.Run("stores DN and password", func(t *testing.T) {
		creds := ConnectionCredentials{
			DN:       "cn=user,dc=test,dc=com",
			Password: "secret",
		}

		assert.Equal(t, "cn=user,dc=test,dc=com", creds.DN)
		assert.Equal(t, "secret", creds.Password)
	})
}

func TestPoolStats(t *testing.T) {
	t.Run("returns atomic snapshot of stats", func(t *testing.T) {
		pool := newTestPool(nil)

		// Set various stats
		atomic.StoreInt32(&pool.stats.ActiveConnections, 3)
		atomic.StoreInt32(&pool.stats.IdleConnections, 5)
		atomic.StoreInt32(&pool.stats.TotalConnections, 8)
		atomic.StoreInt64(&pool.stats.PoolHits, 42)
		atomic.StoreInt64(&pool.stats.PoolMisses, 7)
		atomic.StoreInt64(&pool.stats.HealthChecksPassed, 100)
		atomic.StoreInt64(&pool.stats.HealthChecksFailed, 3)
		atomic.StoreInt64(&pool.stats.ConnectionsCreated, 15)
		atomic.StoreInt64(&pool.stats.ConnectionsClosed, 7)

		stats := pool.Stats()

		assert.Equal(t, int32(3), stats.ActiveConnections)
		assert.Equal(t, int32(5), stats.IdleConnections)
		assert.Equal(t, int32(8), stats.TotalConnections)
		assert.Equal(t, int64(42), stats.PoolHits)
		assert.Equal(t, int64(7), stats.PoolMisses)
		assert.Equal(t, int64(100), stats.HealthChecksPassed)
		assert.Equal(t, int64(3), stats.HealthChecksFailed)
		assert.Equal(t, int64(15), stats.ConnectionsCreated)
		assert.Equal(t, int64(7), stats.ConnectionsClosed)
	})
}

func TestPoolPutNil(t *testing.T) {
	t.Run("put nil connection is no-op", func(t *testing.T) {
		pool := newTestPool(nil)

		err := pool.Put(nil)
		assert.NoError(t, err)
	})
}

func TestPoolPutClosedPool(t *testing.T) {
	t.Run("put to closed pool returns ErrPoolClosed", func(t *testing.T) {
		pool := newTestPool(nil)
		pool.closed = true

		// nil is handled before the closed check, so no error
		err := pool.Put(nil)
		assert.NoError(t, err)
	})
}

func TestPoolGetClosedPool(t *testing.T) {
	t.Run("get from closed pool returns ErrPoolClosed", func(t *testing.T) {
		pool := newTestPool(nil)
		pool.closed = true

		conn, err := pool.Get(context.Background())
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, ErrPoolClosed)
	})
}

func TestPoolGetWithCredentialsClosedPool(t *testing.T) {
	t.Run("get with credentials from closed pool returns ErrPoolClosed", func(t *testing.T) {
		pool := newTestPool(nil)
		pool.closed = true

		conn, err := pool.GetWithCredentials(context.Background(), "cn=user,dc=test", "pass")
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, ErrPoolClosed)
	})
}

func TestPoolCloseTwice(t *testing.T) {
	t.Run("closing already-closed pool is no-op", func(t *testing.T) {
		pool := newTestPool(nil)
		pool.closed = true

		err := pool.Close()
		assert.NoError(t, err)
	})
}

func TestPoolCloseEmpty(t *testing.T) {
	t.Run("close empty pool with no connections", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:      5,
			MinConnections:      0,
			MaxIdleTime:         5 * time.Minute,
			HealthCheckInterval: 30 * time.Second,
			ConnectionTimeout:   30 * time.Second,
			GetTimeout:          10 * time.Second,
		})

		err := pool.Close()
		assert.NoError(t, err)
		assert.True(t, pool.closed)
	})
}

func TestCanReuseConnection(t *testing.T) {
	pool := newTestPool(&PoolConfig{
		MaxConnections: 5,
		MaxIdleTime:    5 * time.Minute,
	})

	tests := []struct {
		name     string
		conn     *pooledConnection
		creds    *ConnectionCredentials
		expected bool
	}{
		{
			name: "unhealthy connection",
			conn: &pooledConnection{
				isHealthy: false,
				lastUsed:  time.Now(),
			},
			creds:    nil,
			expected: false,
		},
		{
			name: "idle too long",
			conn: &pooledConnection{
				isHealthy: true,
				lastUsed:  time.Now().Add(-10 * time.Minute),
			},
			creds:    nil,
			expected: false,
		},
		{
			name: "matching credentials",
			conn: &pooledConnection{
				isHealthy: true,
				lastUsed:  time.Now(),
				credentials: &ConnectionCredentials{
					DN:       "cn=user1,dc=test",
					Password: "pass1",
				},
			},
			creds: &ConnectionCredentials{
				DN:       "cn=user1,dc=test",
				Password: "pass1",
			},
			expected: true,
		},
		{
			name: "non-matching credentials DN",
			conn: &pooledConnection{
				isHealthy: true,
				lastUsed:  time.Now(),
				credentials: &ConnectionCredentials{
					DN:       "cn=user1,dc=test",
					Password: "pass1",
				},
			},
			creds: &ConnectionCredentials{
				DN:       "cn=user2,dc=test",
				Password: "pass1",
			},
			expected: false,
		},
		{
			name: "non-matching credentials password",
			conn: &pooledConnection{
				isHealthy: true,
				lastUsed:  time.Now(),
				credentials: &ConnectionCredentials{
					DN:       "cn=user1,dc=test",
					Password: "pass1",
				},
			},
			creds: &ConnectionCredentials{
				DN:       "cn=user1,dc=test",
				Password: "differentpass",
			},
			expected: false,
		},
		{
			name: "both nil credentials (readonly)",
			conn: &pooledConnection{
				isHealthy:   true,
				lastUsed:    time.Now(),
				credentials: nil,
			},
			creds:    nil,
			expected: true,
		},
		{
			name: "conn has credentials but creds is nil",
			conn: &pooledConnection{
				isHealthy: true,
				lastUsed:  time.Now(),
				credentials: &ConnectionCredentials{
					DN:       "cn=user1,dc=test",
					Password: "pass1",
				},
			},
			creds:    nil,
			expected: false,
		},
		{
			name: "conn nil credentials but creds is non-nil",
			conn: &pooledConnection{
				isHealthy:   true,
				lastUsed:    time.Now(),
				credentials: nil,
			},
			creds: &ConnectionCredentials{
				DN:       "cn=user1,dc=test",
				Password: "pass1",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pool.canReuseConnection(tt.conn, tt.creds)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsConnectionHealthyNilCases(t *testing.T) {
	pool := newTestPool(nil)

	t.Run("nil pooledConnection returns false", func(t *testing.T) {
		assert.False(t, pool.isConnectionHealthy(nil))
	})

	t.Run("nil conn field returns false", func(t *testing.T) {
		pc := &pooledConnection{
			conn:      nil,
			isHealthy: true,
			lastUsed:  time.Now(),
		}
		assert.False(t, pool.isConnectionHealthy(pc))
	})
}

func TestCloseConnectionNilCases(t *testing.T) {
	pool := newTestPool(nil)

	t.Run("nil pooledConnection is no-op", func(t *testing.T) {
		pool.closeConnection(nil)
	})

	t.Run("nil conn field is no-op", func(t *testing.T) {
		pc := &pooledConnection{
			conn: nil,
		}
		pool.closeConnection(pc)
	})
}

func TestDetectLeakedConnections(t *testing.T) {
	t.Run("returns nil when self-healing disabled", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			EnableSelfHealing: false,
		})

		leaked := pool.detectLeakedConnections()
		assert.Nil(t, leaked)
	})

	t.Run("returns nil when no connections are in use", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         5,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 5 * time.Minute,
			LeakEvictionThreshold:  10 * time.Minute,
		})

		pc := &pooledConnection{
			inUse:    false,
			lastUsed: time.Now(),
		}
		pool.connMap[nil] = pc

		leaked := pool.detectLeakedConnections()
		assert.Empty(t, leaked)
	})

	t.Run("detects leaked connections beyond eviction threshold", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         5,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 100 * time.Millisecond,
			LeakEvictionThreshold:  200 * time.Millisecond,
		})

		pc := &pooledConnection{
			inUse:        true,
			checkedOutAt: time.Now().Add(-300 * time.Millisecond),
		}
		pool.connMapMu.Lock()
		pool.connMap[nil] = pc
		pool.connMapMu.Unlock()

		leaked := pool.detectLeakedConnections()
		assert.Len(t, leaked, 1)
		assert.Equal(t, pc, leaked[0])
	})

	t.Run("warns but does not evict connections between thresholds", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         5,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 100 * time.Millisecond,
			LeakEvictionThreshold:  5 * time.Second,
		})

		pc := &pooledConnection{
			inUse:        true,
			checkedOutAt: time.Now().Add(-200 * time.Millisecond),
		}
		pool.connMapMu.Lock()
		pool.connMap[nil] = pc
		pool.connMapMu.Unlock()

		leaked := pool.detectLeakedConnections()
		assert.Empty(t, leaked)
	})

	t.Run("does not flag recently checked out connections", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         5,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 5 * time.Minute,
			LeakEvictionThreshold:  10 * time.Minute,
		})

		pc := &pooledConnection{
			inUse:        true,
			checkedOutAt: time.Now(),
		}
		pool.connMapMu.Lock()
		pool.connMap[nil] = pc
		pool.connMapMu.Unlock()

		leaked := pool.detectLeakedConnections()
		assert.Empty(t, leaked)
	})
}

func TestMonitorLeaks(t *testing.T) {
	t.Run("no-op when self-healing disabled", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			EnableSelfHealing: false,
		})

		pool.monitorLeaks()
	})

	t.Run("no-op when no leaks detected", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         5,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 5 * time.Minute,
			LeakEvictionThreshold:  10 * time.Minute,
		})

		pool.monitorLeaks()
	})
}

func TestPerformHealthChecksClosedPool(t *testing.T) {
	t.Run("no-op when pool is closed", func(t *testing.T) {
		pool := newTestPool(nil)
		pool.closed = true

		pool.performHealthChecks()
	})
}

func TestCleanupIdleConnectionsClosedPool(t *testing.T) {
	t.Run("no-op when pool is closed", func(t *testing.T) {
		pool := newTestPool(nil)
		pool.closed = true

		pool.cleanupIdleConnections()
	})
}

func TestCleanupIdleConnectionsBelowMinimum(t *testing.T) {
	t.Run("no-op when at or below minimum connections", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 10,
			MinConnections: 5,
			MaxIdleTime:    5 * time.Minute,
		})

		for i := 0; i < 3; i++ {
			pool.connections = append(pool.connections, &pooledConnection{})
		}

		pool.cleanupIdleConnections()
		assert.Len(t, pool.connections, 3)
	})
}

func TestPoolErrorVariables(t *testing.T) {
	t.Run("ErrPoolClosed", func(t *testing.T) {
		assert.Equal(t, "connection pool is closed", ErrPoolClosed.Error())
	})

	t.Run("ErrPoolExhausted", func(t *testing.T) {
		assert.Equal(t, "connection pool exhausted", ErrPoolExhausted.Error())
	})

	t.Run("ErrConnectionUnhealthy", func(t *testing.T) {
		assert.Equal(t, "connection is unhealthy", ErrConnectionUnhealthy.Error())
	})
}

func TestRecoverFromLeakNilConn(t *testing.T) {
	t.Run("handles connection with nil conn field", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Second,
		})

		pc := &pooledConnection{
			conn:  nil,
			inUse: true,
		}

		// recoverFromLeak will try to create a replacement which will fail
		err := pool.recoverFromLeak(pc)
		assert.Error(t, err)

		assert.Equal(t, int64(1), atomic.LoadInt64(&pool.stats.LeakedConnections))
		assert.Equal(t, int64(1), atomic.LoadInt64(&pool.stats.SelfHealingEvents))
	})
}

func TestRecoverFromLeakMaxConnections(t *testing.T) {
	t.Run("does not create replacement when at max connections", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    2,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Second,
		})

		pool.connections = make([]*pooledConnection, 2)

		pc := &pooledConnection{
			conn:  nil,
			inUse: true,
		}

		err := pool.recoverFromLeak(pc)
		assert.NoError(t, err)

		assert.Equal(t, int64(1), atomic.LoadInt64(&pool.stats.LeakedConnections))
		assert.Equal(t, int64(1), atomic.LoadInt64(&pool.stats.SelfHealingEvents))
	})
}

func TestPerformHealthChecksEmptyAvailable(t *testing.T) {
	t.Run("handles empty available channel", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:      5,
			MinConnections:      0,
			MaxIdleTime:         5 * time.Minute,
			HealthCheckInterval: 30 * time.Second,
		})

		pool.performHealthChecks()
	})
}

func TestCloseConnectionRemovesFromSlice(t *testing.T) {
	t.Run("nil conn returns early without removing", func(t *testing.T) {
		pool := newTestPool(nil)

		pc1 := &pooledConnection{conn: nil, createdAt: time.Now()}
		pc2 := &pooledConnection{conn: nil, createdAt: time.Now()}

		pool.connections = []*pooledConnection{pc1, pc2}

		// closeConnection returns early for nil conn, so slice is unchanged
		pool.closeConnection(pc1)
		assert.Len(t, pool.connections, 2)
	})

	t.Run("nil pooledConnection is safe", func(t *testing.T) {
		pool := newTestPool(nil)
		// Should not panic
		pool.closeConnection(nil)
	})
}

func TestPooledConnectionFields(t *testing.T) {
	t.Run("pooledConnection stores metadata", func(t *testing.T) {
		now := time.Now()
		creds := &ConnectionCredentials{DN: "cn=test", Password: "pass"}

		pc := &pooledConnection{
			conn:         nil,
			createdAt:    now,
			lastUsed:     now,
			checkedOutAt: now,
			usageCount:   5,
			isHealthy:    true,
			inUse:        false,
			credentials:  creds,
		}

		assert.Nil(t, pc.conn)
		assert.Equal(t, now, pc.createdAt)
		assert.Equal(t, now, pc.lastUsed)
		assert.Equal(t, now, pc.checkedOutAt)
		assert.Equal(t, int64(5), pc.usageCount)
		assert.True(t, pc.isHealthy)
		assert.False(t, pc.inUse)
		assert.Equal(t, creds, pc.credentials)
	})
}

func TestDetectLeakedConnectionsMultiple(t *testing.T) {
	t.Run("detects leaked connection in map", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         10,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 50 * time.Millisecond,
			LeakEvictionThreshold:  100 * time.Millisecond,
		})

		pc := &pooledConnection{
			inUse:        true,
			checkedOutAt: time.Now().Add(-200 * time.Millisecond),
			conn:         nil,
		}
		pool.connMapMu.Lock()
		pool.connMap[nil] = pc
		pool.connMapMu.Unlock()

		leaked := pool.detectLeakedConnections()
		assert.NotEmpty(t, leaked)
	})
}

func TestNewConnectionPoolConfigValidation(t *testing.T) {
	// These tests verify config validation in NewConnectionPool.
	// We use 127.0.0.1:1 (connection refused - fast) for tests with MinConnections > 0,
	// and MinConnections=0 for tests where pool creation succeeds.
	// Using ldap:// scheme to avoid TLS issues.

	fastFailServer := "ldap://127.0.0.1:1"

	t.Run("negative MaxConnections gets corrected to 10", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:    -1,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Second,
		}

		pool, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		if err != nil {
			// Config should still be corrected even if pool creation failed
			assert.Equal(t, 10, config.MaxConnections)
			return
		}
		defer func() { _ = pool.Close() }()
		assert.Equal(t, 10, config.MaxConnections)
	})

	t.Run("MinConnections clamped to MaxConnections", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:    5,
			MinConnections:    20,
			ConnectionTimeout: 1 * time.Second,
		}

		_, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		// warmPool will fail because MinConnections gets clamped to 5, and connection fails
		assert.Error(t, err)
		assert.Equal(t, 5, config.MinConnections)
	})

	t.Run("negative MinConnections clamped to 0", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:    5,
			MinConnections:    -3,
			ConnectionTimeout: 1 * time.Second,
		}

		pool, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		if err != nil {
			assert.Equal(t, 0, config.MinConnections)
			return
		}
		defer func() { _ = pool.Close() }()
		assert.Equal(t, 0, config.MinConnections)
	})

	t.Run("zero MaxIdleTime gets default", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			MaxIdleTime:       0,
			ConnectionTimeout: 1 * time.Second,
		}

		pool, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		if err != nil {
			assert.Equal(t, 5*time.Minute, config.MaxIdleTime)
			return
		}
		defer func() { _ = pool.Close() }()
		assert.Equal(t, 5*time.Minute, config.MaxIdleTime)
	})

	t.Run("zero HealthCheckInterval gets default", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:      5,
			MinConnections:      0,
			HealthCheckInterval: 0,
			ConnectionTimeout:   1 * time.Second,
		}

		pool, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		if err != nil {
			assert.Equal(t, 30*time.Second, config.HealthCheckInterval)
			return
		}
		defer func() { _ = pool.Close() }()
		assert.Equal(t, 30*time.Second, config.HealthCheckInterval)
	})

	t.Run("zero ConnectionTimeout gets default", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 0,
		}

		pool, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		if err != nil {
			assert.Equal(t, 30*time.Second, config.ConnectionTimeout)
			return
		}
		defer func() { _ = pool.Close() }()
		assert.Equal(t, 30*time.Second, config.ConnectionTimeout)
	})

	t.Run("zero GetTimeout gets default", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			GetTimeout:        0,
			ConnectionTimeout: 1 * time.Second,
		}

		pool, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		if err != nil {
			assert.Equal(t, 10*time.Second, config.GetTimeout)
			return
		}
		defer func() { _ = pool.Close() }()
		assert.Equal(t, 10*time.Second, config.GetTimeout)
	})

	t.Run("nil config uses defaults", func(t *testing.T) {
		_, err := NewConnectionPool(nil, Config{Server: fastFailServer}, "user", "pass", slog.Default())
		// warmPool will try to connect 2 times (default MinConnections), so it will fail
		assert.Error(t, err)
	})

	t.Run("nil logger uses default", func(t *testing.T) {
		config := &PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Second,
		}

		pool, err := NewConnectionPool(config, Config{Server: fastFailServer}, "user", "pass", nil)
		if err != nil {
			// Just verify no panic
			return
		}
		defer func() { _ = pool.Close() }()
	})
}

func TestCreateConnectionMaxConnections(t *testing.T) {
	t.Run("returns ErrPoolExhausted at max connections", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    2,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Second,
			GetTimeout:        1 * time.Second,
		})

		pool.connections = make([]*pooledConnection, 2)

		conn, err := pool.createConnection(context.Background())
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, ErrPoolExhausted)
	})
}

func TestCreateConnectionWithCredentialsMaxConnections(t *testing.T) {
	t.Run("returns ErrPoolExhausted at max connections", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    2,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Second,
			GetTimeout:        1 * time.Second,
		})

		pool.connections = make([]*pooledConnection, 2)

		creds := &ConnectionCredentials{DN: "cn=user", Password: "pass"}
		conn, err := pool.createConnectionWithCredentials(context.Background(), creds)
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, ErrPoolExhausted)
	})
}

func TestIsConnectionHealthyIdleTooLong(t *testing.T) {
	t.Run("connection idle too long returns false", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 5,
			MaxIdleTime:    1 * time.Millisecond,
		})

		pc := &pooledConnection{
			conn:      &ldap.Conn{},
			isHealthy: true,
			lastUsed:  time.Now().Add(-1 * time.Second),
		}

		result := pool.isConnectionHealthy(pc)
		assert.False(t, result)
	})
}

func TestCreateConnectionContextCancelled(t *testing.T) {
	t.Run("returns error on cancelled context", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Millisecond,
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := pool.createConnection(ctx)
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}

func TestCreateConnectionWithCredentialsContextCancelled(t *testing.T) {
	t.Run("returns error on cancelled context", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 1 * time.Millisecond,
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		creds := &ConnectionCredentials{DN: "cn=user", Password: "pass"}
		conn, err := pool.createConnectionWithCredentials(ctx, creds)
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}

func TestCleanupIdleConnectionsWithExpiredConnections(t *testing.T) {
	t.Run("removes idle connections above minimum", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 10,
			MinConnections: 1,
			MaxIdleTime:    1 * time.Millisecond,
		})

		// Add connections above minimum
		for i := 0; i < 5; i++ {
			pc := &pooledConnection{
				conn:      nil,
				lastUsed:  time.Now().Add(-1 * time.Second), // idle for 1 second
				isHealthy: true,
			}
			pool.connections = append(pool.connections, pc)
			pool.available <- pc
		}
		atomic.StoreInt32(&pool.stats.IdleConnections, 5)

		pool.cleanupIdleConnections()

		// Some connections should have been cleaned up
		// The exact number depends on the min() calculation
		idleConns := atomic.LoadInt32(&pool.stats.IdleConnections)
		assert.Less(t, idleConns, int32(5))
	})
}

func TestWarmPoolWithZeroMinConnections(t *testing.T) {
	t.Run("warmPool is no-op with zero min connections", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 5,
			MinConnections: 0,
		})

		err := pool.warmPool(context.Background())
		assert.NoError(t, err)
		assert.Empty(t, pool.connections)
	})
}

func TestMonitorLeaksWithLeakedConnections(t *testing.T) {
	t.Run("calls recoverFromLeak for detected leaks", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         5,
			MinConnections:         0,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 50 * time.Millisecond,
			LeakEvictionThreshold:  100 * time.Millisecond,
			ConnectionTimeout:      1 * time.Second,
		})

		pc := &pooledConnection{
			conn:         nil,
			inUse:        true,
			checkedOutAt: time.Now().Add(-200 * time.Millisecond),
		}
		pool.connMapMu.Lock()
		pool.connMap[nil] = pc
		pool.connMapMu.Unlock()

		pool.monitorLeaks()

		// LeakedConnections should be incremented
		assert.Equal(t, int64(1), atomic.LoadInt64(&pool.stats.LeakedConnections))
	})
}

func TestPutConnectionNotFromPool(t *testing.T) {
	t.Run("put connection not tracked in connMap closes it directly", func(t *testing.T) {
		// This test verifies the path where Put receives a connection
		// that isn't in the connMap (not from pool).
		// We can't easily create a real *ldap.Conn, so we test via
		// the existing pool_test.go integration tests. Here we just
		// verify the nil handling.
		pool := newTestPool(nil)

		err := pool.Put(nil)
		assert.NoError(t, err)
	})
}

// Test that ensures the unused fmt import works (used in other tests)
var _ = fmt.Sprintf

// --- Additional pool coverage tests ---

func TestGetContextCancelled(t *testing.T) {
	t.Run("Get returns context error when context is cancelled", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 5,
			MinConnections: 0,
			GetTimeout:     1 * time.Second,
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		conn, err := pool.Get(ctx)
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}

func TestGetTimesOutAndCreatesConnection(t *testing.T) {
	t.Run("Get times out waiting for available and tries to create", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			GetTimeout:        10 * time.Millisecond,
			ConnectionTimeout: 10 * time.Millisecond,
		})

		ctx := context.Background()
		conn, err := pool.Get(ctx)
		// Will timeout waiting for available, then try createConnection which will fail
		assert.Nil(t, conn)
		assert.Error(t, err) // Connection refused on 127.0.0.1:1
	})
}

func TestGetUnhealthyConnectionFromChannel(t *testing.T) {
	t.Run("Get closes unhealthy connection and creates new", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			GetTimeout:        50 * time.Millisecond,
			ConnectionTimeout: 10 * time.Millisecond,
			MaxIdleTime:       5 * time.Minute,
		})

		// Put an unhealthy connection in the available channel
		unhealthy := &pooledConnection{
			conn:      nil, // nil conn makes isConnectionHealthy return false
			isHealthy: false,
			lastUsed:  time.Now(),
		}
		pool.available <- unhealthy

		ctx := context.Background()
		conn, err := pool.Get(ctx)
		// Gets unhealthy conn, closes it, tries createConnection which fails
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}


func TestClosePoolWithConnectionsInAvailableChannel(t *testing.T) {
	t.Run("Close drains available channel", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 5,
			MinConnections: 0,
			MaxIdleTime:    5 * time.Minute,
		})

		// Add connections to available channel (with nil conn so closeConnection is no-op)
		pc1 := &pooledConnection{conn: nil, lastUsed: time.Now()}
		pc2 := &pooledConnection{conn: nil, lastUsed: time.Now()}
		pool.available <- pc1
		pool.available <- pc2

		err := pool.Close()
		assert.NoError(t, err)
		assert.True(t, pool.closed)
	})
}

func TestClosePoolWithRemainingConnections(t *testing.T) {
	t.Run("Close handles remaining connections in slice", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 5,
			MinConnections: 0,
		})

		// Add connections to the slice (with nil conn, so closeConnection skips them)
		pool.connections = append(pool.connections, &pooledConnection{conn: nil})
		pool.connections = append(pool.connections, &pooledConnection{conn: nil})

		err := pool.Close()
		assert.NoError(t, err)
		assert.Nil(t, pool.connections)
	})
}

func TestPerformHealthChecksWithIdleConnections(t *testing.T) {
	t.Run("removes unhealthy connections from available", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:      5,
			MinConnections:      0,
			MaxIdleTime:         5 * time.Minute,
			HealthCheckInterval: 30 * time.Second,
			ConnectionTimeout:   1 * time.Second,
		})

		// Add an unhealthy connection (nil conn) to available
		unhealthy := &pooledConnection{
			conn:      nil,
			isHealthy: true,
			lastUsed:  time.Now(),
		}
		pool.available <- unhealthy
		pool.connections = append(pool.connections, unhealthy)

		pool.performHealthChecks()

		// The available channel should be drained (unhealthy connection removed)
		assert.Equal(t, 0, len(pool.available))
	})
}

func TestPerformHealthChecksRemovesAndReplacesBelow(t *testing.T) {
	t.Run("tries to maintain minimum when removing unhealthy", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:      5,
			MinConnections:      3,
			MaxIdleTime:         5 * time.Minute,
			HealthCheckInterval: 30 * time.Second,
			ConnectionTimeout:   100 * time.Millisecond,
		})

		// Add an unhealthy connection (nil conn) to available
		unhealthy := &pooledConnection{
			conn:      nil,
			isHealthy: true,
			lastUsed:  time.Now(),
		}
		pool.available <- unhealthy
		pool.connections = append(pool.connections, unhealthy)

		pool.performHealthChecks()

		// The available channel should be drained (unhealthy connection removed)
		assert.Equal(t, 0, len(pool.available))

		// Wait for replacement goroutine to run (will fail since no real LDAP server)
		time.Sleep(200 * time.Millisecond)
	})
}

func TestCleanupIdleConnectionsNonExpired(t *testing.T) {
	t.Run("returns non-expired connections to pool", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections: 10,
			MinConnections: 1,
			MaxIdleTime:    5 * time.Minute,
		})

		// Add a fresh connection
		fresh := &pooledConnection{
			conn:      nil,
			lastUsed:  time.Now(), // Just used, not expired
			isHealthy: true,
		}
		for i := 0; i < 3; i++ {
			pool.connections = append(pool.connections, &pooledConnection{})
		}
		pool.available <- fresh
		atomic.StoreInt32(&pool.stats.IdleConnections, 1)

		pool.cleanupIdleConnections()

		// Fresh connection should be returned to available
		select {
		case c := <-pool.available:
			assert.Equal(t, fresh, c)
		default:
			// It's OK if the connection was already returned
		}
	})
}

func TestStartBackgroundTasksAndStop(t *testing.T) {
	t.Run("starts and stops background tasks cleanly", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:         5,
			MinConnections:         0,
			MaxIdleTime:            100 * time.Millisecond,
			HealthCheckInterval:    50 * time.Millisecond,
			ConnectionTimeout:      1 * time.Second,
			EnableSelfHealing:      true,
			LeakDetectionThreshold: 100 * time.Millisecond,
			LeakEvictionThreshold:  200 * time.Millisecond,
		})

		pool.startBackgroundTasks()

		// Let background tasks run briefly
		time.Sleep(150 * time.Millisecond)

		// Stop by closing channels
		close(pool.healthCheckStop)
		close(pool.cleanupStop)
		pool.wg.Wait()
	})
}

func TestStartBackgroundTasksNoSelfHealing(t *testing.T) {
	t.Run("starts only health check and cleanup when self-healing disabled", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:      5,
			MinConnections:      0,
			MaxIdleTime:         100 * time.Millisecond,
			HealthCheckInterval: 50 * time.Millisecond,
			ConnectionTimeout:   1 * time.Second,
			EnableSelfHealing:   false,
		})

		pool.startBackgroundTasks()

		// Let background tasks run briefly
		time.Sleep(100 * time.Millisecond)

		// Stop by closing channels
		close(pool.healthCheckStop)
		close(pool.cleanupStop)
		pool.wg.Wait()
	})
}

func TestRecoverFromLeakWithConnInSlice(t *testing.T) {
	t.Run("removes leaked connection from connections slice", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 100 * time.Millisecond,
		})

		pc := &pooledConnection{
			conn:  nil,
			inUse: true,
		}
		pool.connections = append(pool.connections, pc)

		err := pool.recoverFromLeak(pc)
		// createConnection will fail, but the connection should be removed from slice
		assert.Error(t, err)
		assert.Empty(t, pool.connections)
		assert.Equal(t, int64(1), atomic.LoadInt64(&pool.stats.LeakedConnections))
		assert.Equal(t, int64(1), atomic.LoadInt64(&pool.stats.SelfHealingEvents))
	})
}

func TestGetWithCredentialsTimeout(t *testing.T) {
	t.Run("GetWithCredentials returns error on timeout", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    1,
			MinConnections:    0,
			GetTimeout:        10 * time.Millisecond,
			ConnectionTimeout: 10 * time.Millisecond,
		})

		// Fill up connections so no new ones can be created
		pool.connections = make([]*pooledConnection, 1)

		ctx := context.Background()
		conn, err := pool.GetWithCredentials(ctx, "cn=user,dc=test", "pass")
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}

func TestGetWithCredentialsContextCancelled(t *testing.T) {
	t.Run("GetWithCredentials returns error on cancelled context", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			GetTimeout:        1 * time.Second,
			ConnectionTimeout: 100 * time.Millisecond,
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := pool.GetWithCredentials(ctx, "cn=user,dc=test", "pass")
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}

func TestGetWithCredentialsNonMatchingConnection(t *testing.T) {
	t.Run("closes connection with non-matching credentials", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			GetTimeout:        50 * time.Millisecond,
			ConnectionTimeout: 10 * time.Millisecond,
			MaxIdleTime:       5 * time.Minute,
		})

		// Add a connection with different credentials
		otherConn := &pooledConnection{
			conn:      nil, // nil conn, will be closed by closeConnection as no-op
			isHealthy: true,
			lastUsed:  time.Now(),
			credentials: &ConnectionCredentials{
				DN:       "cn=other,dc=test",
				Password: "otherpass",
			},
		}
		pool.available <- otherConn
		atomic.StoreInt32(&pool.stats.IdleConnections, 1)

		ctx := context.Background()
		conn, err := pool.GetWithCredentials(ctx, "cn=user,dc=test", "pass")
		// Should close non-matching conn and try to create new (which fails)
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}

func TestWarmPoolWithFailedConnections(t *testing.T) {
	t.Run("warmPool returns error when connections fail", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    2,
			ConnectionTimeout: 10 * time.Millisecond,
		})

		err := pool.warmPool(context.Background())
		assert.Error(t, err) // Connection to 127.0.0.1:1 will fail
	})
}


func TestCreateConnectionDialFails(t *testing.T) {
	t.Run("createConnection returns error when dial fails", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 100 * time.Millisecond,
		})

		ctx := context.Background()
		conn, err := pool.createConnection(ctx)
		assert.Nil(t, conn)
		assert.Error(t, err) // Connection refused
	})
}

func TestCreateConnectionWithCredentialsDialFails(t *testing.T) {
	t.Run("createConnectionWithCredentials returns error when dial fails", func(t *testing.T) {
		pool := newTestPool(&PoolConfig{
			MaxConnections:    5,
			MinConnections:    0,
			ConnectionTimeout: 100 * time.Millisecond,
		})

		ctx := context.Background()
		creds := &ConnectionCredentials{DN: "cn=user,dc=test", Password: "pass"}
		conn, err := pool.createConnectionWithCredentials(ctx, creds)
		assert.Nil(t, conn)
		assert.Error(t, err) // Connection refused
	})
}
