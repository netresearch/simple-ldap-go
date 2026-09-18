package ldap

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// poolWithStats builds a pool that is never started and never dials: only the
// two fields applyPoolStats reads are set. Every counter gets a distinct value
// so a field copied from the wrong source shows up as a wrong number rather
// than as a coincidence.
func poolWithStats(maxConnections, minConnections int, stats PoolStats) *ConnectionPool {
	return &ConnectionPool{
		config: &PoolConfig{
			MaxConnections: maxConnections,
			MinConnections: minConnections,
		},
		stats: stats,
	}
}

func TestApplyPoolStatsPopulatesTheFlatFields(t *testing.T) {
	pool := poolWithStats(20, 3, PoolStats{
		ActiveConnections:  4,
		IdleConnections:    6,
		TotalConnections:   10,
		PoolHits:           11,
		PoolMisses:         12,
		HealthChecksPassed: 13,
		HealthChecksFailed: 14,
		ConnectionsCreated: 15,
		ConnectionsClosed:  16,
	})

	stats := PerformanceMetrics{}
	applyPoolStats(&stats, pool)

	// The ten fields #247 is about. Each was zero for every real server before.
	assert.Equal(t, int64(11), stats.PoolHits)
	assert.Equal(t, int64(12), stats.PoolMisses)
	assert.Equal(t, 10, stats.TotalConnections)
	assert.Equal(t, int64(15), stats.ConnectionsCreated)
	assert.Equal(t, 4, stats.ActiveConnections)
	assert.Equal(t, 6, stats.IdleConnections)
	assert.Equal(t, int64(13), stats.HealthChecksPassed)
	assert.Equal(t, int64(14), stats.HealthChecksFailed)
	assert.Equal(t, int64(16), stats.ConnectionsClosed)
	assert.InDelta(t, 4.0/20.0, stats.ConnectionPoolRatio, 1e-9)

	// The nested snapshot keeps reporting, and now carries the ceiling it used
	// to leave at zero with a "would need config" comment.
	require.NotNil(t, stats.PoolStats)
	assert.Equal(t, 20, stats.PoolStats.MaxConnections)
	assert.Equal(t, 3, stats.PoolStats.MinConnections)
	assert.Equal(t, 4, stats.PoolStats.ActiveConnections)
	assert.Equal(t, 6, stats.PoolStats.IdleConnections)
	assert.Equal(t, int64(11), stats.PoolStats.PoolHits)
	assert.Equal(t, int64(12), stats.PoolStats.PoolMisses)
}

func TestApplyPoolStatsWithoutAPoolLeavesStatsAlone(t *testing.T) {
	stats := PerformanceMetrics{OperationsTotal: 7}
	applyPoolStats(&stats, nil)

	// No pool configured must stay distinguishable from a pool reporting zero:
	// PoolStats stays nil, so the JSON omits it rather than publishing zeros.
	assert.Nil(t, stats.PoolStats)
	assert.Equal(t, 0, stats.TotalConnections)
	assert.Equal(t, int64(7), stats.OperationsTotal)
}

func TestPoolUtilisation(t *testing.T) {
	tests := []struct {
		name           string
		active         int
		maxConnections int
		expected       float64
	}{
		{"empty pool", 0, 10, 0},
		{"half checked out", 5, 10, 0.5},
		{"saturated", 10, 10, 1},
		{"unknown ceiling reports no ratio", 4, 0, 0},
		{"negative ceiling reports no ratio", 4, -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.InDelta(t, tt.expected, poolUtilisation(tt.active, tt.maxConnections), 1e-9)
		})
	}
}

// A pool without EnableMetrics is an ordinary configuration — Config.Pool is
// read on its own — and it used to report zeros from GetPoolStats because the
// performance monitor, which is where the pool was read, did not exist.
func TestGetPoolStatsReadsThePoolWithoutAPerformanceMonitor(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://directory.internal:389",
			BaseDN: "DC=internal",
		},
		logger:   slog.Default(),
		connPool: poolWithStats(10, 1, PoolStats{ActiveConnections: 2, IdleConnections: 3, TotalConnections: 5, PoolHits: 9}),
	}
	require.Nil(t, client.perfMonitor, "this test covers the no-monitor path")

	stats := client.GetPoolStats()

	// The predicate netresearch/ldap-manager builds its readiness probe on.
	assert.Positive(t, stats.TotalConnections, "readiness probes test TotalConnections > 0")
	assert.Equal(t, 5, stats.TotalConnections)
	assert.Equal(t, 2, stats.ActiveConnections)
	assert.Equal(t, 3, stats.IdleConnections)
	assert.Equal(t, int64(9), stats.PoolHits)
}
