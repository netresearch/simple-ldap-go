//go:build integration

package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_OpenLDAP_PoolStatsReportAgainstARealServer pins #247 end to
// end: against a real directory with a pool configured, GetPoolStats must
// report the pool it has. Every one of these fields was zero before, so a
// readiness probe built on TotalConnections > 0 — netresearch/ldap-manager's —
// could never become ready.
//
// The unit tests beside this one drive applyPoolStats directly. This one is
// what proves the wiring from New through to the public accessor, which is the
// part a hand-built pool cannot show.
func TestIntegration_OpenLDAP_PoolStatsReportAgainstARealServer(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	cfg := tc.Config
	cfg.Pool = &PoolConfig{
		MaxConnections:      4,
		MinConnections:      2,
		MaxIdleTime:         5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		ConnectionTimeout:   30 * time.Second,
		GetTimeout:          2 * time.Second,
	}

	client, err := New(cfg, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NotNil(t, client.connPool, "setup: the pool must be enabled for this test")

	// No EnableMetrics and no EnableOptimizations here on purpose: Config.Pool is
	// read on its own, and that is the configuration that reported zeros.
	require.Nil(t, client.perfMonitor, "setup: this case covers the no-monitor path")

	stats := client.GetPoolStats()

	assert.Positive(t, stats.TotalConnections,
		"a configured pool must report its connections; readiness probes test TotalConnections > 0 (#247)")
	assert.GreaterOrEqual(t, stats.TotalConnections, 2, "MinConnections: 2 were pre-warmed")
	assert.Positive(t, stats.IdleConnections, "the pre-warmed connections are idle")
	assert.Positive(t, stats.ConnectionsCreated, "warming the pool creates connections")

	require.NotNil(t, stats.PoolStats)
	assert.Equal(t, 4, stats.PoolStats.MaxConnections)
	assert.Equal(t, 2, stats.PoolStats.MinConnections)

	// New tests the connection through the pool. Releasing it is what keeps the
	// ratio honest: without that release one slot stays checked out forever.
	assert.Zero(t, stats.ActiveConnections,
		"no operation is in flight, so nothing may be checked out after New")
	assert.InDelta(t, 0.0, stats.ConnectionPoolRatio, 1e-9,
		"an idle pool is at zero utilisation")

	// And the ratio follows a real checkout.
	conn, err := client.GetConnection()
	require.NoError(t, err)
	busy := client.GetPoolStats()
	assert.Equal(t, 1, busy.ActiveConnections)
	assert.InDelta(t, 1.0/4.0, busy.ConnectionPoolRatio, 1e-9)
	require.NoError(t, client.ReleaseConnection(conn))
}
