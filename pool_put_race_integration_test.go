//go:build integration

package ldap

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIntegration_OpenLDAP_PoolPutDoesNotTouchAPublishedConnection is a
// regression test for a data race between Put and Get, and it only means
// something under -race, which the integration targets pass.
//
// Put sent the connection back on p.available and then read its lastUsed and
// usageCount for a debug log. Once the send completes another goroutine can
// own the connection, and Get writes both fields — lastUsed plainly and
// usageCount atomically — so the log read raced either write.
// netresearch/ldap-manager hit it on its first use of the pool: its cache
// warm-up runs three searches concurrently through one client.
//
// Connections go back through Put, which is the path that raced. The older
// TestConnectionPool_Concurrency returns them with conn.Close(), which never
// reaches Put, and its !integration tag plus the short-mode skip mean it runs
// in neither CI tier.
func TestIntegration_OpenLDAP_PoolPutDoesNotTouchAPublishedConnection(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	// Fewer connections than goroutines, so every Put hands a connection
	// straight to a waiting Get: the interleaving the race needs.
	poolConfig := &PoolConfig{
		MaxConnections:      2,
		MinConnections:      2,
		MaxIdleTime:         5 * time.Minute,
		HealthCheckInterval: time.Hour,
		ConnectionTimeout:   30 * time.Second,
		GetTimeout:          30 * time.Second,
	}

	pool, err := NewConnectionPool(poolConfig, tc.Config, tc.AdminUser, tc.AdminPass, nil)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	const goroutines = 8
	const rounds = 25

	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*rounds)

	for range goroutines {
		wg.Go(func() {
			for range rounds {
				conn, getErr := pool.Get(ctx)
				if getErr != nil {
					errs <- getErr

					return
				}
				if putErr := pool.Put(conn); putErr != nil {
					errs <- putErr

					return
				}
			}
		})
	}

	wg.Wait()
	close(errs)

	for e := range errs {
		require.NoError(t, e)
	}

	stats := pool.Stats()
	require.Equal(t, int32(0), stats.ActiveConnections, "every connection must be back in the pool")
	require.Positive(t, stats.PoolHits, "connections must have been reused, or Put was never reached")
}
