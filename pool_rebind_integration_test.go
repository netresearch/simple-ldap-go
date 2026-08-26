//go:build integration

package ldap

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIntegration_OpenLDAP_RebindPooledConnToService is a regression test for
// #213. After a password check binds a borrowed connection as the end user,
// rebindPooledConnToService must restore the service-account identity before the
// connection returns to the pool, so the next borrower does not inherit the
// user's identity. Inspecting the connection directly (rather than draining the
// pool) makes the assertion deterministic — the pool's health check would
// otherwise discard a mis-bound connection and hide the leak.
func TestIntegration_OpenLDAP_RebindPooledConnToService(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	cfg := tc.Config
	cfg.Pool = &PoolConfig{
		MaxConnections:      2,
		MinConnections:      1,
		MaxIdleTime:         5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		ConnectionTimeout:   30 * time.Second,
		GetTimeout:          2 * time.Second,
	}

	client, err := New(cfg, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)
	require.NotNil(t, client.connPool, "connection pool must be enabled for this test")

	td := tc.GetTestData()

	// Borrow a pooled connection and rebind it as the end user, exactly as the
	// password-verification bind does.
	conn, err := client.connPool.Get(t.Context())
	require.NoError(t, err)
	require.NoError(t, conn.Bind(td.ValidUserDN, td.ValidUserPassword))

	who, err := conn.WhoAmI(nil)
	require.NoError(t, err)
	require.Contains(t, strings.ToLower(who.AuthzID), strings.ToLower(td.ValidUserUID),
		"setup: connection should now be bound as the user")

	// The fix under test: restore the service-account identity.
	client.rebindPooledConnToService(conn, "test")

	who, err = conn.WhoAmI(nil)
	require.NoError(t, err)
	authz := strings.ToLower(who.AuthzID)
	require.NotContains(t, authz, strings.ToLower(td.ValidUserUID),
		"connection must no longer be bound as the user after rebind (#213)")
	require.Contains(t, authz, "admin",
		"connection must be rebound to the service account, got %q", who.AuthzID)

	_ = client.connPool.Put(conn)
}
