//go:build integration

package ldap

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIntegration_OpenLDAP_DNTimingMitigation is a regression test for #219:
// a lookup failure on the DN path must get the same treatment as one on the
// sAMAccountName path. The observable for the fix is the rate limiter's
// FailedAuth metric — pre-#219 the not-found path returned before any
// recording, so the metric stayed at zero (CheckLimit's own attempt counting
// is unaffected either way and is NOT what this test pins).
func TestIntegration_OpenLDAP_DNTimingMitigation(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	t.Run("nonexistent DN records a failed attempt", func(t *testing.T) {
		client, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		client.rateLimiter = NewRateLimiter(&RateLimiterConfig{
			MaxAttempts:     10,
			Window:          15 * time.Minute,
			LockoutDuration: 30 * time.Minute,
			CleanupInterval: 5 * time.Minute,
			MaxEntries:      100,
		}, slog.Default())

		missing := "cn=definitely-not-there," + tc.Config.BaseDN

		_, err = client.CheckPasswordForDN(missing, "irrelevant")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrUserNotFound)

		require.Equal(t, int64(1), client.rateLimiter.GetMetrics().FailedAuth,
			"an enumeration probe against a nonexistent DN must be recorded as a failed attempt, as on the sAMAccountName path")
	})

	t.Run("DN with metacharacters is dummy-bound without injection", func(t *testing.T) {
		// Guards the escaping of the new dummy-bind path: the (escaped)
		// identifier is interpolated into a DN; a value full of DN
		// metacharacters must yield a plain not-found error, not a bind
		// against an injected structure or a panic.
		client, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		_, err = client.CheckPasswordForDN("cn=x,cn=admin,"+tc.Config.BaseDN, "irrelevant")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrUserNotFound)
	})
}
