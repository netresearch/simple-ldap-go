//go:build integration

package ldap

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIntegration_OpenLDAP_RateLimitCaseFolding is a regression test for #216:
// the rate-limit key must be case-folded so an attacker cannot reset the
// per-account attempt counter by rotating the case of the identifier.
func TestIntegration_OpenLDAP_RateLimitCaseFolding(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
	require.NoError(t, err)

	// MaxAttempts=2: the third CheckLimit call on one key is blocked.
	client.rateLimiter = NewRateLimiter(&RateLimiterConfig{
		MaxAttempts:     2,
		Window:          15 * time.Minute,
		LockoutDuration: 30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
		MaxEntries:      100,
	}, slog.Default())

	td := tc.GetTestData()
	upper := strings.ToUpper(td.ValidUserUID)
	lower := td.ValidUserUID

	// Two failed attempts under different case variants of the same account.
	_, _ = client.CheckPasswordForSAMAccountName(upper, "wrong-password")
	_, _ = client.CheckPasswordForSAMAccountName(lower, "wrong-password")

	// A third attempt — even with the correct password and yet another case —
	// must be blocked by rate limiting, proving the counter is shared. Without
	// key folding each variant has its own counter and this would succeed.
	mixed := strings.ToUpper(lower[:1]) + lower[1:]
	_, err = client.CheckPasswordForSAMAccountName(mixed, td.ValidUserPassword)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rate limiting",
		"third attempt must be blocked by the shared, case-folded rate-limit counter")
}
