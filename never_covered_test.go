//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The guards exercised here were the only never-executed branches in the
// package that are reachable without a directory server: comparing the
// non-integration and the integration coverage profiles left 562 statements
// with an execution count of zero in both, and all but these sit behind a live
// *ldap.Conn or are unreachable defensive arms.

// offlineClient builds a client without dialing. New() verifies the connection
// at construction, so a test that must not touch the network constructs the
// struct directly, as the existing mock tests do.
func offlineClient() *LDAP {
	return &LDAP{
		config: &Config{
			Server: "ldap://127.0.0.1:1",
			BaseDN: "dc=probe,dc=invalid",
		},
		logger: slog.Default(),
	}
}

// TestGenericsRejectInterfaceTypeArgument pins the guard that keeps the
// reflection in Search and FindByDN from dereferencing a nil type.
//
// LDAPObject is an interface, so `var zero T` for T = LDAPObject is a nil
// interface and reflect.TypeOf returns nil. Without the guard the next
// statement calls zeroType.Elem() and panics. The generic API accepts any T
// satisfying LDAPObject, and the interface itself satisfies it, so a caller
// can reach this by writing Search[LDAPObject] instead of Search[*User].
func TestGenericsRejectInterfaceTypeArgument(t *testing.T) {
	l := offlineClient()
	ctx := context.Background()

	t.Run("Search", func(t *testing.T) {
		objs, err := Search[LDAPObject](ctx, l, "(objectClass=*)", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot determine type for search")
		assert.Empty(t, objs)
	})

	t.Run("FindByDN", func(t *testing.T) {
		obj, err := FindByDN[LDAPObject](ctx, l, "cn=a,dc=probe,dc=invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot determine type for search")
		assert.Nil(t, obj)
	})

	t.Run("the guard runs before any connection is attempted", func(t *testing.T) {
		// The client above points at a closed port. A dial would surface as a
		// connection error; the type error proves the guard returns first.
		_, err := Search[LDAPObject](ctx, l, "(objectClass=*)", "")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "connection")
		assert.NotContains(t, err.Error(), "refused")
	})
}

// TestValidateServerURLPortOverflow covers the one port-validation branch a
// caller can actually reach. url.Parse rejects a non-numeric port before
// ValidateServerURL sees it, so the "invalid port format" arm is unreachable;
// a numeric port too large for an int is not, and must be refused rather than
// wrapping into a plausible-looking port number.
func TestValidateServerURLPortOverflow(t *testing.T) {
	err := ValidateServerURL("ldap://host:99999999999999999999")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port number")

	// Control: the same shape with an in-range port is accepted, so the
	// assertion above is about the overflow and not about the URL.
	require.NoError(t, ValidateServerURL("ldap://host:389"))
}

// TestParseGeneralizedTimeRejectsUnparsable pins the zero return for input that
// is not an LDAP GeneralizedTime. Returning a zero timestamp rather than a
// partially parsed one keeps "no value" distinguishable from a real epoch.
func TestParseGeneralizedTimeRejectsUnparsable(t *testing.T) {
	for _, in := range []string{"", "garbage", "2024-01-01T00:00:00Z", "20240101"} {
		assert.Zero(t, parseGeneralizedTime(in), "input %q", in)
	}

	// A fractional part is accepted with any number of digits, but only when
	// the value still ends in Z. Without the trailing Z the fraction is
	// stripped and the remainder would parse as a valid time, so this case
	// has to be rejected before that happens rather than after.
	assert.Zero(t, parseGeneralizedTime("20240101000000.123X"))
	assert.Zero(t, parseGeneralizedTime("20240101000000.1"))

	// Control: the same values with the trailing Z do parse, so the
	// assertions above measure the missing Z and not the fraction.
	assert.Equal(t, int64(1704067200), parseGeneralizedTime("20240101000000Z"))
	assert.Equal(t, int64(1704067200), parseGeneralizedTime("20240101000000.123Z"))
}

// TestEvictForSpaceRefusesOversizedEntry covers the ErrCacheFull path: an entry
// larger than the entire memory budget cannot be made room for, however much is
// evicted, and the cache must refuse it instead of exceeding MaxMemoryMB.
func TestEvictForSpaceRefusesOversizedEntry(t *testing.T) {
	cache, err := NewLRUCache(&CacheConfig{
		Enabled:         true,
		TTL:             time.Minute,
		MaxSize:         10,
		RefreshInterval: time.Minute,
		MaxMemoryMB:     1,
	}, slog.Default())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	// Two megabytes into a one-megabyte budget: nothing to evict, and evicting
	// everything would still not free enough.
	oversized := strings.Repeat("x", 2*1024*1024)
	err = cache.Set("oversized", oversized, time.Minute)
	require.ErrorIs(t, err, ErrCacheFull)

	// Control: a value that fits is stored, so the assertion above is about the
	// size and not about Set rejecting everything.
	require.NoError(t, cache.Set("small", "value", time.Minute))
	got, found := cache.Get("small")
	assert.True(t, found)
	assert.Equal(t, "value", got)
}
