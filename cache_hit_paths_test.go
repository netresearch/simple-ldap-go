//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// users.go / groups.go cache-hit happy paths — exercise the short-circuit
// return that happens before GetConnectionContext when the cache is populated.
// =============================================================================

func newExampleClientWithCache(t *testing.T) *LDAP {
	t.Helper()
	client, err := New(Config{
		Server: "ldap://example.com:389",
		BaseDN: "dc=example,dc=com",
	}, "admin", "pass")
	require.NoError(t, err)

	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cache, err := NewLRUCache(cfg, slog.Default())
	require.NoError(t, err)
	client.cache = cache
	client.config.EnableCache = true
	t.Cleanup(func() { _ = cache.Close() })
	return client
}

func TestFindUserByDN_CacheHit(t *testing.T) {
	client := newExampleClientWithCache(t)
	dn := "cn=cached,dc=example,dc=com"
	sam := "cached"
	cached := &User{
		Object:         Object{cn: "cached", dn: dn},
		SAMAccountName: sam,
		Enabled:        true,
	}
	require.NoError(t, client.cache.Set("user:dn:"+dn, cached, client.getCacheTTL()))

	got, err := client.FindUserByDN(dn)
	require.NoError(t, err)
	assert.Equal(t, sam, got.SAMAccountName)
}

func TestFindUserByMail_CacheHit(t *testing.T) {
	client := newExampleClientWithCache(t)
	mail := "cached@example.com"
	sam := "cached"
	cached := &User{
		Object:         Object{cn: "cached", dn: "cn=cached,dc=example,dc=com"},
		SAMAccountName: sam,
	}
	require.NoError(t, client.cache.Set("user:mail:"+mail, cached, client.getCacheTTL()))

	got, err := client.FindUserByMail(mail)
	require.NoError(t, err)
	assert.Equal(t, sam, got.SAMAccountName)
}

func TestFindUserBySAMAccountName_CacheHit(t *testing.T) {
	client := newExampleClientWithCache(t)
	sam := "cached"
	cached := &User{
		Object:         Object{cn: "cached", dn: "cn=cached,dc=example,dc=com"},
		SAMAccountName: sam,
	}
	require.NoError(t, client.cache.Set("user:sam:"+sam, cached, client.getCacheTTL()))

	got, err := client.FindUserBySAMAccountName(sam)
	require.NoError(t, err)
	assert.Equal(t, sam, got.SAMAccountName)
}

func TestFindGroupByDN_CacheHit(t *testing.T) {
	client := newExampleClientWithCache(t)
	dn := "cn=g,dc=example,dc=com"
	cached := &Group{
		Object:  Object{cn: "g", dn: dn},
		Members: []string{"cn=a,dc=example,dc=com"},
	}
	require.NoError(t, client.cache.Set("group:dn:"+dn, cached, client.getCacheTTL()))

	got, err := client.FindGroupByDN(dn)
	require.NoError(t, err)
	assert.Equal(t, "g", got.CN())
	assert.Len(t, got.Members, 1)
}

func TestClearCache_Populated(t *testing.T) {
	client := newExampleClientWithCache(t)
	require.NoError(t, client.cache.Set("any:key", 42, client.getCacheTTL()))
	client.ClearCache()
	_, found := client.cache.Get("any:key")
	assert.False(t, found)
}

// Context cancellation after a cache hit short-circuit isn't possible — the
// cache-hit branch returns early. But we can check that cache ops respect
// nil values.
func TestFindUserByDN_CacheHitNoPanicOnWrongType(t *testing.T) {
	client := newExampleClientWithCache(t)
	dn := "cn=x,dc=example,dc=com"
	// Store a value that is NOT a *User at the cache slot — the look-up
	// should fall through to the LDAP path (and fail at GetConnection).
	require.NoError(t, client.cache.Set("user:dn:"+dn, "not a user", client.getCacheTTL()))
	_, err := client.FindUserByDN(dn)
	assert.Error(t, err) // falls through to LDAP, which errors against example server
}

func TestFindUserBySAMAccountName_UsesCache(t *testing.T) {
	// Calling twice should hit cache second time.
	client := newExampleClientWithCache(t)
	sam := "sticky"
	cached := &User{
		Object:         Object{cn: "sticky", dn: "cn=sticky,dc=example,dc=com"},
		SAMAccountName: sam,
	}
	require.NoError(t, client.cache.Set("user:sam:"+sam, cached, client.getCacheTTL()))

	ctx := context.Background()
	u1, err := client.FindUserBySAMAccountNameContext(ctx, sam)
	require.NoError(t, err)
	u2, err := client.FindUserBySAMAccountNameContext(ctx, sam)
	require.NoError(t, err)
	assert.Equal(t, u1.SAMAccountName, u2.SAMAccountName)
}
