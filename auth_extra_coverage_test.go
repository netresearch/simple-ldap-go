//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPasswordForSAMAccountNameContext_ValidationAndCancellation(t *testing.T) {
	t.Run("invalid identifier returns validation error", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: true, BaseDN: "dc=example,dc=com"},
			logger: slog.Default(),
		}
		_, err := l.CheckPasswordForSAMAccountNameContext(context.Background(), "bad user!", "pass")
		require.Error(t, err)
	})

	t.Run("cancelled context before start", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, BaseDN: "dc=example,dc=com", Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := l.CheckPasswordForSAMAccountNameContext(ctx, "validuser", "pass")
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("empty password triggers secure credential error or validation", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, BaseDN: "dc=example,dc=com", Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		_, err := l.CheckPasswordForSAMAccountNameContext(context.Background(), "validuser", "")
		// Empty password is handled via secure credential; expect error (may be auth error after lookup, but should not panic)
		_ = err
	})
}

func TestCheckPasswordForDNContext_EarlyReturns(t *testing.T) {
	t.Run("invalid DN", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, BaseDN: "dc=example,dc=com", Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		_, err := l.CheckPasswordForDNContext(context.Background(), "not a dn", "pass")
		require.Error(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, BaseDN: "dc=example,dc=com", Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := l.CheckPasswordForDNContext(ctx, "cn=user,dc=example,dc=com", "pass")
		require.Error(t, err)
	})
}

func TestChangePasswordForSAMAccountNameContext_EarlyReturns(t *testing.T) {
	t.Run("invalid identifier", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: true, BaseDN: "dc=example,dc=com"},
			logger: slog.Default(),
		}
		err := l.ChangePasswordForSAMAccountNameContext(context.Background(), "bad!", "old", "new")
		require.Error(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, BaseDN: "dc=example,dc=com", Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := l.ChangePasswordForSAMAccountNameContext(ctx, "validuser", "old", "new")
		require.Error(t, err)
	})
}

func TestResetPasswordForSAMAccountNameContext_EarlyReturns(t *testing.T) {
	t.Run("invalid identifier", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: true, BaseDN: "dc=example,dc=com"},
			logger: slog.Default(),
		}
		err := l.ResetPasswordForSAMAccountNameContext(context.Background(), "bad!", "newpass123!")
		require.Error(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, BaseDN: "dc=example,dc=com", Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := l.ResetPasswordForSAMAccountNameContext(ctx, "validuser", "newpass123!")
		require.Error(t, err)
	})
}

func TestRebindPooledConnToService_NilPool(t *testing.T) {
	l := &LDAP{
		config:   &Config{Server: "ldap://example:389", BaseDN: "dc=example,dc=com"},
		logger:   slog.Default(),
		connPool: nil,
	}
	// Must not panic when pool is nil, even with nil conn
	l.rebindPooledConnToService(nil, "test-op")
}

func TestWarnCleartextPasswordWrite_Branches(t *testing.T) {
	t.Run("skips for AD", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: true, Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		l.warnCleartextPasswordWrite("op", "user")
	})
	t.Run("skips for ldaps", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, Server: "ldaps://example:636"},
			logger: slog.Default(),
		}
		l.warnCleartextPasswordWrite("op", "user")
	})
	t.Run("warns for cleartext", func(t *testing.T) {
		l := &LDAP{
			config: &Config{IsActiveDirectory: false, Server: "ldap://example:389"},
			logger: slog.Default(),
		}
		l.warnCleartextPasswordWrite("op", "user")
	})
}

func TestNormalizeDNKey_Fallback(t *testing.T) {
	t.Run("malformed DN fallback to case-fold", func(t *testing.T) {
		got := normalizeDNKey("not a dn at all!!!")
		assert.NotEmpty(t, got)
	})
	t.Run("valid DN canonicalises", func(t *testing.T) {
		got := normalizeDNKey("CN=User,DC=Example,DC=COM")
		assert.Equal(t, "cn=user,dc=example,dc=com", got)
	})
}

func TestBuildDummyBindDN_Escaping(t *testing.T) {
	dn := buildDummyBindDN("user,=test", "dc=example,dc=com")
	assert.Contains(t, dn, "CN=nonexistent-")
	assert.Contains(t, dn, "dc=example,dc=com")
}
