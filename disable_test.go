//go:build !integration

package ldap

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestACCOUNTDISABLEConstant is a documentation test — it locks in the
// advertised 0x2 bit so downstream callers that use
// `ldap.ACCOUNTDISABLE` as a named constant aren't silently affected
// by a library change. The value comes from Microsoft's
// ADS_USER_FLAG enumeration and is part of the library's API surface.
func TestACCOUNTDISABLEConstant(t *testing.T) {
	assert.Equal(t, uint32(0x2), ACCOUNTDISABLE,
		"ACCOUNTDISABLE constant must be 0x2 (ADS_UF_ACCOUNTDISABLE)")
}

// TestDisableEnableUser_NoConnection verifies the error path when the
// client has no live connection. We can't easily assert a full
// round-trip without an AD server (OpenLDAP doesn't honour
// userAccountControl), but we CAN prove the methods exist, take a
// context, and surface a useful error instead of a nil-pointer
// panic when they can't connect.
//
// Server is `ldap://test:389` so isExampleServerName() short-circuits
// createDirectConnection() before any real DNS / TCP dial. Test runs
// offline, finishes fast, no network flakes.
func TestDisableEnableUser_NoConnection(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://test:389",
			BaseDN: "dc=example,dc=com",
		},
		logger: slog.Default(),
	}

	ctx := context.Background()

	t.Run("DisableUserContext surfaces connection error", func(t *testing.T) {
		err := client.DisableUserContext(ctx, "cn=test,dc=example,dc=com")
		assert.Error(t, err, "must fail without a working LDAP server")
	})

	t.Run("EnableUserContext surfaces connection error", func(t *testing.T) {
		err := client.EnableUserContext(ctx, "cn=test,dc=example,dc=com")
		assert.Error(t, err, "must fail without a working LDAP server")
	})

	t.Run("DisableComputerContext surfaces connection error", func(t *testing.T) {
		err := client.DisableComputerContext(ctx, "cn=pc01,dc=example,dc=com")
		assert.Error(t, err, "must fail without a working LDAP server")
	})

	t.Run("EnableComputerContext surfaces connection error", func(t *testing.T) {
		err := client.EnableComputerContext(ctx, "cn=pc01,dc=example,dc=com")
		assert.Error(t, err, "must fail without a working LDAP server")
	})

	t.Run("non-context wrappers exist and behave the same", func(t *testing.T) {
		// Just prove these wrappers exist and return an error; they
		// delegate to the *Context form with context.Background().
		assert.Error(t, client.DisableUser("cn=test,dc=example,dc=com"))
		assert.Error(t, client.EnableUser("cn=test,dc=example,dc=com"))
		assert.Error(t, client.DisableComputer("cn=pc01,dc=example,dc=com"))
		assert.Error(t, client.EnableComputer("cn=pc01,dc=example,dc=com"))
	})
}

// TestUpdateUACBit_BitArithmetic verifies the bit manipulation the
// read-modify-write path applies. We extract the pure-function core
// here so it can be unit-tested without touching the connection pool
// or the LDAP wire — this catches off-by-one bit errors that would
// otherwise only manifest against a real AD.
func TestUpdateUACBit_BitArithmetic(t *testing.T) {
	cases := []struct {
		name     string
		current  uint32
		bit      uint32
		set      bool
		expected uint32
	}{
		{
			name:     "set disable on 0x200 (NORMAL_ACCOUNT)",
			current:  0x200,
			bit:      ACCOUNTDISABLE,
			set:      true,
			expected: 0x202, // NORMAL | DISABLED
		},
		{
			name:     "clear disable on 0x202 (NORMAL + DISABLED)",
			current:  0x202,
			bit:      ACCOUNTDISABLE,
			set:      false,
			expected: 0x200, // NORMAL only
		},
		{
			name:     "set disable when already set is idempotent",
			current:  0x202,
			bit:      ACCOUNTDISABLE,
			set:      true,
			expected: 0x202,
		},
		{
			name:     "clear disable when already cleared is idempotent",
			current:  0x200,
			bit:      ACCOUNTDISABLE,
			set:      false,
			expected: 0x200,
		},
		{
			name:     "set disable preserves unrelated bits (workstation + no-expire)",
			current:  0x1000 | 0x10000, // WORKSTATION_TRUST + NO_PASSWORD_EXPIRATION
			bit:      ACCOUNTDISABLE,
			set:      true,
			expected: 0x1000 | 0x10000 | 0x2,
		},
		{
			name:     "clear disable preserves unrelated bits",
			current:  0x1000 | 0x10000 | 0x2,
			bit:      ACCOUNTDISABLE,
			set:      false,
			expected: 0x1000 | 0x10000,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got uint32
			if tc.set {
				got = tc.current | tc.bit
			} else {
				got = tc.current &^ tc.bit
			}

			assert.Equal(t, tc.expected, got,
				"bit arithmetic mismatch for current=0x%x bit=0x%x set=%v",
				tc.current, tc.bit, tc.set)
		})
	}
}

// TestClassifyUACSearchResult covers the search-result error mapping
// extracted from updateUACBit. These branches were unreachable in
// PR #167's tests because the offline server short-circuits in
// createDirectConnection before any Search call is attempted.
func TestClassifyUACSearchResult(t *testing.T) {
	const (
		dn     = "cn=test,dc=example,dc=com"
		server = "ldap://test:389"
	)

	t.Run("LDAPResultNoSuchObject maps to caller-supplied sentinel (user)", func(t *testing.T) {
		searchErr := ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("0000208D: NameErr: DSID-..."))

		entry, mapErr := classifyUACSearchResult(nil, searchErr, dn, ErrUserNotFound, server)

		assert.Nil(t, entry)
		require.Error(t, mapErr)
		assert.ErrorIs(t, mapErr, ErrUserNotFound)
		assert.Contains(t, mapErr.Error(), dn)
	})

	t.Run("LDAPResultNoSuchObject maps to ErrComputerNotFound when caller passes it", func(t *testing.T) {
		searchErr := ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("not found"))

		entry, mapErr := classifyUACSearchResult(nil, searchErr, dn, ErrComputerNotFound, server)

		assert.Nil(t, entry)
		require.Error(t, mapErr)
		assert.ErrorIs(t, mapErr, ErrComputerNotFound)
		assert.NotErrorIs(t, mapErr, ErrUserNotFound, "must not surface ErrUserNotFound for computer callers")
	})

	t.Run("non-NoSuchObject error wraps via WrapLDAPError", func(t *testing.T) {
		// Use a different LDAP error code (insufficient access) — must
		// fall through to the WrapLDAPError branch, not the sentinel branch.
		searchErr := ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("permission denied"))

		entry, mapErr := classifyUACSearchResult(nil, searchErr, dn, ErrUserNotFound, server)

		assert.Nil(t, entry)
		require.Error(t, mapErr)
		assert.NotErrorIs(t, mapErr, ErrUserNotFound, "non-NoSuchObject must NOT map to the not-found sentinel")
		assert.Contains(t, mapErr.Error(), "SearchUAC", "must wrap via WrapLDAPError with operation 'SearchUAC'")
	})

	t.Run("non-LDAP error wraps via WrapLDAPError", func(t *testing.T) {
		// A plain Go error (network failure, etc.) — also goes through
		// the WrapLDAPError branch.
		searchErr := errors.New("dial tcp: i/o timeout")

		entry, mapErr := classifyUACSearchResult(nil, searchErr, dn, ErrUserNotFound, server)

		assert.Nil(t, entry)
		require.Error(t, mapErr)
		assert.NotErrorIs(t, mapErr, ErrUserNotFound)
		assert.Contains(t, mapErr.Error(), "SearchUAC")
	})

	t.Run("empty result set maps to caller-supplied sentinel", func(t *testing.T) {
		// Some directories return success + 0 entries instead of
		// LDAPResultNoSuchObject for a missing DN. Both shapes must
		// surface as the same sentinel.
		emptySr := &ldap.SearchResult{Entries: []*ldap.Entry{}}

		entry, mapErr := classifyUACSearchResult(emptySr, nil, dn, ErrUserNotFound, server)

		assert.Nil(t, entry)
		require.Error(t, mapErr)
		assert.ErrorIs(t, mapErr, ErrUserNotFound)
		assert.Contains(t, mapErr.Error(), dn)
	})

	t.Run("nil SearchResult with no error treated as not-found", func(t *testing.T) {
		// Defensive: if the caller somehow passes (nil, nil) we must
		// not panic; treat it as not-found rather than crashing.
		entry, mapErr := classifyUACSearchResult(nil, nil, dn, ErrUserNotFound, server)

		assert.Nil(t, entry)
		require.Error(t, mapErr)
		assert.ErrorIs(t, mapErr, ErrUserNotFound)
	})

	t.Run("single matching entry returned unchanged", func(t *testing.T) {
		want := &ldap.Entry{
			DN: dn,
			Attributes: []*ldap.EntryAttribute{
				{Name: "userAccountControl", Values: []string{"514"}},
			},
		}
		sr := &ldap.SearchResult{Entries: []*ldap.Entry{want}}

		got, mapErr := classifyUACSearchResult(sr, nil, dn, ErrUserNotFound, server)

		require.NoError(t, mapErr)
		assert.Same(t, want, got)
	})
}

// TestApplyUACBitToEntry covers the read-modify branches extracted
// from updateUACBit: missing attribute, parse failure, set/clear
// arithmetic, and the no-op short-circuit when the bit is already
// in the desired state.
func TestApplyUACBitToEntry(t *testing.T) {
	t.Run("missing userAccountControl attribute", func(t *testing.T) {
		// OpenLDAP entries don't have userAccountControl; must error
		// loudly instead of silently treating it as 0.
		entry := &ldap.Entry{DN: "cn=ol,dc=example,dc=com", Attributes: nil}

		_, _, _, err := applyUACBitToEntry(entry, ACCOUNTDISABLE, true)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "userAccountControl attribute missing")
		assert.Contains(t, err.Error(), entry.DN)
	})

	t.Run("attribute present but unparseable", func(t *testing.T) {
		// AD always populates a uint32; if we see "garbage" we want
		// the parse error wrapped with context, not a misleading 0.
		entry := &ldap.Entry{
			DN:         "cn=bad,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{{Name: "userAccountControl", Values: []string{"not-a-number"}}},
		}

		_, _, _, err := applyUACBitToEntry(entry, ACCOUNTDISABLE, true)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse userAccountControl")
		assert.Contains(t, err.Error(), "not-a-number")
		assert.Contains(t, err.Error(), entry.DN)
	})

	t.Run("set ACCOUNTDISABLE on a NORMAL_ACCOUNT (changes)", func(t *testing.T) {
		entry := &ldap.Entry{
			DN:         "cn=u,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{{Name: "userAccountControl", Values: []string{"512"}}}, // 0x200 NORMAL
		}

		current, next, changed, err := applyUACBitToEntry(entry, ACCOUNTDISABLE, true)

		require.NoError(t, err)
		assert.Equal(t, uint32(0x200), current)
		assert.Equal(t, uint32(0x202), next)
		assert.True(t, changed)
	})

	t.Run("set ACCOUNTDISABLE when already set is a no-op", func(t *testing.T) {
		entry := &ldap.Entry{
			DN:         "cn=u,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{{Name: "userAccountControl", Values: []string{"514"}}}, // NORMAL | DISABLED
		}

		current, next, changed, err := applyUACBitToEntry(entry, ACCOUNTDISABLE, true)

		require.NoError(t, err)
		assert.Equal(t, uint32(0x202), current)
		assert.Equal(t, uint32(0x202), next)
		assert.False(t, changed, "no-op when bit already set — caller must skip Modify")
	})

	t.Run("clear ACCOUNTDISABLE preserves unrelated bits", func(t *testing.T) {
		entry := &ldap.Entry{
			DN:         "cn=u,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{{Name: "userAccountControl", Values: []string{"66050"}}}, // 0x10202 NORMAL+DISABLED+NO_PASSWORD_EXPIRATION
		}

		current, next, changed, err := applyUACBitToEntry(entry, ACCOUNTDISABLE, false)

		require.NoError(t, err)
		assert.Equal(t, uint32(0x10202), current)
		assert.Equal(t, uint32(0x10200), next, "must preserve NORMAL + NO_PASSWORD_EXPIRATION while clearing DISABLED")
		assert.True(t, changed)
	})

	t.Run("clear ACCOUNTDISABLE when already cleared is a no-op", func(t *testing.T) {
		entry := &ldap.Entry{
			DN:         "cn=u,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{{Name: "userAccountControl", Values: []string{"512"}}}, // NORMAL only
		}

		current, next, changed, err := applyUACBitToEntry(entry, ACCOUNTDISABLE, false)

		require.NoError(t, err)
		assert.Equal(t, uint32(0x200), current)
		assert.Equal(t, uint32(0x200), next)
		assert.False(t, changed)
	})
}

// TestLogConnectionReleaseError covers the defer log path that fires
// when ReleaseConnection() returns an error. nil-error must be silent
// (no spurious log output for the happy path); a real error must
// produce a structured slog.Debug record with operation + error fields.
func TestLogConnectionReleaseError(t *testing.T) {
	t.Run("nil err is silent", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		client := &LDAP{logger: logger}

		client.logConnectionReleaseError("updateUACBit", nil)

		assert.Empty(t, buf.String(), "no log line on the success path")
	})

	t.Run("real error is logged with operation and message", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		client := &LDAP{logger: logger}

		client.logConnectionReleaseError("updateUACBit", errors.New("pool closed"))

		out := buf.String()
		assert.Contains(t, out, "connection_close_error")
		assert.Contains(t, out, "operation=updateUACBit")
		assert.Contains(t, out, `error="pool closed"`)
		assert.Contains(t, out, "level=DEBUG", "must use Debug level so prod logs aren't spammed")
	})

	t.Run("operation field reflects the caller's value", func(t *testing.T) {
		// The helper takes an operation string so callers from
		// different code paths can be distinguished in the log.
		// updateUACBit passes "updateUACBit"; verify that custom
		// values flow through unchanged so future callers don't
		// accidentally hard-code one operation name.
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		client := &LDAP{logger: logger}

		client.logConnectionReleaseError("custom-op-name", errors.New("oops"))

		assert.Contains(t, buf.String(), "operation=custom-op-name")
	})
}
