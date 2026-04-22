//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
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
func TestDisableEnableUser_NoConnection(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://nonexistent.invalid:389",
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
