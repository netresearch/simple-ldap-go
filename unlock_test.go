//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUnlockAttributes pins the Active Directory unlock semantics:
// unlocking an account must set lockoutTime to 0.
func TestUnlockAttributes(t *testing.T) {
	assert.Equal(t, map[string][]string{
		"lockoutTime": {"0"},
	}, unlockAttributes())
}

// TestUnlockUser_NonActiveDirectory verifies that account unlock is
// rejected explicitly when the client is not configured for Active Directory.
func TestUnlockUser_NonActiveDirectory(t *testing.T) {
	client := &LDAP{
		config: &Config{
			IsActiveDirectory: false,
		},
	}

	err := client.UnlockUser("uid=testuser,dc=example,dc=com")

	assert.ErrorIs(t, err, ErrUnlockRequiresActiveDirectory)
}

func TestUnlockUserForSAMAccountName_NonActiveDirectory(t *testing.T) {
	client := &LDAP{
		config: &Config{
			IsActiveDirectory: false,
		},
	}

	err := client.UnlockUserForSAMAccountName("testuser")

	assert.ErrorIs(t, err, ErrUnlockRequiresActiveDirectory)
}

// TestUnlockUser_NoConnection verifies that the unlock methods surface
// a connection error instead of panicking when no LDAP server is
// available.
//
// Server is ldap://test:389 so isExampleServerName() short-circuits
// before any real network connection is attempted.
func TestUnlockUser_NoConnection(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server:            "ldap://test:389",
			BaseDN:            "dc=example,dc=com",
			IsActiveDirectory: true,
		},
		logger: slog.Default(),
	}

	ctx := context.Background()
	dn := "cn=test,dc=example,dc=com"

	t.Run("UnlockUserContext surfaces connection error", func(t *testing.T) {
		err := client.UnlockUserContext(ctx, dn)
		assert.Error(t, err, "must fail without a working LDAP server")
	})

	t.Run("non-context wrapper exists and behaves the same", func(t *testing.T) {
		err := client.UnlockUser(dn)
		assert.Error(t, err, "must fail without a working LDAP server")
	})
}

// TestUnlockUserForSAMAccountName_InvalidIdentifier verifies that invalid
// account identifiers are rejected before any LDAP operation is attempted.
func TestUnlockUserForSAMAccountName_InvalidIdentifier(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server:            "ldap://test:389",
			BaseDN:            "dc=example,dc=com",
			IsActiveDirectory: true,
		},
		logger: slog.Default(),
	}

	t.Run("empty sAMAccountName", func(t *testing.T) {
		err := client.UnlockUserForSAMAccountName("")
		assert.ErrorContains(t, err, "invalid sAMAccountName")
	})

	t.Run("invalid sAMAccountName", func(t *testing.T) {
		err := client.UnlockUserForSAMAccountName("user/name")
		assert.ErrorContains(t, err, "invalid sAMAccountName")
	})
}
