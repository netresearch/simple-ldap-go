package ldap

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// changeOps flattens a ModifyRequest into (operation, attribute) pairs so a test
// can assert the shape of the request without reaching for a live connection.
func changeOps(req *ldap.ModifyRequest) []string {
	names := map[uint]string{
		ldap.AddAttribute:     "add",
		ldap.DeleteAttribute:  "delete",
		ldap.ReplaceAttribute: "replace",
	}
	ops := make([]string, 0, len(req.Changes))
	for _, c := range req.Changes {
		ops = append(ops, names[c.Operation]+":"+c.Modification.Type)
	}
	return ops
}

// TestBuildADPasswordModify pins the Active Directory request shape.
//
// The distinction matters beyond cosmetics: DELETE+ADD requires the caller to
// know the current password, so AD authorises it as a self-service change.
// REPLACE does not, and is only permitted for a caller holding reset rights.
// Emitting the wrong one silently changes who is allowed to perform the
// operation, and no OpenLDAP-backed test can catch it.
func TestBuildADPasswordModify(t *testing.T) {
	t.Run("administrative reset uses REPLACE", func(t *testing.T) {
		req := buildADPasswordModify(passwordWrite{
			userDN:     "CN=jdoe,OU=Users,DC=example,DC=com",
			newEncoded: "encoded-new",
		})

		assert.Equal(t, "CN=jdoe,OU=Users,DC=example,DC=com", req.DN)
		assert.Equal(t, []string{"replace:unicodePwd"}, changeOps(req))
		require.Len(t, req.Changes, 1)
		assert.Equal(t, []string{"encoded-new"}, req.Changes[0].Modification.Vals)
	})

	t.Run("self-service change uses DELETE old then ADD new", func(t *testing.T) {
		req := buildADPasswordModify(passwordWrite{
			userDN:     "CN=jdoe,OU=Users,DC=example,DC=com",
			oldEncoded: "encoded-old",
			newEncoded: "encoded-new",
		})

		// Order matters: AD expects the delete of the current value first.
		assert.Equal(t, []string{"delete:unicodePwd", "add:unicodePwd"}, changeOps(req))
		require.Len(t, req.Changes, 2)
		assert.Equal(t, []string{"encoded-old"}, req.Changes[0].Modification.Vals)
		assert.Equal(t, []string{"encoded-new"}, req.Changes[1].Modification.Vals)
	})

	t.Run("only unicodePwd is touched", func(t *testing.T) {
		for _, w := range []passwordWrite{
			{userDN: "dn", newEncoded: "n"},
			{userDN: "dn", oldEncoded: "o", newEncoded: "n"},
		} {
			for _, c := range buildADPasswordModify(w).Changes {
				assert.Equal(t, "unicodePwd", c.Modification.Type)
			}
		}
	})
}

// TestWarnCleartextPasswordWrite covers the guard that fires when a non-AD
// password write would cross an unencrypted connection. RFC 3062 carries the new
// password in the request, so this is the operator's only signal.
func TestWarnCleartextPasswordWrite(t *testing.T) {
	newLDAP := func(server string, isAD bool, buf *bytes.Buffer) *LDAP {
		return &LDAP{
			config: &Config{Server: server, IsActiveDirectory: isAD},
			logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		}
	}

	tests := []struct {
		name      string
		server    string
		isAD      bool
		wantWarn  bool
		reasoning string
	}{
		{"non-AD over cleartext warns", "ldap://dir.example.com:389", false, true,
			"the password crosses the wire unencrypted"},
		{"non-AD over ldaps stays quiet", "ldaps://dir.example.com:636", false, false,
			"transport already encrypted"},
		{"AD is never warned here", "ldap://dc.example.com:389", true, false,
			"AD is rejected outright by ErrActiveDirectoryMustBeLDAPS before reaching this"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			newLDAP(tt.server, tt.isAD, &buf).warnCleartextPasswordWrite("TestOp", "jd**oe")

			logged := strings.Contains(buf.String(), "password_write_over_cleartext_connection")
			assert.Equal(t, tt.wantWarn, logged, tt.reasoning)

			if tt.wantWarn {
				// The warning is useless without the detail an operator acts on.
				assert.Contains(t, buf.String(), "TestOp")
				assert.Contains(t, buf.String(), tt.server)
			}
		})
	}
}

// TestDialAndBind_ErrorPaths covers the failure branches of the connection
// helper that the self-service change path relies on. The happy path is covered
// by the OpenLDAP integration test; these are the branches a live server never
// exercises.
func TestDialAndBind_ErrorPaths(t *testing.T) {
	newLDAP := func(server string) *LDAP {
		return &LDAP{
			config: &Config{Server: server, BaseDN: "dc=example,dc=org"},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
	}

	t.Run("cancelled context returns before dialing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := newLDAP("ldap://127.0.0.1:1").dialAndBind(ctx, "cn=x,dc=example,dc=org", "pw")
		require.Error(t, err)
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, context.Canceled,
			"a cancelled context must surface as such, not as a dial failure")
	})

	t.Run("unreachable server surfaces a dial error", func(t *testing.T) {
		// Port 1 is reserved and refuses connections, so this fails at dial
		// rather than hanging.
		conn, err := newLDAP("ldap://127.0.0.1:1").dialAndBind(
			context.Background(), "cn=x,dc=example,dc=org", "pw")
		require.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "failed to dial",
			"the error must name the dial step so a misconfigured host is diagnosable")
	})
}
