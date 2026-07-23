//go:build integration
// +build integration

package ldap

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bindAs proves a password is live by opening a fresh connection and binding as
// the user. Asserting on the write call's error alone is not enough: it would
// still pass if the server accepted a write that did not actually take effect.
func bindAs(t *testing.T, tc *TestContainer, userDN, password string) error {
	t.Helper()

	conn, err := ldap.DialURL(tc.Config.Server)
	require.NoError(t, err, "dial for bind check")
	defer func() { _ = conn.Close() }()

	return conn.Bind(userDN, password)
}

// TestIntegration_OpenLDAP_PasswordWrites is a regression test for password
// writes against a non-Active-Directory server.
//
// Both password paths used to write the Microsoft-specific unicodePwd attribute
// unconditionally, with no branch on Config.IsActiveDirectory. OpenLDAP has no
// such attribute, so every write failed with LDAP result 17 "Undefined Attribute
// Type" and no password could ever be changed or reset on a non-AD directory.
//
// Nothing caught it because every other test either mocks the connection or only
// performs lookups. This test drives a real OpenLDAP server and then binds with
// the new password, which is the only assertion that distinguishes "the server
// accepted our request" from "the password actually changed".
func TestIntegration_OpenLDAP_PasswordWrites(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	td := tc.GetTestData()

	// The harness seeds OpenLDAP, so IsActiveDirectory must be false here. If it
	// were true the client would take the unicodePwd path and this test would be
	// asserting nothing about the branch it exists to cover.
	require.False(t, tc.Config.IsActiveDirectory,
		"fixture must be a non-AD directory for this regression test to mean anything")

	t.Run("administrative reset sets a usable password", func(t *testing.T) {
		client, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		const newPassword = "Reset1!Password"

		require.NoError(t,
			client.ResetPasswordForSAMAccountName(td.ValidUserUID, newPassword),
			"reset must not fail on OpenLDAP (regression: unicodePwd, result 17)")

		assert.NoError(t, bindAs(t, tc, td.ValidUserDN, newPassword),
			"the new password must actually bind")
		assert.Error(t, bindAs(t, tc, td.ValidUserDN, td.ValidUserPassword),
			"the old password must stop working")
	})

	t.Run("self-service change works from an unprivileged service bind", func(t *testing.T) {
		// The client must NOT be bound as an account with write access to the
		// target. A real deployment binds a read-only service account, and RFC 3062
		// authorises a change from the bind identity — so a privileged bind here
		// would mask the failure that account actually hits. An earlier revision of
		// this test used tc.AdminUser and passed while production got
		// result 53 "unwilling to verify old password".
		admin, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		const startPassword = "Start1!Password"
		require.NoError(t, admin.ResetPasswordForSAMAccountName(td.DisabledUserUID, startPassword))

		client, err := New(tc.Config, tc.ReadOnlyDN(), tc.ReadOnlyPassword())
		require.NoError(t, err, "client bound as a service account that can read but not write")

		const changedPassword = "Changed1!Password"
		require.NoError(t,
			client.ChangePasswordForSAMAccountName(td.DisabledUserUID, startPassword, changedPassword),
			"change must succeed even though the service bind cannot write the target entry")

		userDN := fmt.Sprintf("uid=%s,%s", td.DisabledUserUID, tc.UsersOU)
		assert.NoError(t, bindAs(t, tc, userDN, changedPassword),
			"the changed password must actually bind")
		assert.Error(t, bindAs(t, tc, userDN, startPassword),
			"the previous password must stop working")
	})

	t.Run("change rejects a wrong current password", func(t *testing.T) {
		client, err := New(tc.Config, tc.AdminUser, tc.AdminPass)
		require.NoError(t, err)

		const known = "Known1!Password"
		require.NoError(t, client.ResetPasswordForSAMAccountName(td.ValidUserUID, known))

		// RFC 3062 carries the old password so the server can authorise the change.
		// Supplying the wrong one must fail, otherwise the change path would be an
		// unauthenticated reset for anyone who can reach it.
		err = client.ChangePasswordForSAMAccountName(td.ValidUserUID, "not-the-current-password", "Another1!Password")
		assert.Error(t, err, "a wrong current password must be rejected")

		assert.NoError(t, bindAs(t, tc, td.ValidUserDN, known),
			"a rejected change must leave the existing password intact")
	})
}
