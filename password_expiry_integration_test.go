//go:build integration
// +build integration

package ldap

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

// ppolicyMaxAge is deliberately short in wall-clock terms but long enough that
// the computed deadline is unambiguously in the future.
const ppolicyMaxAge = 90 * 24 * time.Hour

// enablePpolicy loads the ppolicy overlay and installs a default policy.
//
// The overlay is what produces pwdChangedTime; without it OpenLDAP records
// nothing about password age and PasswordExpiryFor can only answer "unknown".
// osixia/openldap ships the module but does not enable the overlay.
func enablePpolicy(t *testing.T, tc *TestContainer, policyDN string) {
	t.Helper()

	cfgConn, err := ldap.DialURL(tc.Config.Server)
	require.NoError(t, err, "dial for cn=config")
	defer func() { _ = cfgConn.Close() }()
	require.NoError(t, cfgConn.Bind("cn=admin,cn=config", "config123"), "bind cn=config")

	// The module may already be loaded; only the overlay is guaranteed absent.
	modAdd := ldap.NewModifyRequest("cn=module{0},cn=config", nil)
	modAdd.Add("olcModuleLoad", []string{"ppolicy.la"})
	if err := cfgConn.Modify(modAdd); err != nil {
		t.Logf("loading ppolicy module reported %v (already loaded is fine)", err)
	}

	overlay := ldap.NewAddRequest("olcOverlay=ppolicy,olcDatabase={1}mdb,cn=config", nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcPPolicyConfig"})
	overlay.Attribute("olcOverlay", []string{"ppolicy"})
	overlay.Attribute("olcPPolicyDefault", []string{policyDN})
	overlay.Attribute("olcPPolicyHashCleartext", []string{"TRUE"})
	if err := cfgConn.Add(overlay); err != nil {
		require.True(t, ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists),
			"enable ppolicy overlay: %v", err)
	}
}

// createPasswordPolicy adds the policy entry the overlay points at.
func createPasswordPolicy(t *testing.T, conn *ldap.Conn, policyDN string, maxAge time.Duration) {
	t.Helper()

	add := ldap.NewAddRequest(policyDN, nil)
	add.Attribute("objectClass", []string{"top", "device", "pwdPolicy"})
	add.Attribute("cn", []string{"default"})
	// pwdAttribute is defined with OID syntax, so the numeric OID of
	// userPassword is required — the attribute *name* is rejected as
	// "invalid per syntax" by OpenLDAP.
	add.Attribute("pwdAttribute", []string{"2.5.4.35"})
	add.Attribute("pwdMaxAge", []string{fmt.Sprintf("%d", int64(maxAge.Seconds()))})
	if err := conn.Add(add); err != nil {
		require.True(t, ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists),
			"create password policy: %v", err)
	}
}

// changePasswordAsUser performs the change through the user's own bind.
//
// This matters: the ppolicy overlay does not maintain policy state for writes
// made by the rootdn, so an administrative Modify leaves pwdChangedTime unset
// and the whole feature looks broken. Doing it as the user is both what
// records the timestamp and what a self-service tool actually does.
func changePasswordAsUser(t *testing.T, tc *TestContainer, userDN, oldPassword, newPassword string) {
	t.Helper()

	conn, err := ldap.DialURL(tc.Config.Server)
	require.NoError(t, err, "dial as user")
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.Bind(userDN, oldPassword), "bind as the user")

	req := ldap.NewPasswordModifyRequest(userDN, oldPassword, newPassword)
	_, err = conn.PasswordModify(req)
	require.NoError(t, err, "password modify as the user")
}

// ppolicyFixture is the setup every ppolicy test shares: a container with the
// overlay enabled, a default policy of the given max age, and the seeded valid
// user's password freshly changed (which is what records pwdChangedTime). It
// returns the client — with PasswordPolicyDN pointed at the policy — the
// policy DN, and the test data.
func ppolicyFixture(t *testing.T, tc *TestContainer, maxAge time.Duration) (*LDAP, string, *TestData) {
	t.Helper()

	policyDN := fmt.Sprintf("cn=default,%s", tc.BaseDN)

	adminConn, err := ldap.DialURL(tc.Config.Server)
	require.NoError(t, err, "dial")
	defer func() { _ = adminConn.Close() }()
	require.NoError(t, adminConn.Bind(tc.AdminUser, tc.AdminPass), "bind admin")

	createPasswordPolicy(t, adminConn, policyDN, maxAge)
	enablePpolicy(t, tc, policyDN)

	data := tc.GetTestData()
	changePasswordAsUser(t, tc, data.ValidUserDN, data.ValidUserPassword, "FreshPassword123!")

	client := tc.GetLDAPClient(t)
	client.config.PasswordPolicyDN = policyDN

	return client, policyDN, data
}

// TestIntegrationPasswordExpiry_OpenLDAPPpolicy proves the OpenLDAP path end to
// end: the overlay records pwdChangedTime when a password is set, the library
// reads that operational attribute, resolves pwdMaxAge from the policy, and
// derives a deadline. None of that is observable without a real server — the
// attributes are operational and server-generated.
func TestIntegrationPasswordExpiry_OpenLDAPPpolicy(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	before := time.Now().UTC().Add(-time.Minute)
	client, _, data := ppolicyFixture(t, tc, ppolicyMaxAge)

	user, err := client.FindUserByDNContext(t.Context(), data.ValidUserDN)
	require.NoError(t, err, "find user")

	require.NotZero(t, user.PwdChangedAt,
		"pwdChangedTime must be read back; it is operational and excluded from a default search")
	require.GreaterOrEqual(t, user.PwdChangedAt, before.Unix(), "pwdChangedTime should be the write we just made")

	expiry, err := client.PasswordExpiryFor(t.Context(), user)
	require.NoError(t, err, "resolve expiry")

	require.Equal(t, PasswordExpires, expiry.Status, "a policy with pwdMaxAge must yield a deadline")
	require.False(t, expiry.Expired(time.Now()), "a password just set must not be expired")

	want := time.Unix(user.PwdChangedAt, 0).UTC().Add(ppolicyMaxAge)
	require.WithinDuration(t, want, expiry.At, time.Second, "deadline is pwdChangedTime + pwdMaxAge")
}

// A policy of pwdMaxAge 0 disables ageing. Verified against the server rather
// than only in a unit test, because it is the configuration an operator lands
// on when they want the overlay's lockout features but no expiry.
func TestIntegrationPasswordExpiry_ZeroMaxAgeNeverExpires(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client, _, data := ppolicyFixture(t, tc, 0)

	user, err := client.FindUserByDNContext(t.Context(), data.ValidUserDN)
	require.NoError(t, err, "find user")

	expiry, err := client.PasswordExpiryFor(t.Context(), user)
	require.NoError(t, err, "resolve expiry")
	require.Equal(t, PasswordNeverExpires, expiry.Status)
	require.False(t, expiry.Expired(time.Now()))
}

// Without the overlay there is no pwdChangedTime, and the honest answer is
// "unknown" — not "expiring". A notifier acting on a wrong answer here would
// mail the entire directory.
func TestIntegrationPasswordExpiry_UnknownWithoutPpolicy(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client := tc.GetLDAPClient(t)
	data := tc.GetTestData()

	user, err := client.FindUserByDNContext(t.Context(), data.ValidUserDN)
	require.NoError(t, err, "find user")

	expiry, err := client.PasswordExpiryFor(t.Context(), user)
	require.NoError(t, err, "resolve expiry")
	require.Equal(t, PasswordExpiryUnknown, expiry.Status,
		"a directory without ppolicy reports nothing about password age")
	require.False(t, expiry.Expired(time.Now()), "unknown must never read as expired")
}

// UsersWithExpiringPasswords is the API a notifier would drive, so it is worth
// exercising against a real directory rather than trusting the pieces.
//
// The seeded users get their passwords before the overlay is enabled, so they
// carry no pwdChangedTime and must be reported as unknown — which makes them a
// built-in negative case: only the account whose password is changed
// afterwards may appear.
func TestIntegrationUsersWithExpiringPasswords(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client, _, data := ppolicyFixture(t, tc, ppolicyMaxAge)

	// A window comfortably beyond the policy age: the changed account is due.
	due, err := client.UsersWithExpiringPasswords(t.Context(), ppolicyMaxAge+24*time.Hour)
	require.NoError(t, err, "scan for expiring passwords")

	var found *ExpiringUser
	for i := range due {
		if due[i].User.DN() == data.ValidUserDN {
			found = &due[i]
		}
	}
	require.NotNil(t, found, "the account whose password was changed should be due within the window")
	require.Equal(t, PasswordExpires, found.Expiry.Status)
	require.False(t, found.Expiry.Expired(time.Now()), "a password just set is not expired")

	// Accounts the directory says nothing about must never be swept in — that
	// is the difference between warning the right people and mailing everyone.
	for _, u := range due {
		require.NotEqual(t, PasswordExpiryUnknown, u.Expiry.Status,
			"unknown-expiry accounts must be excluded, got %s", u.User.DN())
	}

	// A window shorter than the remaining lifetime must exclude it again.
	none, err := client.UsersWithExpiringPasswords(t.Context(), time.Hour)
	require.NoError(t, err, "scan with a short window")
	for _, u := range none {
		require.NotEqual(t, data.ValidUserDN, u.User.DN(),
			"a password with ~90 days left must not appear in a one-hour window")
	}
}

// A policy DN that does not resolve must surface as an error, not be swallowed
// into "unknown" — a misconfigured PasswordPolicyDN should be loud.
func TestIntegrationPasswordExpiry_MissingPolicyDNErrors(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client, _, data := ppolicyFixture(t, tc, ppolicyMaxAge)
	// Point the client-wide default at a policy entry that does not exist.
	client.config.PasswordPolicyDN = fmt.Sprintf("cn=ghost,%s", tc.BaseDN)

	user, err := client.FindUserByDNContext(t.Context(), data.ValidUserDN)
	require.NoError(t, err, "find user")

	_, err = client.PasswordExpiryFor(t.Context(), user)
	require.Error(t, err, "an unresolvable policy DN must be reported")
	require.ErrorIs(t, err, ErrPasswordPolicyNotFound)
}

// A policy DN that is syntactically invalid fails the search with code 34
// (Invalid DN Syntax) rather than 32, so it exercises the general wrapped-error
// path rather than the ErrPasswordPolicyNotFound translation.
func TestIntegrationPasswordExpiry_MalformedPolicyDNPropagatesError(t *testing.T) {
	tc := SetupTestContainer(t)
	defer tc.Close(t)

	client, _, data := ppolicyFixture(t, tc, ppolicyMaxAge)
	client.config.PasswordPolicyDN = "this is not a dn"

	user, err := client.FindUserByDNContext(t.Context(), data.ValidUserDN)
	require.NoError(t, err, "find user")

	_, err = client.PasswordExpiryFor(t.Context(), user)
	require.Error(t, err, "a malformed policy DN must surface as an error")
	// It is a real LDAP error, not the not-found sentinel.
	require.NotErrorIs(t, err, ErrPasswordPolicyNotFound)
}
