//go:build !integration

package ldap

import (
	"context"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// auth.go — ChangePassword / ResetPassword error paths
// =============================================================================

func TestChangePassword_ADWithoutLDAPS(t *testing.T) {
	client, err := New(Config{
		Server:            "ldap://example.com:389",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}, "admin", "pass")
	require.NoError(t, err)

	err = client.ChangePasswordForSAMAccountName("jdoe", "old", "new")
	assert.ErrorIs(t, err, ErrActiveDirectoryMustBeLDAPS)
}

func TestChangePassword_InvalidSAM(t *testing.T) {
	client := newExampleClient(t)
	// Empty sAMAccountName triggers validator.
	err := client.ChangePasswordForSAMAccountName("", "old", "new")
	assert.Error(t, err)
}

func TestChangePassword_CancelledContext(t *testing.T) {
	client, err := New(Config{
		Server:            "ldaps://example.com:636",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}, "admin", "pass")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = client.ChangePasswordForSAMAccountNameContext(ctx, "jdoe", "old", "new")
	assert.Error(t, err)
}

func TestChangePassword_ConnectionError(t *testing.T) {
	client, err := New(Config{
		Server:            "ldaps://example.com:636",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}, "admin", "pass")
	require.NoError(t, err)
	err = client.ChangePasswordForSAMAccountName("jdoe", "old", "new")
	assert.Error(t, err)
}

func TestResetPassword_ADWithoutLDAPS(t *testing.T) {
	client, err := New(Config{
		Server:            "ldap://example.com:389",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}, "admin", "pass")
	require.NoError(t, err)

	err = client.ResetPasswordForSAMAccountName("jdoe", "newpass")
	assert.ErrorIs(t, err, ErrActiveDirectoryMustBeLDAPS)
}

func TestResetPassword_InvalidSAM(t *testing.T) {
	client := newExampleClient(t)
	err := client.ResetPasswordForSAMAccountName("", "newpass")
	assert.Error(t, err)
}

func TestResetPassword_CancelledContext(t *testing.T) {
	client, err := New(Config{
		Server:            "ldaps://example.com:636",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}, "admin", "pass")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = client.ResetPasswordForSAMAccountNameContext(ctx, "jdoe", "newpass")
	assert.Error(t, err)
}

func TestResetPassword_ConnectionError(t *testing.T) {
	client, err := New(Config{
		Server:            "ldaps://example.com:636",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}, "admin", "pass")
	require.NoError(t, err)
	err = client.ResetPasswordForSAMAccountName("jdoe", "newpass")
	assert.Error(t, err)
}

func TestCheckPasswordForSAMAccountName_InvalidSAM(t *testing.T) {
	client := newExampleClient(t)
	u, err := client.CheckPasswordForSAMAccountName("", "password")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestCheckPasswordForSAMAccountName_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u, err := client.CheckPasswordForSAMAccountNameContext(ctx, "jdoe", "password")
	assert.Error(t, err)
	assert.Nil(t, u)
}

// =============================================================================
// iterators.go — iterate (exercise yield/error paths)
// =============================================================================

func TestSearchIter_YieldsConnectionError(t *testing.T) {
	client := newExampleClient(t)
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"cn"}, nil,
	)
	var gotErr error
	for _, err := range client.SearchIter(context.Background(), req) {
		if err != nil {
			gotErr = err
		}
	}
	assert.Error(t, gotErr)
}

func TestSearchIter_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"cn"}, nil,
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var gotErr error
	for _, err := range client.SearchIter(ctx, req) {
		if err != nil {
			gotErr = err
		}
	}
	assert.Error(t, gotErr)
}

func TestSearchPagedIter_YieldsConnectionError(t *testing.T) {
	client := newExampleClient(t)
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"cn"}, nil,
	)
	var gotErr error
	for _, err := range client.SearchPagedIter(context.Background(), req, 10) {
		if err != nil {
			gotErr = err
		}
	}
	assert.Error(t, gotErr)
}

func TestSearchPagedIter_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"cn"}, nil,
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var gotErr error
	for _, err := range client.SearchPagedIter(ctx, req, 10) {
		if err != nil {
			gotErr = err
		}
	}
	assert.Error(t, gotErr)
}

func TestGroupMembersIter_YieldsConnectionError(t *testing.T) {
	client := newExampleClient(t)
	var gotErr error
	for _, err := range client.GroupMembersIter(context.Background(), "cn=g,dc=example,dc=com") {
		if err != nil {
			gotErr = err
		}
	}
	assert.Error(t, gotErr)
}

// =============================================================================
// generics.go — typed helpers error paths
// =============================================================================

func TestGenericSearch_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	users, err := Search[*User](context.Background(), client, "(objectClass=user)", "")
	assert.Error(t, err)
	assert.Nil(t, users)
}

func TestGenericSearch_WithCustomBaseDN(t *testing.T) {
	client := newExampleClient(t)
	_, err := Search[*User](context.Background(), client, "(objectClass=user)", "ou=users,dc=example,dc=com")
	assert.Error(t, err)
}

func TestGenericFindByDN_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	u, err := FindByDN[*User](context.Background(), client, "cn=x,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestGenericDeleteByDN_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	err := DeleteByDN(context.Background(), client, "cn=x,dc=example,dc=com")
	assert.Error(t, err)
}

func TestGenericCreate_TypeWithoutCreatable(t *testing.T) {
	client := newExampleClient(t)
	// *User doesn't implement ToAddRequest/Validate, so Create must return the
	// "does not implement" error.
	u := &User{}
	dn, err := Create(context.Background(), client, u)
	assert.Error(t, err)
	assert.Empty(t, dn)
}

func TestGenericModify_TypeWithoutModifiable(t *testing.T) {
	client := newExampleClient(t)
	u := &User{}
	err := Modify(context.Background(), client, u, map[string][]string{"description": {"d"}})
	assert.Error(t, err)
}

// =============================================================================
// client.go — ReleaseConnection paths
// =============================================================================

func TestReleaseConnection_NilConnection(t *testing.T) {
	client := newExampleClient(t)
	err := client.ReleaseConnection(nil)
	assert.NoError(t, err)
}

// =============================================================================
// computers.go — additional error paths
// =============================================================================

func TestFindComputerBySAMAccountName_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	c, err := client.FindComputerBySAMAccountName("WS01")
	assert.Error(t, err)
	assert.Nil(t, c)
}

func TestFindComputerBySAMAccountName_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err := client.FindComputerBySAMAccountNameContext(ctx, "WS01")
	assert.Error(t, err)
	assert.Nil(t, c)
}

// =============================================================================
// users.go — FindUserBySAMAccountName error paths (additional)
// =============================================================================

func TestFindUserBySAMAccountName_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	u, err := client.FindUserBySAMAccountName("jdoe")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestFindUserBySAMAccountName_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestFindUserBySAMAccountName_InvalidSAM(t *testing.T) {
	client := newExampleClient(t)
	u, err := client.FindUserBySAMAccountName("")
	assert.Error(t, err)
	assert.Nil(t, u)
}
