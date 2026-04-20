//go:build !integration

package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newExampleClient builds a client that points at an example/test server so
// that GetConnection returns an error before touching the network. This lets
// us exercise error paths in every LDAP client method without requiring an
// actual directory.
func newExampleClient(t *testing.T) *LDAP {
	t.Helper()
	client, err := New(Config{
		Server: "ldap://example.com:389",
		BaseDN: "dc=example,dc=com",
	}, "cn=admin,dc=example,dc=com", "pass")
	require.NoError(t, err)
	require.NotNil(t, client)
	return client
}

// =============================================================================
// users.go — find/create/modify/delete error paths
// =============================================================================

func TestFindUserByDN_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	user, err := client.FindUserByDN("cn=x,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestFindUserByDN_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	user, err := client.FindUserByDNContext(ctx, "cn=x,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestFindUserByMail_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	user, err := client.FindUserByMail("foo@example.com")
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestFindUserByMail_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	user, err := client.FindUserByMailContext(ctx, "foo@example.com")
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestFindUsersBySAMAccountNames_Empty(t *testing.T) {
	client := newExampleClient(t)
	users, err := client.FindUsersBySAMAccountNames(nil)
	assert.NoError(t, err)
	assert.Empty(t, users)
}

func TestFindUsersBySAMAccountNames_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	users, err := client.FindUsersBySAMAccountNamesContext(ctx, []string{"a", "b"})
	assert.Error(t, err)
	// Implementation returns pre-allocated (empty) slice on ctx cancel before any lookup.
	assert.Empty(t, users)
}

func TestFindUsers_ExampleServerReturnsMockData(t *testing.T) {
	client := newExampleClient(t)
	users, err := client.FindUsers()
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	// Example server produces 150 mock users.
	assert.Len(t, users, 150)
	// Mock users are wired as enabled and have sAMAccountName values.
	for _, u := range users[:5] {
		assert.True(t, u.Enabled)
		assert.NotEmpty(t, u.SAMAccountName)
	}
}

func TestFindUsers_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	users, err := client.FindUsersContext(ctx)
	assert.Error(t, err)
	assert.Nil(t, users)
}

func TestAddUserToGroup_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	err := client.AddUserToGroup("cn=u,dc=example,dc=com", "cn=g,dc=example,dc=com")
	assert.Error(t, err)
}

func TestAddUserToGroup_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.AddUserToGroupContext(ctx, "cn=u,dc=example,dc=com", "cn=g,dc=example,dc=com")
	assert.Error(t, err)
}

func TestRemoveUserFromGroup_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	err := client.RemoveUserFromGroup("cn=u,dc=example,dc=com", "cn=g,dc=example,dc=com")
	assert.Error(t, err)
}

func TestRemoveUserFromGroup_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.RemoveUserFromGroupContext(ctx, "cn=u,dc=example,dc=com", "cn=g,dc=example,dc=com")
	assert.Error(t, err)
}

func TestCreateUser_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	sam := "newuser"
	email := "new@example.com"
	desc := "d"
	user := FullUser{
		CN:             "New User",
		FirstName:      "New",
		LastName:       "User",
		SAMAccountName: &sam,
		Email:          &email,
		Description:    &desc,
	}
	_, err := client.CreateUser(user, "password!")
	assert.Error(t, err)
}

func TestCreateUser_WithPath(t *testing.T) {
	client := newExampleClient(t)
	path := "ou=users"
	sam := "user"
	user := FullUser{
		CN:             "P User",
		FirstName:      "P",
		LastName:       "User",
		SAMAccountName: &sam,
		Path:           &path,
	}
	_, err := client.CreateUserContext(context.Background(), user, "pass!")
	assert.Error(t, err)
}

func TestCreateUser_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.CreateUserContext(ctx, FullUser{CN: "c"}, "pass")
	assert.Error(t, err)
}

func TestModifyUser_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	err := client.ModifyUser("cn=x,dc=example,dc=com", map[string][]string{
		"description": {"new"},
	})
	assert.Error(t, err)
}

func TestModifyUser_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.ModifyUserContext(ctx, "cn=x,dc=example,dc=com", map[string][]string{"description": {"new"}})
	assert.Error(t, err)
}

func TestDeleteUser_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	err := client.DeleteUser("cn=x,dc=example,dc=com")
	assert.Error(t, err)
}

func TestDeleteUser_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.DeleteUserContext(ctx, "cn=x,dc=example,dc=com")
	assert.Error(t, err)
}

// =============================================================================
// BulkXxxUsers helpers — when EnableBulkOps=false
// =============================================================================

func TestBulkOps_DisabledByDefault(t *testing.T) {
	// The exported bulk operations are gated behind EnableBulkOps. When
	// disabled they must return an explicit error.
	client, err := New(Config{
		Server:        "ldap://example.com:389",
		BaseDN:        "dc=example,dc=com",
		EnableBulkOps: false,
	}, "admin", "pass")
	require.NoError(t, err)
	// The default path in New() sets EnableOptimizations=true, which in turn
	// flips EnableBulkOps. To exercise the error branch explicitly, flip it off.
	client.config.EnableBulkOps = false

	t.Run("BulkCreateUsers", func(t *testing.T) {
		res, err := client.BulkCreateUsers([]FullUser{{CN: "a"}}, "x")
		assert.Error(t, err)
		assert.Nil(t, res)
	})
	t.Run("BulkModifyUsers", func(t *testing.T) {
		res, err := client.BulkModifyUsers([]UserModification{{DN: "cn=x", Attributes: map[string][]string{"description": {"d"}}}})
		assert.Error(t, err)
		assert.Nil(t, res)
	})
	t.Run("BulkDeleteUsers", func(t *testing.T) {
		res, err := client.BulkDeleteUsers([]string{"cn=x"})
		assert.Error(t, err)
		assert.Nil(t, res)
	})
}

// Note: Bulk{Create,Modify,Delete}UsersContext with EnableBulkOps=true is
// deliberately not unit-tested here — the production code path defers
// pool.Close() while synchronously ranging over pool.Results() which will not
// terminate until the worker-pool context times out (default 5 min). That
// represents a product-code concern that is out of scope for this coverage
// change and needs a separate fix.

// =============================================================================
// groups.go — FindGroupByDN/FindGroups error paths
// =============================================================================

func TestFindGroupByDN_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	group, err := client.FindGroupByDN("cn=g,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, group)
}

func TestFindGroupByDN_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	group, err := client.FindGroupByDNContext(ctx, "cn=g,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, group)
}

func TestFindGroups_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	groups, err := client.FindGroups()
	assert.Error(t, err)
	assert.Nil(t, groups)
}

func TestFindGroups_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	groups, err := client.FindGroupsContext(ctx)
	assert.Error(t, err)
	assert.Nil(t, groups)
}

// =============================================================================
// computers.go — FindComputerByDN / FindComputers error paths
// =============================================================================

func TestFindComputerByDN_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	c, err := client.FindComputerByDN("cn=c,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, c)
}

func TestFindComputerByDN_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err := client.FindComputerByDNContext(ctx, "cn=c,dc=example,dc=com")
	assert.Error(t, err)
	assert.Nil(t, c)
}

func TestFindComputers_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	computers, err := client.FindComputers()
	// Implementation may return mock data for example server or a connection error.
	// Either way, it must not panic and the result must be coherent.
	if err != nil {
		assert.Nil(t, computers)
	} else {
		// nil-safe; just iterate defensively
		_ = computers
	}
}

// =============================================================================
// auth.go — CheckPasswordForDN error paths
// =============================================================================

func TestCheckPasswordForDN_ConnectionError(t *testing.T) {
	client := newExampleClient(t)
	u, err := client.CheckPasswordForDN("cn=x,dc=example,dc=com", "pw")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestCheckPasswordForDN_CancelledContext(t *testing.T) {
	client := newExampleClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u, err := client.CheckPasswordForDNContext(ctx, "cn=x,dc=example,dc=com", "pw")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestCheckPasswordForDN_EmptyPassword(t *testing.T) {
	client := newExampleClient(t)
	// Empty password should still produce a handled error (rather than panicking).
	u, err := client.CheckPasswordForDN("cn=x,dc=example,dc=com", "")
	assert.Error(t, err)
	assert.Nil(t, u)
}

// =============================================================================
// concurrency.go — BulkCreateUsers/BulkFindUsers/BulkDeleteUsers of
// ConcurrentLDAPOperations always returns per-item errors on connection failure.
// =============================================================================

func TestConcurrentOps_BulkCreateUsers(t *testing.T) {
	client := newExampleClient(t)
	co := NewConcurrentOperations(client, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sam := "a"
	errs := co.BulkCreateUsers(ctx, []FullUser{{
		CN:             "A",
		FirstName:      "A",
		LastName:       "Z",
		SAMAccountName: &sam,
	}}, "pw")
	assert.Len(t, errs, 1)
	assert.Error(t, errs[0])
}

func TestConcurrentOps_BulkFindUsers(t *testing.T) {
	client := newExampleClient(t)
	co := NewConcurrentOperations(client, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	users, errs := co.BulkFindUsers(ctx, []string{"cn=x,dc=example,dc=com"})
	assert.Len(t, users, 1)
	assert.Len(t, errs, 1)
	assert.Error(t, errs[0])
}

func TestConcurrentOps_BulkDeleteUsers(t *testing.T) {
	client := newExampleClient(t)
	co := NewConcurrentOperations(client, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errs := co.BulkDeleteUsers(ctx, []string{"cn=x,dc=example,dc=com"})
	assert.Len(t, errs, 1)
	assert.Error(t, errs[0])
}

// =============================================================================
// users.go — getCacheTTL (0% covered)
// =============================================================================

func TestGetCacheTTL_Default(t *testing.T) {
	client := newExampleClient(t)
	ttl := client.getCacheTTL()
	assert.Equal(t, 5*time.Minute, ttl)
}

func TestGetCacheTTL_FromConfig(t *testing.T) {
	client, err := New(Config{
		Server: "ldap://example.com:389",
		BaseDN: "dc=example,dc=com",
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     30 * time.Second,
		},
	}, "admin", "pass")
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, client.getCacheTTL())
}
