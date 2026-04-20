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

func TestCreateUser_InvalidSAMAccountName(t *testing.T) {
	client := newExampleClient(t)
	// Contains a space, which ValidateSAMAccountName rejects.
	bad := "bad user"
	_, err := client.CreateUser(FullUser{
		CN:             "Bad User",
		FirstName:      "Bad",
		LastName:       "User",
		SAMAccountName: &bad,
	}, "password")
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid sAMAccountName")
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

// Regression tests for the deadlock that used to live in the
// Bulk{Create,Modify,Delete}UsersContext call sites with EnableBulkOps=true:
// `defer pool.Close()` ran only after the function returned, but the
// synchronous `for result := range pool.Results()` loop waited for the
// result channel to close — which only happens inside Close(). The fix is
// to call Close() in a goroutine after all items are submitted so the
// channel drains and then closes, letting the range loop terminate.
//
// The tests wrap each bulk call in a 2 s timeout context. The underlying
// LDAP operations fail immediately (no real server), so the calls must
// return well within the timeout. Previously they would block for 5+ minutes
// (worker-pool context timeout) and then still hang on the unclosed result
// channel, i.e. indefinitely.

func newBulkOpsClient(t *testing.T) *LDAP {
	t.Helper()
	// Using an example.com hostname bypasses the eager dial in New() so the
	// test can construct a client without a live LDAP server. All subsequent
	// operations will fail at GetConnection time — which is fine: we only
	// care that the bulk call RETURNS rather than hangs.
	client, err := New(Config{
		Server:        "ldap://example.com:389",
		BaseDN:        "dc=example,dc=com",
		EnableBulkOps: true,
	}, "cn=admin,dc=example,dc=com", "pass")
	require.NoError(t, err)
	require.NotNil(t, client)
	return client
}

// fastBulkConfig returns a WorkerPoolConfig with a short operation timeout so
// the tests don't wait the 5 min default if the fix regresses. Two workers and
// a small buffer also exercise the "more items than buffer" case.
func fastBulkConfig() *WorkerPoolConfig {
	return &WorkerPoolConfig{
		WorkerCount: 2,
		BufferSize:  4,
		Timeout:     500 * time.Millisecond,
		FailFast:    false,
	}
}

func runWithDeadlockGuard(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatalf("%s deadlocked: did not return within 5s", name)
	}
}

func TestBulkCreateUsersContext_NoDeadlock(t *testing.T) {
	client := newBulkOpsClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Submit more items than BufferSize to make sure we don't deadlock when
	// workers block on a full result channel.
	users := make([]FullUser, 10)
	for i := range users {
		users[i] = FullUser{CN: "user"}
	}

	runWithDeadlockGuard(t, "BulkCreateUsersContext", func() {
		results, err := client.BulkCreateUsersContext(ctx, users, "pw", fastBulkConfig())
		// We don't assert on err — the point is that the call RETURNS.
		// Operations will have failed (no real LDAP server) but they should
		// either show up as errored results or be skipped via submission
		// failures; either way the function must return.
		_ = results
		_ = err
	})
}

func TestBulkModifyUsersContext_NoDeadlock(t *testing.T) {
	client := newBulkOpsClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mods := make([]UserModification, 10)
	for i := range mods {
		mods[i] = UserModification{
			DN:         "cn=x,dc=example,dc=com",
			Attributes: map[string][]string{"description": {"d"}},
		}
	}

	runWithDeadlockGuard(t, "BulkModifyUsersContext", func() {
		results, err := client.BulkModifyUsersContext(ctx, mods, fastBulkConfig())
		_ = results
		_ = err
	})
}

func TestBulkDeleteUsersContext_NoDeadlock(t *testing.T) {
	client := newBulkOpsClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dns := make([]string, 10)
	for i := range dns {
		dns[i] = "cn=x,dc=example,dc=com"
	}

	runWithDeadlockGuard(t, "BulkDeleteUsersContext", func() {
		results, err := client.BulkDeleteUsersContext(ctx, dns, fastBulkConfig())
		_ = results
		_ = err
	})
}

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
