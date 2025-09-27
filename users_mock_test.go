//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/netresearch/simple-ldap-go/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CreateTestEntry creates an LDAP entry for testing
func CreateTestEntry(dn string, attributes map[string][]string) *ldap.Entry {
	entry := &ldap.Entry{
		DN:         dn,
		Attributes: []*ldap.EntryAttribute{},
	}

	for name, values := range attributes {
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
			Name:   name,
			Values: values,
		})
	}

	return entry
}

// CreateTestUser creates a test User object
func CreateTestUser(cn, sam, mail, desc string, enabled bool) *User {
	user := &User{
		SAMAccountName: sam,
		Description:    desc,
		Enabled:        enabled,
	}
	if mail != "" {
		user.Mail = &mail
	}
	user.Object = Object{
		cn: cn,
		dn: "cn=" + cn + ",ou=users,dc=example,dc=com",
	}
	return user
}

// CreateTestGroup creates a test Group object
func CreateTestGroup(cn, desc string, members []string) *Group {
	group := &Group{
		Members: members,
	}
	group.Object = Object{
		cn: cn,
		dn: "cn=" + cn + ",ou=groups,dc=example,dc=com",
	}
	return group
}

// TestUserOperationsWithMock tests user operations using mock connection
func TestUserOperationsWithMock(t *testing.T) {
	t.Run("FindUserByDN", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			logger: slog.Default(),
		}

		// Test with context methods - will fail without proper connection
		ctx := context.Background()
		user, err := client.FindUserByDNContext(ctx, "cn=admin,ou=users,dc=example,dc=com")
		assert.Error(t, err) // Expected to error without connection
		assert.Nil(t, user)
	})
}

// TestUserFromEntryConversion tests the userFromEntry function
func TestUserFromEntryConversion(t *testing.T) {
	t.Run("complete user entry", func(t *testing.T) {
		entry := CreateTestEntry("cn=test,ou=users,dc=example,dc=com", map[string][]string{
			"cn":                 {"test"},
			"sAMAccountName":     {"testuser"},
			"mail":               {"test@example.com"},
			"description":        {"Test User"},
			"userAccountControl": {"512"},
			"memberOf": {
				"cn=group1,ou=groups,dc=example,dc=com",
				"cn=group2,ou=groups,dc=example,dc=com",
			},
		})

		user, err := userFromEntry(entry)
		require.NoError(t, err)
		assert.Equal(t, "test", user.CN())
		assert.Equal(t, "testuser", user.SAMAccountName)
		assert.NotNil(t, user.Mail)
		assert.Equal(t, "test@example.com", *user.Mail)
		assert.Equal(t, "Test User", user.Description)
		assert.True(t, user.Enabled)
		assert.Len(t, user.Groups, 2)
	})

	t.Run("minimal user entry", func(t *testing.T) {
		entry := CreateTestEntry("cn=minimal,ou=users,dc=example,dc=com", map[string][]string{
			"cn": {"minimal"},
		})

		user, err := userFromEntry(entry)
		require.NoError(t, err)
		assert.Equal(t, "minimal", user.CN())
		assert.Equal(t, "minimal", user.SAMAccountName) // Falls back to cn when no uid/sAMAccountName
		assert.Nil(t, user.Mail)
		assert.Empty(t, user.Description)
		assert.True(t, user.Enabled) // Default when no userAccountControl
		assert.Empty(t, user.Groups)
	})

	t.Run("disabled user entry", func(t *testing.T) {
		entry := CreateTestEntry("cn=disabled,ou=users,dc=example,dc=com", map[string][]string{
			"cn":                 {"disabled"},
			"userAccountControl": {"514"}, // 514 = disabled
		})

		user, err := userFromEntry(entry)
		require.NoError(t, err)
		assert.Equal(t, "disabled", user.CN())
		assert.False(t, user.Enabled)
	})

	t.Run("invalid userAccountControl", func(t *testing.T) {
		entry := CreateTestEntry("cn=invalid,ou=users,dc=example,dc=com", map[string][]string{
			"cn":                 {"invalid"},
			"userAccountControl": {"not-a-number"},
		})

		user, err := userFromEntry(entry)
		assert.Error(t, err)
		assert.Nil(t, user)
	})

	t.Run("user with empty mail", func(t *testing.T) {
		entry := CreateTestEntry("cn=nomail,ou=users,dc=example,dc=com", map[string][]string{
			"cn":   {"nomail"},
			"mail": {""},
		})

		user, err := userFromEntry(entry)
		require.NoError(t, err)
		assert.Nil(t, user.Mail)
	})

	t.Run("user with multiple mail values", func(t *testing.T) {
		entry := CreateTestEntry("cn=multimail,ou=users,dc=example,dc=com", map[string][]string{
			"cn":   {"multimail"},
			"mail": {"first@example.com", "second@example.com"},
		})

		user, err := userFromEntry(entry)
		require.NoError(t, err)
		assert.NotNil(t, user.Mail)
		assert.Equal(t, "first@example.com", *user.Mail) // Takes first value
	})
}

// TestUserMethods tests User struct methods
func TestUserMethods(t *testing.T) {
	t.Run("DN method", func(t *testing.T) {
		user := CreateTestUser("testuser", "tuser", "test@example.com", "Test User", true)
		assert.Equal(t, "cn=testuser,ou=users,dc=example,dc=com", user.DN())
	})

	t.Run("CN method", func(t *testing.T) {
		user := CreateTestUser("testuser", "tuser", "test@example.com", "Test User", true)
		assert.Equal(t, "testuser", user.CN())
	})
}

// TestBulkFindUsersBySAMAccountNameWithMock tests bulk user finding
func TestBulkFindUsersBySAMAccountNameWithMock(t *testing.T) {
	client := &LDAP{
		config: &Config{
			Server: "ldap://test:389",
			BaseDN: "dc=example,dc=com",
		},
		logger: slog.Default(),
	}

	ctx := context.Background()
	samAccountNames := []string{"admin", "user1", "nonexistent"}
	options := &BulkSearchOptions{
		BatchSize:      10,
		MaxConcurrency: 2,
		UseCache:       false,
	}
	users, err := client.BulkFindUsersBySAMAccountName(ctx, samAccountNames, options)
	// Currently returns stub implementation
	assert.NoError(t, err)
	assert.NotNil(t, users)
	assert.Len(t, users, 3)
	assert.Contains(t, users, "admin")
	assert.Contains(t, users, "user1")
	assert.Contains(t, users, "nonexistent")
}


// TestMockLDAPConnUserOperations tests the mock itself
func TestMockLDAPConnUserOperations(t *testing.T) {
	t.Run("search for users", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		req := ldap.NewSearchRequest(
			"ou=users,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=user)",
			[]string{"cn", "sAMAccountName", "mail"},
			nil,
		)

		result, err := mock.Search(req)
		require.NoError(t, err)
		assert.Equal(t, 3, len(result.Entries)) // admin, user1, disabled
	})

	t.Run("search by SAMAccountName", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		req := ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(sAMAccountName=admin)",
			[]string{"cn", "sAMAccountName", "mail"},
			nil,
		)

		result, err := mock.Search(req)
		require.NoError(t, err)
		assert.Equal(t, 1, len(result.Entries))
		assert.Equal(t, "cn=admin,ou=users,dc=example,dc=com", result.Entries[0].DN)
	})

	t.Run("add new user", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		addReq := ldap.NewAddRequest("cn=newuser,ou=users,dc=example,dc=com", nil)
		addReq.Attribute("objectClass", []string{"user"})
		addReq.Attribute("cn", []string{"newuser"})
		addReq.Attribute("sAMAccountName", []string{"newuser"})
		addReq.Attribute("mail", []string{"new@example.com"})

		err := mock.Add(addReq)
		require.NoError(t, err)

		// Verify user was added
		assert.Contains(t, mock.Users, "cn=newuser,ou=users,dc=example,dc=com")
		addedUser := mock.Users["cn=newuser,ou=users,dc=example,dc=com"]
		assert.Equal(t, "newuser", addedUser.CN)
		assert.Equal(t, "newuser", addedUser.SAMAccountName)
		assert.Equal(t, "new@example.com", addedUser.Mail)
	})

	t.Run("modify user", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		modReq := ldap.NewModifyRequest("cn=user1,ou=users,dc=example,dc=com", nil)
		modReq.Replace("mail", []string{"updated@example.com"})
		modReq.Replace("description", []string{"Updated Description"})

		err := mock.Modify(modReq)
		require.NoError(t, err)

		// Verify user was modified
		user := mock.Users["cn=user1,ou=users,dc=example,dc=com"]
		assert.Equal(t, "updated@example.com", user.Mail)
		assert.Equal(t, "Updated Description", user.Description)
	})

	t.Run("delete user", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		delReq := ldap.NewDelRequest("cn=user1,ou=users,dc=example,dc=com", nil)
		err := mock.Del(delReq)
		require.NoError(t, err)

		// Verify user was deleted
		assert.NotContains(t, mock.Users, "cn=user1,ou=users,dc=example,dc=com")
	})

	t.Run("bind with valid credentials", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		err := mock.Bind("cn=admin,ou=users,dc=example,dc=com", "admin123")
		assert.NoError(t, err)
		assert.Equal(t, 1, mock.GetBindCallCount())
	})

	t.Run("bind with invalid credentials", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		err := mock.Bind("cn=admin,ou=users,dc=example,dc=com", "wrongpassword")
		assert.Error(t, err)
		assert.Equal(t, 1, mock.GetBindCallCount())
	})

	t.Run("bind with nonexistent user", func(t *testing.T) {
		mock := testutil.NewMockLDAPConn()
		testutil.SetupTestUsersAndGroups(mock)

		err := mock.Bind("cn=nonexistent,ou=users,dc=example,dc=com", "password")
		assert.Error(t, err)
	})
}

// BenchmarkUserFromEntry benchmarks the userFromEntry function
func BenchmarkUserFromEntry(b *testing.B) {
	entry := CreateTestEntry("cn=bench,ou=users,dc=example,dc=com", map[string][]string{
		"cn":                 {"bench"},
		"sAMAccountName":     {"benchuser"},
		"mail":               {"bench@example.com"},
		"description":        {"Benchmark User"},
		"userAccountControl": {"512"},
		"memberOf": {
			"cn=group1,ou=groups,dc=example,dc=com",
			"cn=group2,ou=groups,dc=example,dc=com",
			"cn=group3,ou=groups,dc=example,dc=com",
		},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = userFromEntry(entry)
	}
}

// BenchmarkMockSearch benchmarks mock search operations
func BenchmarkMockSearch(b *testing.B) {
	mock := testutil.NewMockLDAPConn()
	testutil.SetupTestUsersAndGroups(mock)

	req := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)",
		[]string{"cn", "sAMAccountName", "mail"},
		nil,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mock.Search(req)
	}
}
