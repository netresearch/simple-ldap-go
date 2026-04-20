package testutil

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestNewMockLDAPConn verifies that a new mock is created with defaults.
func TestNewMockLDAPConn(t *testing.T) {
	m := NewMockLDAPConn()
	if m == nil {
		t.Fatal("NewMockLDAPConn returned nil")
	}
	if m.Users == nil {
		t.Error("Users map is nil")
	}
	if m.Groups == nil {
		t.Error("Groups map is nil")
	}
	if m.DefaultSearchLimit != 1000 {
		t.Errorf("DefaultSearchLimit = %d, want 1000", m.DefaultSearchLimit)
	}
	if len(m.Users) == 0 {
		t.Error("expected default users to be populated")
	}
	if len(m.Groups) == 0 {
		t.Error("expected default groups to be populated")
	}
}

func TestMockLDAPConn_Bind(t *testing.T) {
	t.Run("EmptyCredentials", func(t *testing.T) {
		m := NewMockLDAPConn()
		if err := m.Bind("", ""); err == nil {
			t.Error("expected error for empty credentials")
		}
	})
	t.Run("ValidCredentials", func(t *testing.T) {
		m := NewMockLDAPConn()
		err := m.Bind("cn=john.doe,ou=users,dc=example,dc=com", "password123")
		if err != nil {
			t.Errorf("unexpected bind error: %v", err)
		}
		if got := m.GetBindCallCount(); got != 1 {
			t.Errorf("bind count = %d, want 1", got)
		}
	})
	t.Run("InvalidPassword", func(t *testing.T) {
		m := NewMockLDAPConn()
		if err := m.Bind("cn=john.doe,ou=users,dc=example,dc=com", "wrong"); err == nil {
			t.Error("expected error for invalid password")
		}
	})
	t.Run("UnknownUser", func(t *testing.T) {
		m := NewMockLDAPConn()
		if err := m.Bind("cn=nobody,ou=users,dc=example,dc=com", "x"); err == nil {
			t.Error("expected error for unknown user")
		}
	})
	t.Run("BindBySAMAccountName", func(t *testing.T) {
		m := NewMockLDAPConn()
		if err := m.Bind("jdoe", "password123"); err != nil {
			t.Errorf("unexpected bind error: %v", err)
		}
	})
	t.Run("SetBindError", func(t *testing.T) {
		m := NewMockLDAPConn()
		injected := errors.New("server down")
		m.SetBindError(injected)
		err := m.Bind("whatever", "whatever")
		if !errors.Is(err, injected) && err.Error() != injected.Error() {
			t.Errorf("expected injected error, got %v", err)
		}
	})
}

func TestMockLDAPConn_Search(t *testing.T) {
	m := NewMockLDAPConn()

	// Search users
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=user)", []string{"cn", "mail"}, nil,
	)
	result, err := m.Search(req)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected user search results")
	}

	// Search groups
	groupReq := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=group)", nil, nil,
	)
	groupResult, err := m.Search(groupReq)
	if err != nil {
		t.Fatalf("group search failed: %v", err)
	}
	if len(groupResult.Entries) == 0 {
		t.Error("expected group search results")
	}

	// Search by samaccountname
	samReq := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(sAMAccountName=jdoe)", []string{"cn"}, nil,
	)
	samResult, err := m.Search(samReq)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(samResult.Entries) == 0 {
		t.Error("expected result for sAMAccountName=jdoe")
	}

	// Wildcard search
	allReq := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"cn"}, nil,
	)
	allResult, err := m.Search(allReq)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(allResult.Entries) == 0 {
		t.Error("expected wildcard search results")
	}

	// Size limit
	limReq := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 0, false, "(objectClass=*)", nil, nil,
	)
	limResult, err := m.Search(limReq)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(limResult.Entries) > 1 {
		t.Errorf("size limit not respected: got %d entries", len(limResult.Entries))
	}

	if m.GetSearchCallCount() < 4 {
		t.Errorf("search call count = %d, want >=4", m.GetSearchCallCount())
	}
}

func TestMockLDAPConn_SearchWithPaging(t *testing.T) {
	m := NewMockLDAPConn()
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=user)", nil, nil,
	)
	result, err := m.SearchWithPaging(req, 10)
	if err != nil {
		t.Fatalf("SearchWithPaging failed: %v", err)
	}
	if result == nil {
		t.Fatal("SearchWithPaging returned nil result")
	}

	// With custom paging func
	called := false
	m.SearchWithPagingFunc = func(r *ldap.SearchRequest, pageSize uint32) (*ldap.SearchResult, error) {
		called = true
		return &ldap.SearchResult{}, nil
	}
	_, err = m.SearchWithPaging(req, 5)
	if err != nil {
		t.Fatalf("custom SearchWithPaging failed: %v", err)
	}
	if !called {
		t.Error("custom paging func was not called")
	}
}

func TestMockLDAPConn_SetSearchError(t *testing.T) {
	m := NewMockLDAPConn()
	m.SetSearchError(errors.New("boom"))
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, err := m.Search(req)
	if err == nil || err.Error() != "boom" {
		t.Errorf("expected boom error, got %v", err)
	}
}

func TestMockLDAPConn_SetSearchResult(t *testing.T) {
	m := NewMockLDAPConn()
	fixed := &ldap.SearchResult{
		Entries: []*ldap.Entry{{DN: "cn=fixed"}},
	}
	m.SetSearchResult(fixed)
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	res, err := m.Search(req)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].DN != "cn=fixed" {
		t.Errorf("expected fixed result, got %+v", res.Entries)
	}
}

func TestMockLDAPConn_Modify(t *testing.T) {
	m := NewMockLDAPConn()
	dn := "cn=john.doe,ou=users,dc=example,dc=com"

	// Modify user attribute
	req := ldap.NewModifyRequest(dn, nil)
	req.Replace("mail", []string{"new@example.com"})
	req.Replace("description", []string{"updated"})
	if err := m.Modify(req); err != nil {
		t.Fatalf("modify failed: %v", err)
	}
	if u := m.Users[dn]; u.Mail != "new@example.com" {
		t.Errorf("mail not updated: %q", u.Mail)
	}

	// Modify group: add member
	groupDN := "cn=users,ou=groups,dc=example,dc=com"
	addMember := ldap.NewModifyRequest(groupDN, nil)
	addMember.Add("member", []string{"cn=newguy,ou=users,dc=example,dc=com"})
	if err := m.Modify(addMember); err != nil {
		t.Fatalf("modify group failed: %v", err)
	}

	// Delete member
	delMember := ldap.NewModifyRequest(groupDN, nil)
	delMember.Delete("member", []string{"cn=newguy,ou=users,dc=example,dc=com"})
	if err := m.Modify(delMember); err != nil {
		t.Fatalf("modify group failed: %v", err)
	}

	// Unknown object
	unknown := ldap.NewModifyRequest("cn=nope,dc=example,dc=com", nil)
	unknown.Replace("mail", []string{"x"})
	if err := m.Modify(unknown); err == nil {
		t.Error("expected error for unknown DN")
	}
}

func TestMockLDAPConn_Add(t *testing.T) {
	m := NewMockLDAPConn()

	// Add user
	userReq := ldap.NewAddRequest("cn=new.user,ou=users,dc=example,dc=com", nil)
	userReq.Attribute("objectClass", []string{"user"})
	userReq.Attribute("cn", []string{"new.user"})
	userReq.Attribute("sAMAccountName", []string{"newuser"})
	userReq.Attribute("mail", []string{"new@example.com"})
	userReq.Attribute("description", []string{"A new user"})
	if err := m.Add(userReq); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
	if _, exists := m.Users["cn=new.user,ou=users,dc=example,dc=com"]; !exists {
		t.Error("user not added")
	}

	// Duplicate user
	if err := m.Add(userReq); err == nil {
		t.Error("expected duplicate user error")
	}

	// Add group
	groupReq := ldap.NewAddRequest("cn=newgroup,ou=groups,dc=example,dc=com", nil)
	groupReq.Attribute("objectClass", []string{"group"})
	groupReq.Attribute("cn", []string{"newgroup"})
	groupReq.Attribute("description", []string{"A new group"})
	groupReq.Attribute("member", []string{"cn=new.user,ou=users,dc=example,dc=com"})
	if err := m.Add(groupReq); err != nil {
		t.Fatalf("add group failed: %v", err)
	}

	// Duplicate group
	if err := m.Add(groupReq); err == nil {
		t.Error("expected duplicate group error")
	}
}

func TestMockLDAPConn_Del(t *testing.T) {
	m := NewMockLDAPConn()

	// Delete user
	delReq := ldap.NewDelRequest("cn=john.doe,ou=users,dc=example,dc=com", nil)
	if err := m.Del(delReq); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, exists := m.Users["cn=john.doe,ou=users,dc=example,dc=com"]; exists {
		t.Error("user not deleted")
	}

	// Delete group
	delGrp := ldap.NewDelRequest("cn=users,ou=groups,dc=example,dc=com", nil)
	if err := m.Del(delGrp); err != nil {
		t.Fatalf("delete group failed: %v", err)
	}

	// Delete non-existent
	delBad := ldap.NewDelRequest("cn=nope,dc=example,dc=com", nil)
	if err := m.Del(delBad); err == nil {
		t.Error("expected error for unknown DN")
	}
}

func TestMockLDAPConn_Close(t *testing.T) {
	m := NewMockLDAPConn()
	if err := m.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if !m.Closed {
		t.Error("Closed flag not set")
	}

	// Custom close
	customCalled := false
	m2 := NewMockLDAPConn()
	m2.CloseFunc = func() error {
		customCalled = true
		return nil
	}
	_ = m2.Close()
	if !customCalled {
		t.Error("custom CloseFunc not called")
	}
}

func TestMockLDAPConn_Reset(t *testing.T) {
	m := NewMockLDAPConn()
	_ = m.Bind("jdoe", "password123")
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, _ = m.Search(req)
	m.Reset()
	if m.GetBindCallCount() != 0 || m.GetSearchCallCount() != 0 {
		t.Error("Reset did not clear call counts")
	}
	if m.Closed {
		t.Error("Reset did not clear closed flag")
	}
}

func TestMockLDAPConn_AddUserAddGroup(t *testing.T) {
	m := NewMockLDAPConn()
	m.AddUser(&MockUser{
		DN: "cn=custom,ou=users,dc=example,dc=com",
		CN: "custom",
	})
	if _, exists := m.Users["cn=custom,ou=users,dc=example,dc=com"]; !exists {
		t.Error("AddUser failed")
	}
	m.AddGroup(&MockGroup{
		DN: "cn=custom,ou=groups,dc=example,dc=com",
		CN: "custom",
	})
	if _, exists := m.Groups["cn=custom,ou=groups,dc=example,dc=com"]; !exists {
		t.Error("AddGroup failed")
	}
}

func TestMockLDAPConn_Compare(t *testing.T) {
	m := NewMockLDAPConn()

	userDN := "cn=john.doe,ou=users,dc=example,dc=com"
	match, err := m.Compare(userDN, "cn", "john.doe")
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if !match {
		t.Error("expected cn match")
	}

	if match, _ := m.Compare(userDN, "sAMAccountName", "jdoe"); !match {
		t.Error("expected sAMAccountName match")
	}
	if match, _ := m.Compare(userDN, "mail", "john.doe@example.com"); !match {
		t.Error("expected mail match")
	}
	if match, _ := m.Compare(userDN, "description", "Test User"); !match {
		t.Error("expected description match")
	}
	if match, _ := m.Compare(userDN, "unknown", "x"); match {
		t.Error("expected no match for unknown attr")
	}

	groupDN := "cn=users,ou=groups,dc=example,dc=com"
	if match, _ := m.Compare(groupDN, "cn", "users"); !match {
		t.Error("expected group cn match")
	}
	if match, _ := m.Compare(groupDN, "description", "All Users"); !match {
		t.Error("expected group description match")
	}
	if match, _ := m.Compare(groupDN, "unknown", "x"); match {
		t.Error("expected no match for unknown group attr")
	}

	if _, err := m.Compare("cn=nope,dc=example,dc=com", "cn", "x"); err == nil {
		t.Error("expected error for unknown DN")
	}
}

func TestMockLDAPConn_DirSync(t *testing.T) {
	m := NewMockLDAPConn()
	req := ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=user)", nil, nil,
	)
	res, err := m.DirSync(req, 0, 0, nil)
	if err != nil {
		t.Fatalf("DirSync failed: %v", err)
	}
	if res == nil {
		t.Fatal("DirSync returned nil")
	}

	// DirSyncAsync returns nil Response
	r := m.DirSyncAsync(context.Background(), req, 10, 0, 0, nil)
	if r != nil {
		t.Errorf("DirSyncAsync should return nil, got %v", r)
	}
}

func TestNewMockDialer(t *testing.T) {
	dialer := NewMockDialer()
	conn, err := dialer(context.Background(), "tcp", "localhost:389")
	if err != nil {
		t.Fatalf("dialer failed: %v", err)
	}
	if conn == nil {
		t.Fatal("dialer returned nil conn")
	}
}

func TestSetupTestUsersAndGroups(t *testing.T) {
	m := NewMockLDAPConn()
	SetupTestUsersAndGroups(m)

	expected := []string{
		"cn=admin,ou=users,dc=example,dc=com",
		"cn=user1,ou=users,dc=example,dc=com",
		"cn=disabled,ou=users,dc=example,dc=com",
	}
	for _, dn := range expected {
		if _, exists := m.Users[dn]; !exists {
			t.Errorf("expected user %q not present", dn)
		}
	}

	// Disabled flag preserved
	if m.Users["cn=disabled,ou=users,dc=example,dc=com"].Enabled {
		t.Error("disabled user should have Enabled=false")
	}
}

func TestMockLDAPConn_userToEntryFilters(t *testing.T) {
	m := NewMockLDAPConn()
	user := &MockUser{
		DN:             "cn=foo,dc=x",
		CN:             "foo",
		SAMAccountName: "foo",
		Mail:           "foo@x",
		Description:    "d",
		Enabled:        false,
		Groups:         []string{"cn=g,dc=x"},
	}
	// Request all attrs (empty list)
	e := m.userToEntry(user, nil)
	if e.DN != user.DN {
		t.Errorf("DN mismatch: %s", e.DN)
	}
	// Verify userAccountControl reflects disabled
	var uacFound bool
	for _, attr := range e.Attributes {
		if attr.Name == "userAccountControl" {
			uacFound = true
			if len(attr.Values) == 0 || attr.Values[0] != "514" {
				t.Errorf("uac for disabled user = %v, want 514", attr.Values)
			}
		}
	}
	if !uacFound {
		t.Error("userAccountControl not set")
	}

	// Request only cn
	e2 := m.userToEntry(user, []string{"cn"})
	if len(e2.Attributes) != 1 || e2.Attributes[0].Name != "cn" {
		t.Errorf("expected single cn attr, got %+v", e2.Attributes)
	}
}

func TestMockLDAPConn_groupToEntryFilters(t *testing.T) {
	m := NewMockLDAPConn()
	g := &MockGroup{
		DN:          "cn=g,dc=x",
		CN:          "g",
		Description: "desc",
		Members:     []string{"cn=m1,dc=x"},
	}
	e := m.groupToEntry(g, nil)
	if e.DN != g.DN {
		t.Errorf("DN mismatch: %s", e.DN)
	}
	// Only cn filter
	e2 := m.groupToEntry(g, []string{"cn"})
	if len(e2.Attributes) != 1 || e2.Attributes[0].Name != "cn" {
		t.Errorf("expected single cn attr, got %+v", e2.Attributes)
	}
}

func TestMockLDAPConn_MatchesFilterAndBaseDN(t *testing.T) {
	m := NewMockLDAPConn()
	u := &MockUser{CN: "alice", SAMAccountName: "alice", Mail: "alice@x"}

	if !m.matchesFilter(u, "(samaccountname=alice)") {
		t.Error("expected sam match")
	}
	if !m.matchesFilter(u, "(cn=alice)") {
		t.Error("expected cn match")
	}
	if !m.matchesFilter(u, "(mail=alice@x)") {
		t.Error("expected mail match")
	}
	if !m.matchesFilter(u, "(objectclass=user)") {
		t.Error("expected objectclass=user match")
	}
	if !m.matchesFilter(u, "(objectclass=*)") {
		t.Error("expected objectclass=* match")
	}
	if m.matchesFilter(u, "(cn=bob)") {
		t.Error("unexpected match for cn=bob")
	}

	if !m.matchesBaseDN("cn=x,DC=example,DC=com", "dc=example,dc=com") {
		t.Error("expected case-insensitive match")
	}
	if m.matchesBaseDN("cn=x,dc=other,dc=com", "dc=example,dc=com") {
		t.Error("unexpected match")
	}
}

func TestMockLDAPConn_ContainsAttribute(t *testing.T) {
	m := NewMockLDAPConn()
	if !m.containsAttribute([]string{"CN", "mail"}, "cn") {
		t.Error("expected case-insensitive attr match")
	}
	if m.containsAttribute([]string{"cn"}, "mail") {
		t.Error("unexpected attr match")
	}
}
