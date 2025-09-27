package testutil

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// MockLDAPConn is a comprehensive mock implementation of the LDAP connection interface
type MockLDAPConn struct {
	mu sync.Mutex

	// Configuration
	BindFunc             func(username, password string) error
	SearchFunc           func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPagingFunc func(req *ldap.SearchRequest, pageSize uint32) (*ldap.SearchResult, error)
	ModifyFunc           func(req *ldap.ModifyRequest) error
	AddFunc              func(req *ldap.AddRequest) error
	DelFunc              func(req *ldap.DelRequest) error
	CloseFunc            func() error

	// State tracking
	BindCalls   []BindCall
	SearchCalls []SearchCall
	ModifyCalls []ModifyCall
	AddCalls    []AddCall
	DelCalls    []DelCall
	Closed      bool

	// Default data
	Users              map[string]*MockUser
	Groups             map[string]*MockGroup
	DefaultSearchLimit int
}

// BindCall records a bind operation
type BindCall struct {
	Username string
	Password string
	Error    error
}

// SearchCall records a search operation
type SearchCall struct {
	Request *ldap.SearchRequest
	Result  *ldap.SearchResult
	Error   error
}

// ModifyCall records a modify operation
type ModifyCall struct {
	Request *ldap.ModifyRequest
	Error   error
}

// AddCall records an add operation
type AddCall struct {
	Request *ldap.AddRequest
	Error   error
}

// DelCall records a delete operation
type DelCall struct {
	Request *ldap.DelRequest
	Error   error
}

// MockUser represents a mock LDAP user
type MockUser struct {
	DN             string
	CN             string
	SAMAccountName string
	Mail           string
	Description    string
	Groups         []string
	Password       string
	Enabled        bool
}

// MockGroup represents a mock LDAP group
type MockGroup struct {
	DN          string
	CN          string
	Description string
	Members     []string
}

// NewMockLDAPConn creates a new mock LDAP connection with default behavior
func NewMockLDAPConn() *MockLDAPConn {
	mock := &MockLDAPConn{
		Users:              make(map[string]*MockUser),
		Groups:             make(map[string]*MockGroup),
		DefaultSearchLimit: 1000,
	}

	// Setup default behavior
	mock.setupDefaultFunctions()
	mock.setupDefaultData()

	return mock
}

// setupDefaultFunctions sets up default function implementations
func (m *MockLDAPConn) setupDefaultFunctions() {
	// Default bind function - simple authentication
	m.BindFunc = func(username, password string) error {
		if username == "" || password == "" {
			return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("empty credentials"))
		}

		// Check if user exists and password matches
		for _, user := range m.Users {
			if user.DN == username || user.SAMAccountName == username {
				if user.Password == password {
					return nil
				}
				return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid password"))
			}
		}
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("user not found"))
	}

	// Default search function
	m.SearchFunc = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		result := &ldap.SearchResult{
			Entries: []*ldap.Entry{},
		}

		// Simple filter parsing
		filter := strings.ToLower(req.Filter)

		if strings.Contains(filter, "objectclass=user") || strings.Contains(filter, "samaccountname=") {
			// Search for users
			for _, user := range m.Users {
				if m.matchesFilter(user, filter) && m.matchesBaseDN(user.DN, req.BaseDN) {
					result.Entries = append(result.Entries, m.userToEntry(user, req.Attributes))
				}
			}
		} else if strings.Contains(filter, "objectclass=group") {
			// Search for groups
			for _, group := range m.Groups {
				if m.matchesBaseDN(group.DN, req.BaseDN) {
					result.Entries = append(result.Entries, m.groupToEntry(group, req.Attributes))
				}
			}
		} else {
			// Search all objects
			for _, user := range m.Users {
				if m.matchesFilter(user, filter) && m.matchesBaseDN(user.DN, req.BaseDN) {
					result.Entries = append(result.Entries, m.userToEntry(user, req.Attributes))
				}
			}
			for _, group := range m.Groups {
				if m.matchesBaseDN(group.DN, req.BaseDN) {
					result.Entries = append(result.Entries, m.groupToEntry(group, req.Attributes))
				}
			}
		}

		// Apply size limit
		if req.SizeLimit > 0 && len(result.Entries) > req.SizeLimit {
			result.Entries = result.Entries[:req.SizeLimit]
		}

		return result, nil
	}

	// Default modify function
	m.ModifyFunc = func(req *ldap.ModifyRequest) error {
		// Find the object to modify
		if user, exists := m.Users[req.DN]; exists {
			// Apply modifications to user
			for _, change := range req.Changes {
				switch change.Modification.Type {
				case "mail":
					if len(change.Modification.Vals) > 0 {
						user.Mail = change.Modification.Vals[0]
					}
				case "description":
					if len(change.Modification.Vals) > 0 {
						user.Description = change.Modification.Vals[0]
					}
				}
			}
			return nil
		}
		if group, exists := m.Groups[req.DN]; exists {
			// Apply modifications to group
			for _, change := range req.Changes {
				switch change.Modification.Type {
				case "member":
					if change.Operation == ldap.AddAttribute {
						group.Members = append(group.Members, change.Modification.Vals...)
					} else if change.Operation == ldap.DeleteAttribute {
						// Remove members
						newMembers := []string{}
						for _, member := range group.Members {
							remove := false
							for _, val := range change.Modification.Vals {
								if member == val {
									remove = true
									break
								}
							}
							if !remove {
								newMembers = append(newMembers, member)
							}
						}
						group.Members = newMembers
					}
				}
			}
			return nil
		}
		return ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("object not found: %s", req.DN))
	}

	// Default add function
	m.AddFunc = func(req *ldap.AddRequest) error {
		// Check if object already exists
		if _, exists := m.Users[req.DN]; exists {
			return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, fmt.Errorf("user already exists: %s", req.DN))
		}
		if _, exists := m.Groups[req.DN]; exists {
			return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, fmt.Errorf("group already exists: %s", req.DN))
		}

		// Determine object type and create
		objectClass := ""
		for _, attr := range req.Attributes {
			if attr.Type == "objectClass" {
				for _, val := range attr.Vals {
					if val == "user" || val == "person" {
						objectClass = "user"
						break
					} else if val == "group" {
						objectClass = "group"
						break
					}
				}
			}
		}

		switch objectClass {
		case "user":
			user := &MockUser{DN: req.DN, Enabled: true}
			for _, attr := range req.Attributes {
				switch attr.Type {
				case "cn":
					if len(attr.Vals) > 0 {
						user.CN = attr.Vals[0]
					}
				case "sAMAccountName":
					if len(attr.Vals) > 0 {
						user.SAMAccountName = attr.Vals[0]
					}
				case "mail":
					if len(attr.Vals) > 0 {
						user.Mail = attr.Vals[0]
					}
				case "description":
					if len(attr.Vals) > 0 {
						user.Description = attr.Vals[0]
					}
				}
			}
			m.Users[req.DN] = user
		case "group":
			group := &MockGroup{DN: req.DN}
			for _, attr := range req.Attributes {
				switch attr.Type {
				case "cn":
					if len(attr.Vals) > 0 {
						group.CN = attr.Vals[0]
					}
				case "description":
					if len(attr.Vals) > 0 {
						group.Description = attr.Vals[0]
					}
				case "member":
					group.Members = attr.Vals
				}
			}
			m.Groups[req.DN] = group
		}

		return nil
	}

	// Default delete function
	m.DelFunc = func(req *ldap.DelRequest) error {
		if _, exists := m.Users[req.DN]; exists {
			delete(m.Users, req.DN)
			return nil
		}
		if _, exists := m.Groups[req.DN]; exists {
			delete(m.Groups, req.DN)
			return nil
		}
		return ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("object not found: %s", req.DN))
	}

	// Default close function
	m.CloseFunc = func() error {
		m.Closed = true
		return nil
	}
}

// setupDefaultData populates the mock with sample data
func (m *MockLDAPConn) setupDefaultData() {
	// Add sample users
	m.Users["cn=john.doe,ou=users,dc=example,dc=com"] = &MockUser{
		DN:             "cn=john.doe,ou=users,dc=example,dc=com",
		CN:             "john.doe",
		SAMAccountName: "jdoe",
		Mail:           "john.doe@example.com",
		Description:    "Test User",
		Password:       "password123",
		Enabled:        true,
		Groups:         []string{"cn=users,ou=groups,dc=example,dc=com"},
	}

	m.Users["cn=jane.smith,ou=users,dc=example,dc=com"] = &MockUser{
		DN:             "cn=jane.smith,ou=users,dc=example,dc=com",
		CN:             "jane.smith",
		SAMAccountName: "jsmith",
		Mail:           "jane.smith@example.com",
		Description:    "Admin User",
		Password:       "admin456",
		Enabled:        true,
		Groups:         []string{"cn=admins,ou=groups,dc=example,dc=com", "cn=users,ou=groups,dc=example,dc=com"},
	}

	// Add sample groups
	m.Groups["cn=users,ou=groups,dc=example,dc=com"] = &MockGroup{
		DN:          "cn=users,ou=groups,dc=example,dc=com",
		CN:          "users",
		Description: "All Users",
		Members: []string{
			"cn=john.doe,ou=users,dc=example,dc=com",
			"cn=jane.smith,ou=users,dc=example,dc=com",
		},
	}

	m.Groups["cn=admins,ou=groups,dc=example,dc=com"] = &MockGroup{
		DN:          "cn=admins,ou=groups,dc=example,dc=com",
		CN:          "admins",
		Description: "Administrators",
		Members:     []string{"cn=jane.smith,ou=users,dc=example,dc=com"},
	}
}

// Bind implements ldap.Conn interface
func (m *MockLDAPConn) Bind(username, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var err error
	if m.BindFunc != nil {
		err = m.BindFunc(username, password)
	}

	m.BindCalls = append(m.BindCalls, BindCall{
		Username: username,
		Password: password,
		Error:    err,
	})

	return err
}

// Search implements ldap.Conn interface
func (m *MockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result *ldap.SearchResult
	var err error

	if m.SearchFunc != nil {
		result, err = m.SearchFunc(req)
	}

	m.SearchCalls = append(m.SearchCalls, SearchCall{
		Request: req,
		Result:  result,
		Error:   err,
	})

	return result, err
}

// SearchWithPaging implements ldap.Conn interface
func (m *MockLDAPConn) SearchWithPaging(req *ldap.SearchRequest, pageSize uint32) (*ldap.SearchResult, error) {
	if m.SearchWithPagingFunc != nil {
		return m.SearchWithPagingFunc(req, pageSize)
	}
	// Default to regular search
	return m.Search(req)
}

// Modify implements ldap.Conn interface
func (m *MockLDAPConn) Modify(req *ldap.ModifyRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var err error
	if m.ModifyFunc != nil {
		err = m.ModifyFunc(req)
	}

	m.ModifyCalls = append(m.ModifyCalls, ModifyCall{
		Request: req,
		Error:   err,
	})

	return err
}

// Add implements ldap.Conn interface
func (m *MockLDAPConn) Add(req *ldap.AddRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var err error
	if m.AddFunc != nil {
		err = m.AddFunc(req)
	}

	m.AddCalls = append(m.AddCalls, AddCall{
		Request: req,
		Error:   err,
	})

	return err
}

// Del implements ldap.Conn interface
func (m *MockLDAPConn) Del(req *ldap.DelRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var err error
	if m.DelFunc != nil {
		err = m.DelFunc(req)
	}

	m.DelCalls = append(m.DelCalls, DelCall{
		Request: req,
		Error:   err,
	})

	return err
}

// Close implements ldap.Conn interface
func (m *MockLDAPConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	m.Closed = true
	return nil
}

// Helper methods for mock functionality

// matchesFilter checks if a user matches the search filter
func (m *MockLDAPConn) matchesFilter(user *MockUser, filter string) bool {
	filter = strings.ToLower(filter)

	// Simple filter matching
	if strings.Contains(filter, fmt.Sprintf("samaccountname=%s", strings.ToLower(user.SAMAccountName))) {
		return true
	}
	if strings.Contains(filter, fmt.Sprintf("cn=%s", strings.ToLower(user.CN))) {
		return true
	}
	if strings.Contains(filter, fmt.Sprintf("mail=%s", strings.ToLower(user.Mail))) {
		return true
	}
	if strings.Contains(filter, "(objectclass=user)") || strings.Contains(filter, "(objectclass=*)") {
		return true
	}

	return false
}

// matchesBaseDN checks if a DN is under the base DN
func (m *MockLDAPConn) matchesBaseDN(dn, baseDN string) bool {
	return strings.HasSuffix(strings.ToLower(dn), strings.ToLower(baseDN))
}

// userToEntry converts a MockUser to an LDAP entry
func (m *MockLDAPConn) userToEntry(user *MockUser, attributes []string) *ldap.Entry {
	entry := &ldap.Entry{
		DN:         user.DN,
		Attributes: []*ldap.EntryAttribute{},
	}

	// Add requested attributes or all if not specified
	addAttr := func(name, value string) {
		if len(attributes) == 0 || m.containsAttribute(attributes, name) {
			if value != "" {
				entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
					Name:   name,
					Values: []string{value},
				})
			}
		}
	}

	addAttr("cn", user.CN)
	addAttr("sAMAccountName", user.SAMAccountName)
	addAttr("mail", user.Mail)
	addAttr("description", user.Description)

	if len(attributes) == 0 || m.containsAttribute(attributes, "memberOf") {
		if len(user.Groups) > 0 {
			entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
				Name:   "memberOf",
				Values: user.Groups,
			})
		}
	}

	// Add userAccountControl for enabled/disabled status
	if len(attributes) == 0 || m.containsAttribute(attributes, "userAccountControl") {
		uac := "512" // Normal account
		if !user.Enabled {
			uac = "514" // Disabled account
		}
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
			Name:   "userAccountControl",
			Values: []string{uac},
		})
	}

	return entry
}

// groupToEntry converts a MockGroup to an LDAP entry
func (m *MockLDAPConn) groupToEntry(group *MockGroup, attributes []string) *ldap.Entry {
	entry := &ldap.Entry{
		DN:         group.DN,
		Attributes: []*ldap.EntryAttribute{},
	}

	// Add requested attributes or all if not specified
	addAttr := func(name, value string) {
		if len(attributes) == 0 || m.containsAttribute(attributes, name) {
			if value != "" {
				entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
					Name:   name,
					Values: []string{value},
				})
			}
		}
	}

	addAttr("cn", group.CN)
	addAttr("description", group.Description)

	if len(attributes) == 0 || m.containsAttribute(attributes, "member") {
		if len(group.Members) > 0 {
			entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
				Name:   "member",
				Values: group.Members,
			})
		}
	}

	return entry
}

// containsAttribute checks if an attribute is in the list
func (m *MockLDAPConn) containsAttribute(attributes []string, attr string) bool {
	for _, a := range attributes {
		if strings.EqualFold(a, attr) {
			return true
		}
	}
	return false
}

// Reset clears all recorded calls
func (m *MockLDAPConn) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.BindCalls = nil
	m.SearchCalls = nil
	m.ModifyCalls = nil
	m.AddCalls = nil
	m.DelCalls = nil
	m.Closed = false
}

// GetBindCallCount returns the number of bind calls made
func (m *MockLDAPConn) GetBindCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.BindCalls)
}

// GetSearchCallCount returns the number of search calls made
func (m *MockLDAPConn) GetSearchCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.SearchCalls)
}

// AddUser adds a user to the mock data
func (m *MockLDAPConn) AddUser(user *MockUser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Users[user.DN] = user
}

// AddGroup adds a group to the mock data
func (m *MockLDAPConn) AddGroup(group *MockGroup) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Groups[group.DN] = group
}

// SetBindError sets a specific error for bind operations
func (m *MockLDAPConn) SetBindError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BindFunc = func(username, password string) error {
		return err
	}
}

// Compare performs an LDAP compare operation (mock implementation)
func (m *MockLDAPConn) Compare(dn, attribute, value string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if user exists and attribute matches
	if user, exists := m.Users[dn]; exists {
		switch attribute {
		case "cn":
			return user.CN == value, nil
		case "sAMAccountName":
			return user.SAMAccountName == value, nil
		case "mail":
			return user.Mail == value, nil
		case "description":
			return user.Description == value, nil
		default:
			return false, nil
		}
	}

	// Check groups
	if group, exists := m.Groups[dn]; exists {
		switch attribute {
		case "cn":
			return group.CN == value, nil
		case "description":
			return group.Description == value, nil
		default:
			return false, nil
		}
	}

	return false, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("DN not found: %s", dn))
}

// DirSync performs a directory synchronization search (not implemented in mock)
func (m *MockLDAPConn) DirSync(searchRequest *ldap.SearchRequest, flags, maxAttrCount int64, cookie []byte) (*ldap.SearchResult, error) {
	// For mock purposes, just return a regular search result
	// Real DirSync would track changes and return only modified entries
	return m.Search(searchRequest)
}

// DirSyncAsync performs an asynchronous directory synchronization search (not implemented in mock)
func (m *MockLDAPConn) DirSyncAsync(ctx context.Context, searchRequest *ldap.SearchRequest, bufferSize int, flags, maxAttrCount int64, cookie []byte) ldap.Response {
	// For mock purposes, just call the synchronous version
	// Real implementation would handle async operations
	_, _ = m.Search(searchRequest)
	// Return nil as we don't have proper async support in mock
	return nil
}

// SetSearchError sets a specific error for search operations
func (m *MockLDAPConn) SetSearchError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SearchFunc = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, err
	}
}

// SetSearchResult sets a specific result for search operations
func (m *MockLDAPConn) SetSearchResult(result *ldap.SearchResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SearchFunc = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		return result, nil
	}
}

// NewMockDialer creates a dialer function that returns mock connections
func NewMockDialer() func(ctx context.Context, network, addr string) (*MockLDAPConn, error) {
	return func(ctx context.Context, network, addr string) (*MockLDAPConn, error) {
		return NewMockLDAPConn(), nil
	}
}
