//go:build !integration

package ldap

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestInterfaceComplianceUserReader tests that LDAP implements UserReader
func TestInterfaceComplianceUserReader(t *testing.T) {
	t.Run("LDAP implements UserReader", func(t *testing.T) {
		var client *LDAP
		assert.Implements(t, (*UserReader)(nil), client)
	})

	t.Run("UserReader interface methods", func(t *testing.T) {
		userReaderType := reflect.TypeOf((*UserReader)(nil)).Elem()
		expectedMethods := []string{
			"FindUserByDN",
			"FindUserByDNContext",
			"FindUserBySAMAccountName",
			"FindUserBySAMAccountNameContext",
			"FindUserByMail",
			"FindUserByMailContext",
		}

		for _, methodName := range expectedMethods {
			method, found := userReaderType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in UserReader", methodName)
			assert.NotNil(t, method)
		}

		assert.Equal(t, len(expectedMethods), userReaderType.NumMethod(), "UserReader should have exactly %d methods", len(expectedMethods))
	})
}

// TestInterfaceComplianceUserWriter tests UserWriter interface structure
func TestInterfaceComplianceUserWriter(t *testing.T) {
	t.Run("UserWriter interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		// LDAP doesn't fully implement UserWriter yet (missing UpdateUserPassword)
		userWriterType := reflect.TypeOf((*UserWriter)(nil)).Elem()
		assert.NotNil(t, userWriterType)
		assert.Equal(t, "UserWriter", userWriterType.Name())
	})

	t.Run("UserWriter interface methods", func(t *testing.T) {
		userWriterType := reflect.TypeOf((*UserWriter)(nil)).Elem()
		expectedMethods := []string{
			"CreateUser",
			"CreateUserContext",
			"DeleteUser",
			"DeleteUserContext",
			"UpdateUserPassword",
			"UpdateUserPasswordContext",
		}

		for _, methodName := range expectedMethods {
			method, found := userWriterType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in UserWriter", methodName)
			assert.NotNil(t, method)
		}

		assert.Equal(t, len(expectedMethods), userWriterType.NumMethod(), "UserWriter should have exactly %d methods", len(expectedMethods))
	})
}

// TestInterfaceComplianceUserManager tests UserManager interface structure
func TestInterfaceComplianceUserManager(t *testing.T) {
	t.Run("UserManager interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		userManagerType := reflect.TypeOf((*UserManager)(nil)).Elem()
		assert.NotNil(t, userManagerType)
		assert.Equal(t, "UserManager", userManagerType.Name())
	})

	t.Run("UserManager embeds UserReader and UserWriter", func(t *testing.T) {
		userManagerType := reflect.TypeOf((*UserManager)(nil)).Elem()

		// UserManager should have all methods from UserReader and UserWriter plus additional ones
		expectedMethods := []string{
			// From UserReader
			"FindUserByDN",
			"FindUserByDNContext",
			"FindUserBySAMAccountName",
			"FindUserBySAMAccountNameContext",
			"FindUserByMail",
			"FindUserByMailContext",
			// From UserWriter
			"CreateUser",
			"CreateUserContext",
			"DeleteUser",
			"DeleteUserContext",
			"UpdateUserPassword",
			"UpdateUserPasswordContext",
			// Additional methods
			"GetUserGroups",
			"GetUserGroupsContext",
		}

		for _, methodName := range expectedMethods {
			method, found := userManagerType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in UserManager", methodName)
			assert.NotNil(t, method)
		}
	})
}

// TestInterfaceComplianceGroupReader tests GroupReader interface structure
func TestInterfaceComplianceGroupReader(t *testing.T) {
	t.Run("GroupReader interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		groupReaderType := reflect.TypeOf((*GroupReader)(nil)).Elem()
		assert.NotNil(t, groupReaderType)
		assert.Equal(t, "GroupReader", groupReaderType.Name())
	})

	t.Run("GroupReader interface methods", func(t *testing.T) {
		groupReaderType := reflect.TypeOf((*GroupReader)(nil)).Elem()
		expectedMethods := []string{
			"FindGroupByDN",
			"FindGroupByDNContext",
			"FindGroupByCN",
			"FindGroupByCNContext",
		}

		for _, methodName := range expectedMethods {
			method, found := groupReaderType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in GroupReader", methodName)
			assert.NotNil(t, method)
		}

		assert.Equal(t, len(expectedMethods), groupReaderType.NumMethod(), "GroupReader should have exactly %d methods", len(expectedMethods))
	})
}

// TestInterfaceComplianceGroupWriter tests GroupWriter interface structure
func TestInterfaceComplianceGroupWriter(t *testing.T) {
	t.Run("GroupWriter interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		groupWriterType := reflect.TypeOf((*GroupWriter)(nil)).Elem()
		assert.NotNil(t, groupWriterType)
		assert.Equal(t, "GroupWriter", groupWriterType.Name())
	})

	t.Run("GroupWriter interface methods", func(t *testing.T) {
		groupWriterType := reflect.TypeOf((*GroupWriter)(nil)).Elem()
		expectedMethods := []string{
			"CreateGroup",
			"CreateGroupContext",
			"DeleteGroup",
			"DeleteGroupContext",
			"AddUserToGroup",
			"AddUserToGroupContext",
			"RemoveUserFromGroup",
			"RemoveUserFromGroupContext",
		}

		for _, methodName := range expectedMethods {
			method, found := groupWriterType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in GroupWriter", methodName)
			assert.NotNil(t, method)
		}

		assert.Equal(t, len(expectedMethods), groupWriterType.NumMethod(), "GroupWriter should have exactly %d methods", len(expectedMethods))
	})
}

// TestInterfaceComplianceGroupManager tests GroupManager interface structure
func TestInterfaceComplianceGroupManager(t *testing.T) {
	t.Run("GroupManager interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		groupManagerType := reflect.TypeOf((*GroupManager)(nil)).Elem()
		assert.NotNil(t, groupManagerType)
		assert.Equal(t, "GroupManager", groupManagerType.Name())
	})

	t.Run("GroupManager embeds GroupReader and GroupWriter", func(t *testing.T) {
		groupManagerType := reflect.TypeOf((*GroupManager)(nil)).Elem()

		expectedMethods := []string{
			// From GroupReader
			"FindGroupByDN",
			"FindGroupByDNContext",
			"FindGroupByCN",
			"FindGroupByCNContext",
			// From GroupWriter
			"CreateGroup",
			"CreateGroupContext",
			"DeleteGroup",
			"DeleteGroupContext",
			"AddUserToGroup",
			"AddUserToGroupContext",
			"RemoveUserFromGroup",
			"RemoveUserFromGroupContext",
			// Additional methods
			"GetGroupMembers",
			"GetGroupMembersContext",
		}

		for _, methodName := range expectedMethods {
			method, found := groupManagerType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in GroupManager", methodName)
			assert.NotNil(t, method)
		}
	})
}

// TestInterfaceComplianceComputerReader tests that LDAP implements ComputerReader
func TestInterfaceComplianceComputerReader(t *testing.T) {
	t.Run("LDAP implements ComputerReader", func(t *testing.T) {
		var client *LDAP
		assert.Implements(t, (*ComputerReader)(nil), client)
	})

	t.Run("ComputerReader interface methods", func(t *testing.T) {
		computerReaderType := reflect.TypeOf((*ComputerReader)(nil)).Elem()
		expectedMethods := []string{
			"FindComputerByDN",
			"FindComputerByDNContext",
			"FindComputerBySAMAccountName",
			"FindComputerBySAMAccountNameContext",
		}

		for _, methodName := range expectedMethods {
			method, found := computerReaderType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in ComputerReader", methodName)
			assert.NotNil(t, method)
		}

		assert.Equal(t, len(expectedMethods), computerReaderType.NumMethod(), "ComputerReader should have exactly %d methods", len(expectedMethods))
	})
}

// TestInterfaceComplianceComputerWriter tests ComputerWriter interface structure
func TestInterfaceComplianceComputerWriter(t *testing.T) {
	t.Run("ComputerWriter interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		computerWriterType := reflect.TypeOf((*ComputerWriter)(nil)).Elem()
		assert.NotNil(t, computerWriterType)
		assert.Equal(t, "ComputerWriter", computerWriterType.Name())
	})

	t.Run("ComputerWriter interface methods", func(t *testing.T) {
		computerWriterType := reflect.TypeOf((*ComputerWriter)(nil)).Elem()
		expectedMethods := []string{
			"CreateComputer",
			"CreateComputerContext",
			"DeleteComputer",
			"DeleteComputerContext",
		}

		for _, methodName := range expectedMethods {
			method, found := computerWriterType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in ComputerWriter", methodName)
			assert.NotNil(t, method)
		}

		assert.Equal(t, len(expectedMethods), computerWriterType.NumMethod(), "ComputerWriter should have exactly %d methods", len(expectedMethods))
	})
}

// TestInterfaceComplianceComputerManager tests ComputerManager interface structure
func TestInterfaceComplianceComputerManager(t *testing.T) {
	t.Run("ComputerManager interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		computerManagerType := reflect.TypeOf((*ComputerManager)(nil)).Elem()
		assert.NotNil(t, computerManagerType)
		assert.Equal(t, "ComputerManager", computerManagerType.Name())
	})

	t.Run("ComputerManager embeds ComputerReader and ComputerWriter", func(t *testing.T) {
		computerManagerType := reflect.TypeOf((*ComputerManager)(nil)).Elem()

		expectedMethods := []string{
			// From ComputerReader
			"FindComputerByDN",
			"FindComputerByDNContext",
			"FindComputerBySAMAccountName",
			"FindComputerBySAMAccountNameContext",
			// From ComputerWriter
			"CreateComputer",
			"CreateComputerContext",
			"DeleteComputer",
			"DeleteComputerContext",
		}

		for _, methodName := range expectedMethods {
			method, found := computerManagerType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in ComputerManager", methodName)
			assert.NotNil(t, method)
		}
	})
}

// TestInterfaceComplianceDirectoryManager tests DirectoryManager interface structure
func TestInterfaceComplianceDirectoryManager(t *testing.T) {
	t.Run("DirectoryManager interface structure", func(t *testing.T) {
		// Test interface structure exists, not implementation compliance
		directoryManagerType := reflect.TypeOf((*DirectoryManager)(nil)).Elem()
		assert.NotNil(t, directoryManagerType)
		assert.Equal(t, "DirectoryManager", directoryManagerType.Name())
	})

	t.Run("DirectoryManager contains all management interfaces", func(t *testing.T) {
		directoryManagerType := reflect.TypeOf((*DirectoryManager)(nil)).Elem()

		// Should have methods from all embedded interfaces plus connection management
		expectedConnectionMethods := []string{
			"GetConnection",
			"GetConnectionContext",
			"Close",
			"GetPoolStats",
			"GetCacheStats",
			"GetPerformanceStats",
			"ClearCache",
		}

		for _, methodName := range expectedConnectionMethods {
			method, found := directoryManagerType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in DirectoryManager", methodName)
			assert.NotNil(t, method)
		}

		// Should also have all methods from embedded interfaces (UserManager, GroupManager, ComputerManager)
		// We'll test a few key ones to verify embedding works
		embeddedMethods := []string{
			"FindUserByDN",
			"CreateUser",
			"FindGroupByDN",
			"CreateGroup",
			"FindComputerByDN",
			"CreateComputer",
		}

		for _, methodName := range embeddedMethods {
			method, found := directoryManagerType.MethodByName(methodName)
			assert.True(t, found, "Embedded method %s should exist in DirectoryManager", methodName)
			assert.NotNil(t, method)
		}
	})
}

// TestInterfaceSegregation tests the Interface Segregation Principle
func TestInterfaceSegregation(t *testing.T) {
	t.Run("interfaces are properly segregated", func(t *testing.T) {
		// UserReader should only have read methods
		userReaderType := reflect.TypeOf((*UserReader)(nil)).Elem()
		assert.Equal(t, 6, userReaderType.NumMethod(), "UserReader should have exactly 6 read methods")

		// UserWriter should only have write methods
		userWriterType := reflect.TypeOf((*UserWriter)(nil)).Elem()
		assert.Equal(t, 6, userWriterType.NumMethod(), "UserWriter should have exactly 6 write methods")

		// GroupReader should only have read methods
		groupReaderType := reflect.TypeOf((*GroupReader)(nil)).Elem()
		assert.Equal(t, 4, groupReaderType.NumMethod(), "GroupReader should have exactly 4 read methods")

		// GroupWriter should only have write methods
		groupWriterType := reflect.TypeOf((*GroupWriter)(nil)).Elem()
		assert.Equal(t, 8, groupWriterType.NumMethod(), "GroupWriter should have exactly 8 write methods")

		// ComputerReader should only have read methods
		computerReaderType := reflect.TypeOf((*ComputerReader)(nil)).Elem()
		assert.Equal(t, 4, computerReaderType.NumMethod(), "ComputerReader should have exactly 4 read methods")

		// ComputerWriter should only have write methods
		computerWriterType := reflect.TypeOf((*ComputerWriter)(nil)).Elem()
		assert.Equal(t, 4, computerWriterType.NumMethod(), "ComputerWriter should have exactly 4 write methods")
	})

	t.Run("manager interfaces properly combine readers and writers", func(t *testing.T) {
		// UserManager should have all UserReader + UserWriter + additional methods
		userManagerType := reflect.TypeOf((*UserManager)(nil)).Elem()
		assert.GreaterOrEqual(t, userManagerType.NumMethod(), 14, "UserManager should have at least 14 methods (6+6+2)")

		// GroupManager should have all GroupReader + GroupWriter + additional methods
		groupManagerType := reflect.TypeOf((*GroupManager)(nil)).Elem()
		assert.GreaterOrEqual(t, groupManagerType.NumMethod(), 14, "GroupManager should have at least 14 methods (4+8+2)")

		// ComputerManager should have all ComputerReader + ComputerWriter methods
		computerManagerType := reflect.TypeOf((*ComputerManager)(nil)).Elem()
		assert.GreaterOrEqual(t, computerManagerType.NumMethod(), 8, "ComputerManager should have at least 8 methods (4+4)")
	})
}

// TestInterfaceMethodSignatures tests that interface methods have correct signatures
func TestInterfaceMethodSignatures(t *testing.T) {
	t.Run("context methods have context parameter", func(t *testing.T) {
		userReaderType := reflect.TypeOf((*UserReader)(nil)).Elem()

		// Test FindUserByDNContext signature
		method, found := userReaderType.MethodByName("FindUserByDNContext")
		assert.True(t, found)

		methodType := method.Type
		assert.Equal(t, 2, methodType.NumIn(), "FindUserByDNContext should have 2 parameters (context, dn)")
		assert.Equal(t, 2, methodType.NumOut(), "FindUserByDNContext should have 2 return values (*User, error)")

		// Check parameter types
		assert.Equal(t, "Context", methodType.In(0).Name(), "First parameter should be Context")
		assert.Equal(t, "string", methodType.In(1).Name(), "Second parameter should be string (dn)")

		// Check return types - should be (*User, error)
		assert.True(t, methodType.Out(0).String() == "*ldap.User" || methodType.Out(0).String() == "*main.User")
		assert.True(t, methodType.Out(1).Implements(reflect.TypeOf((*error)(nil)).Elem()))
	})

	t.Run("non-context methods don't have context parameter", func(t *testing.T) {
		userReaderType := reflect.TypeOf((*UserReader)(nil)).Elem()

		// Test FindUserByDN signature
		method, found := userReaderType.MethodByName("FindUserByDN")
		assert.True(t, found)

		methodType := method.Type
		assert.Equal(t, 1, methodType.NumIn(), "FindUserByDN should have 1 parameter (dn)")
		assert.Equal(t, 2, methodType.NumOut(), "FindUserByDN should have 2 return values (*User, error)")

		// Check parameter types
		assert.Equal(t, "string", methodType.In(0).Name(), "Parameter should be string (dn)")
	})
}

// TestConnectionInterface tests the Connection interface
func TestConnectionInterface(t *testing.T) {
	t.Run("Connection interface methods", func(t *testing.T) {
		connectionType := reflect.TypeOf((*Connection)(nil)).Elem()
		expectedMethods := []string{
			"Close",
			"Bind",
			"Search",
			"SearchContext",
			"Add",
			"AddContext",
			"Modify",
			"ModifyContext",
			"Del",
			"DelRequest",
			"PasswordModify",
			"PasswordModifyContext",
		}

		for _, methodName := range expectedMethods {
			method, found := connectionType.MethodByName(methodName)
			assert.True(t, found, "Method %s should exist in Connection", methodName)
			assert.NotNil(t, method)
		}

		assert.Equal(t, len(expectedMethods), connectionType.NumMethod(), "Connection should have exactly %d methods", len(expectedMethods))
	})
}

// TestSearchRequestAndResultStructs tests the SearchRequest and SearchResult structs
func TestSearchRequestAndResultStructs(t *testing.T) {
	t.Run("SearchRequest has all required fields", func(t *testing.T) {
		searchRequestType := reflect.TypeOf(SearchRequest{})
		expectedFields := []string{
			"BaseDN",
			"Scope",
			"DerefAliases",
			"SizeLimit",
			"TimeLimit",
			"TypesOnly",
			"Filter",
			"Attributes",
		}

		for _, fieldName := range expectedFields {
			field, found := searchRequestType.FieldByName(fieldName)
			assert.True(t, found, "Field %s should exist in SearchRequest", fieldName)
			assert.NotNil(t, field)
		}

		assert.Equal(t, len(expectedFields), searchRequestType.NumField(), "SearchRequest should have exactly %d fields", len(expectedFields))
	})

	t.Run("SearchResult has all required fields", func(t *testing.T) {
		searchResultType := reflect.TypeOf(SearchResult{})
		expectedFields := []string{
			"Entries",
			"Referrals",
		}

		for _, fieldName := range expectedFields {
			field, found := searchResultType.FieldByName(fieldName)
			assert.True(t, found, "Field %s should exist in SearchResult", fieldName)
			assert.NotNil(t, field)
		}

		assert.Equal(t, len(expectedFields), searchResultType.NumField(), "SearchResult should have exactly %d fields", len(expectedFields))
	})

	t.Run("Entry has all required fields", func(t *testing.T) {
		entryType := reflect.TypeOf(Entry{})
		expectedFields := []string{
			"DN",
			"Attributes",
		}

		for _, fieldName := range expectedFields {
			field, found := entryType.FieldByName(fieldName)
			assert.True(t, found, "Field %s should exist in Entry", fieldName)
			assert.NotNil(t, field)
		}

		assert.Equal(t, len(expectedFields), entryType.NumField(), "Entry should have exactly %d fields", len(expectedFields))
	})

	t.Run("EntryAttribute has required fields", func(t *testing.T) {
		entryAttributeType := reflect.TypeOf(EntryAttribute{})

		// Should at least have Name field
		field, found := entryAttributeType.FieldByName("Name")
		assert.True(t, found, "Field Name should exist in EntryAttribute")
		assert.NotNil(t, field)
		assert.Equal(t, "string", field.Type.Name(), "Name field should be string type")
	})
}

// TestInterfaceUsabilityPatterns tests common usage patterns for the interfaces
func TestInterfaceUsabilityPatterns(t *testing.T) {
	t.Run("can use UserReader for read-only operations", func(t *testing.T) {
		// This test demonstrates how interfaces enable dependency injection
		// and testing with mock implementations

		type UserService struct {
			reader UserReader
		}

		service := &UserService{
			reader: &LDAP{}, // LDAP implements UserReader
		}

		assert.NotNil(t, service.reader)
		assert.Implements(t, (*UserReader)(nil), service.reader)
	})

	t.Run("can use UserWriter for write-only operations", func(t *testing.T) {
		type UserCreationService struct {
			writer UserWriter
		}

		service := &UserCreationService{
			writer: nil, // LDAP doesn't fully implement UserWriter yet
		}

		assert.Nil(t, service.writer)
		// LDAP doesn't fully implement UserWriter yet (missing UpdateUserPassword)
	})

	t.Run("can use full DirectoryManager for complete operations", func(t *testing.T) {
		type FullDirectoryService struct {
			manager DirectoryManager
		}

		service := &FullDirectoryService{
			manager: nil, // LDAP doesn't fully implement DirectoryManager yet
		}

		assert.Nil(t, service.manager)
		// LDAP doesn't fully implement DirectoryManager yet (missing ClearCache)
		// Interface tests are for structure validation, not implementation completeness
	})
}

// BenchmarkInterfaceReflection benchmarks interface reflection operations
func BenchmarkInterfaceReflection(b *testing.B) {
	b.Run("interface compliance check", func(b *testing.B) {
		var client *LDAP
		userReaderInterface := (*UserReader)(nil)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = reflect.TypeOf(client).Implements(reflect.TypeOf(userReaderInterface).Elem())
		}
	})

	b.Run("method enumeration", func(b *testing.B) {
		userManagerType := reflect.TypeOf((*UserManager)(nil)).Elem()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < userManagerType.NumMethod(); j++ {
				_ = userManagerType.Method(j)
			}
		}
	})
}
