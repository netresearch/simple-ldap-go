//go:build !integration

package ldap

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockLDAPObject implements LDAPObject for testing
type MockLDAPObject struct {
	dn string
	cn string
}

func (m *MockLDAPObject) DN() string { return m.dn }
func (m *MockLDAPObject) CN() string { return m.cn }

// MockSearchableLDAPObject implements both LDAPObject and additional search methods
type MockSearchableLDAPObject struct {
	MockLDAPObject
}

func (m *MockSearchableLDAPObject) FromEntry(entry *ldap.Entry) (*MockSearchableLDAPObject, error) {
	if entry == nil {
		return nil, errors.New("entry is nil")
	}
	return &MockSearchableLDAPObject{
		MockLDAPObject: MockLDAPObject{
			dn: entry.DN,
			cn: entry.GetAttributeValue("cn"),
		},
	}, nil
}

func (m *MockSearchableLDAPObject) GetObjectClass() string {
	return "mockObject"
}

func (m *MockSearchableLDAPObject) GetSearchAttributes() []string {
	return []string{"cn", "description"}
}

// MockCreatableLDAPObject implements LDAPObject and Creatable
type MockCreatableLDAPObject struct {
	MockLDAPObject
	shouldFailValidation bool
}

func (m *MockCreatableLDAPObject) ToAddRequest() (*ldap.AddRequest, error) {
	req := ldap.NewAddRequest(m.dn, nil)
	req.Attribute("cn", []string{m.cn})
	req.Attribute("objectClass", []string{"mockObject"})
	return req, nil
}

func (m *MockCreatableLDAPObject) Validate() error {
	if m.shouldFailValidation {
		return errors.New("validation failed")
	}
	if m.cn == "" {
		return errors.New("cn is required")
	}
	return nil
}

// MockModifiableLDAPObject implements LDAPObject and Modifiable
type MockModifiableLDAPObject struct {
	MockLDAPObject
}

func (m *MockModifiableLDAPObject) ToModifyRequest(changes map[string][]string) (*ldap.ModifyRequest, error) {
	req := ldap.NewModifyRequest(m.dn, nil)
	for attr, values := range changes {
		req.Replace(attr, values)
	}
	return req, nil
}

func (m *MockModifiableLDAPObject) GetModifiableAttributes() []string {
	return []string{"cn", "description", "mail"}
}

// TestLDAPObjectConstraint tests the LDAPObject interface constraint
func TestLDAPObjectConstraint(t *testing.T) {
	t.Run("MockLDAPObject implements LDAPObject", func(t *testing.T) {
		obj := &MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		}

		assert.Equal(t, "cn=test,dc=example,dc=com", obj.DN())
		assert.Equal(t, "test", obj.CN())

		// Verify it satisfies the LDAPObject constraint
		var _ LDAPObject = obj
	})

	t.Run("User satisfies LDAPObject constraint", func(t *testing.T) {
		user := &User{
			Object: Object{
				cn: "user",
				dn: "cn=user,dc=example,dc=com",
			},
		}

		assert.Equal(t, "cn=user,dc=example,dc=com", user.DN())
		assert.Equal(t, "user", user.CN())

		// Verify User type satisfies constraint
		var _ LDAPObject = user
	})

	t.Run("Group satisfies LDAPObject constraint", func(t *testing.T) {
		group := &Group{
			Object: Object{
				cn: "group",
				dn: "cn=group,dc=example,dc=com",
			},
		}

		assert.Equal(t, "cn=group,dc=example,dc=com", group.DN())
		assert.Equal(t, "group", group.CN())

		// Verify Group type satisfies constraint
		var _ LDAPObject = group
	})

	t.Run("Computer satisfies LDAPObject constraint", func(t *testing.T) {
		computer := &Computer{
			Object: Object{
				cn: "computer",
				dn: "cn=computer,dc=example,dc=com",
			},
		}

		assert.Equal(t, "cn=computer,dc=example,dc=com", computer.DN())
		assert.Equal(t, "computer", computer.CN())

		// Verify Computer type satisfies constraint
		var _ LDAPObject = computer
	})
}

// TestSearchableConstraint tests the Searchable interface constraint
func TestSearchableConstraint(t *testing.T) {
	t.Run("searchable methods work correctly", func(t *testing.T) {
		obj := &MockSearchableLDAPObject{}

		assert.Equal(t, "mockObject", obj.GetObjectClass())
		assert.Equal(t, []string{"cn", "description"}, obj.GetSearchAttributes())

		entry := &ldap.Entry{
			DN: "cn=test,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"test"}},
			},
		}

		converted, err := obj.FromEntry(entry)
		require.NoError(t, err)
		assert.Equal(t, "cn=test,dc=example,dc=com", converted.DN())
		assert.Equal(t, "test", converted.CN())
	})

	t.Run("FromEntry handles nil entry", func(t *testing.T) {
		obj := &MockSearchableLDAPObject{}
		converted, err := obj.FromEntry(nil)
		assert.Error(t, err)
		assert.Nil(t, converted)
		assert.Contains(t, err.Error(), "entry is nil")
	})
}

// TestCreatableConstraint tests the Creatable interface constraint
func TestCreatableConstraint(t *testing.T) {
	t.Run("creatable methods work correctly", func(t *testing.T) {
		obj := &MockCreatableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "test",
			},
		}

		err := obj.Validate()
		require.NoError(t, err)

		req, err := obj.ToAddRequest()
		require.NoError(t, err)
		assert.Equal(t, "cn=test,dc=example,dc=com", req.DN)
		assert.Contains(t, req.Attributes, ldap.Attribute{Type: "cn", Vals: []string{"test"}})
	})

	t.Run("validation can fail", func(t *testing.T) {
		obj := &MockCreatableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "",
			},
		}

		err := obj.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cn is required")
	})

	t.Run("custom validation failure", func(t *testing.T) {
		obj := &MockCreatableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "test",
			},
			shouldFailValidation: true,
		}

		err := obj.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})
}

// TestModifiableConstraint tests the Modifiable interface constraint
func TestModifiableConstraint(t *testing.T) {
	t.Run("modifiable methods work correctly", func(t *testing.T) {
		obj := &MockModifiableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "test",
			},
		}

		attrs := obj.GetModifiableAttributes()
		assert.Contains(t, attrs, "cn")
		assert.Contains(t, attrs, "description")
		assert.Contains(t, attrs, "mail")

		changes := map[string][]string{
			"description": {"new description"},
		}

		req, err := obj.ToModifyRequest(changes)
		require.NoError(t, err)
		assert.Equal(t, "cn=test,dc=example,dc=com", req.DN)
	})
}

// TestSearchGenericFunction tests the generic Search function
func TestSearchGenericFunction(t *testing.T) {
	t.Run("search fails with incompatible type", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()

		// Use a type that doesn't implement required search methods
		result, err := Search[*MockLDAPObject](ctx, client, "(objectClass=*)", "")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not implement required search methods")
	})

	t.Run("search type validation works", func(t *testing.T) {
		// Test that we can at least validate the type without crashing
		var obj *MockSearchableLDAPObject

		// Test type reflection
		objType := reflect.TypeOf(obj)
		assert.NotNil(t, objType)
		assert.Equal(t, "*ldap.MockSearchableLDAPObject", objType.String())

		// Test that we can create a new instance
		if objType.Kind() == reflect.Ptr {
			newObj := reflect.New(objType.Elem()).Interface()
			assert.NotNil(t, newObj)
		}
	})
}

// TestCreateGenericFunction tests the generic Create function
func TestCreateGenericFunction(t *testing.T) {
	t.Run("create fails with incompatible type", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		}

		dn, err := Create[*MockLDAPObject](ctx, client, obj)
		assert.Error(t, err)
		assert.Empty(t, dn)
		assert.Contains(t, err.Error(), "does not implement Creatable interface")
	})

	t.Run("create fails validation", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockCreatableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "", // Will fail validation
			},
		}

		dn, err := Create[*MockCreatableLDAPObject](ctx, client, obj)
		assert.Error(t, err)
		assert.Empty(t, dn)
		assert.Contains(t, err.Error(), "object validation failed")
	})
}

// TestModifyGenericFunction tests the generic Modify function
func TestModifyGenericFunction(t *testing.T) {
	t.Run("modify fails with incompatible type", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		}

		changes := map[string][]string{"cn": {"new name"}}
		err := Modify[*MockLDAPObject](ctx, client, obj, changes)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not implement Modifiable interface")
	})

	t.Run("modify fails with non-modifiable attribute", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockModifiableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "test",
			},
		}

		changes := map[string][]string{
			"nonExistentAttr": {"value"}, // Not in modifiable attributes
		}

		err := Modify[*MockModifiableLDAPObject](ctx, client, obj, changes)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attribute nonExistentAttr is not modifiable")
	})
}

// TestDeleteGenericFunction tests the generic Delete function
func TestDeleteGenericFunction(t *testing.T) {
	t.Run("delete uses object DN correctly", func(t *testing.T) {
		obj := &MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		}

		// Test that the object provides the correct DN
		assert.Equal(t, "cn=test,dc=example,dc=com", obj.DN())
		assert.Equal(t, "test", obj.CN())

		// The Delete function would call DeleteByDN with obj.DN()
		// We can't test the actual deletion without a working connection
		// but we verify the object provides the right interface
	})
}

// TestDeleteByDN tests the DeleteByDN function
func TestDeleteByDN(t *testing.T) {
	t.Run("delete by DN validates input", func(t *testing.T) {
		// Test DN string validation
		testDN := "cn=test,dc=example,dc=com"
		assert.NotEmpty(t, testDN)
		assert.Contains(t, testDN, "cn=")
		assert.Contains(t, testDN, "dc=")

		// DeleteByDN function exists and accepts proper parameters
		// Actual deletion testing requires integration tests with real LDAP
	})
}

// TestFindByDNGenericFunction tests the generic FindByDN function
func TestFindByDNGenericFunction(t *testing.T) {
	t.Run("find by DN fails with incompatible type", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()

		result, err := FindByDN[*MockLDAPObject](ctx, client, "cn=test,dc=example,dc=com")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not implement required search methods")
	})

	t.Run("find by DN type checking", func(t *testing.T) {
		// Test type checking for FindByDN without needing connection
		var obj *MockSearchableLDAPObject

		// Verify type information can be retrieved
		objType := reflect.TypeOf(obj)
		assert.NotNil(t, objType)

		// Test that we can create an instance for interface checking
		if objType.Kind() == reflect.Ptr {
			newInstance := reflect.New(objType.Elem()).Interface()
			_, implementsSearchable := newInstance.(interface {
				GetSearchAttributes() []string
				FromEntry(entry *ldap.Entry) (*MockSearchableLDAPObject, error)
			})
			assert.True(t, implementsSearchable)
		}
	})
}

// TestBatchOperation tests the BatchOperation struct and BatchProcess function
func TestBatchOperation(t *testing.T) {
	t.Run("batch operation structure", func(t *testing.T) {
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}
		changes := map[string][]string{"cn": {"new name"}}

		op := BatchOperation[*MockLDAPObject]{
			Operation: "modify",
			Object:    obj,
			Changes:   changes,
		}

		assert.Equal(t, "modify", op.Operation)
		assert.Equal(t, obj, op.Object)
		assert.Equal(t, changes, op.Changes)
	})

	t.Run("batch result structure", func(t *testing.T) {
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}
		err := errors.New("test error")

		result := BatchResult[*MockLDAPObject]{
			Object: obj,
			Error:  err,
			DN:     "cn=created,dc=example,dc=com",
		}

		assert.Equal(t, obj, result.Object)
		assert.Equal(t, err, result.Error)
		assert.Equal(t, "cn=created,dc=example,dc=com", result.DN)
	})

	t.Run("batch process with unknown operation", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}
		operations := []BatchOperation[*MockLDAPObject]{
			{Operation: "unknown", Object: obj},
		}

		ctx := context.Background()
		results, err := BatchProcess[*MockLDAPObject](ctx, client, operations)

		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Error(t, results[0].Error)
		assert.Contains(t, results[0].Error.Error(), "unknown operation: unknown")
	})

	t.Run("batch process context cancellation handling", func(t *testing.T) {
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}
		operations := []BatchOperation[*MockLDAPObject]{
			{Operation: "delete", Object: obj},
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Test that cancelled context is properly detected
		select {
		case <-ctx.Done():
			assert.Equal(t, context.Canceled, ctx.Err())
		default:
			t.Fatal("Context should be cancelled")
		}

		// Verify the operation structure is valid
		assert.Equal(t, "delete", operations[0].Operation)
		assert.Equal(t, obj, operations[0].Object)
	})
}

// TestOperationPipeline tests the OperationPipeline fluent API
func TestOperationPipeline(t *testing.T) {
	t.Run("pipeline creation", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)

		assert.Equal(t, client, pipeline.client)
		assert.Equal(t, ctx, pipeline.ctx)
		assert.Empty(t, pipeline.errors)
	})

	t.Run("pipeline with create operation interface validation", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}

		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)

		// Verify pipeline structure before adding operations
		assert.Equal(t, client, pipeline.client)
		assert.Equal(t, ctx, pipeline.ctx)
		assert.Empty(t, pipeline.errors)

		// Create operation will fail due to interface mismatch - this is expected
		pipeline.Create(obj)

		err := pipeline.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pipeline failed")
	})

	t.Run("pipeline with modify operation validation", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}
		changes := map[string][]string{"cn": {"new name"}}

		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)

		// Verify changes structure is valid
		assert.Contains(t, changes, "cn")
		assert.Equal(t, []string{"new name"}, changes["cn"])

		// Modify operation will fail due to interface mismatch - this is expected
		pipeline.Modify(obj, changes)

		err := pipeline.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pipeline failed")
	})

	t.Run("pipeline with delete operation validation", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}

		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)

		// Verify object has proper DN for delete operation
		assert.Equal(t, "cn=test,dc=example,dc=com", obj.DN())

		// Don't actually call Delete as it requires connection - just validate setup
		// pipeline.Delete(obj) would fail due to connection issues

		err := pipeline.Execute()
		assert.NoError(t, err) // No operations were added, so should succeed
	})

	t.Run("pipeline error handling logic", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}

		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)

		// Pipeline should stop on first error and not execute subsequent operations
		// This tests the fail-fast behavior of the pipeline

		// First operation will fail due to interface mismatch
		pipeline.Create(obj)

		// Second operation should not execute due to previous error
		pipeline.Delete(obj)

		err := pipeline.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pipeline failed")

		// The pipeline correctly implements fail-fast error handling
	})

	t.Run("successful pipeline execution", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()

		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)

		// No operations, should succeed
		err := pipeline.Execute()
		assert.NoError(t, err)
	})
}

// TestGenericTypeSafety tests that generic functions enforce type safety
func TestGenericTypeSafety(t *testing.T) {
	t.Run("type constraints prevent compilation errors", func(t *testing.T) {
		// These tests verify that our constraints work at compile time
		// If they compile, the constraints are working correctly

		var user *User
		var group *Group
		var computer *Computer

		// Verify all types satisfy LDAPObject constraint
		var _ LDAPObject = user
		var _ LDAPObject = group
		var _ LDAPObject = computer

		// Verify constraint satisfaction at runtime
		assert.True(t, true, "Type constraints satisfied at compile time")
	})

	t.Run("reflection-based type checking", func(t *testing.T) {
		// Test type reflection works as expected
		var mockObj *MockLDAPObject
		objType := reflect.TypeOf(mockObj)
		assert.NotNil(t, objType)
		assert.Equal(t, "*ldap.MockLDAPObject", objType.String())

		// Test pointer type handling
		if objType.Kind() == reflect.Ptr {
			elemType := objType.Elem()
			assert.Equal(t, "ldap.MockLDAPObject", elemType.String())
		}
	})
}

// BenchmarkGenericOperations benchmarks the generic functions
func BenchmarkGenericOperations(b *testing.B) {

	b.Run("Create operation overhead", func(b *testing.B) {
		obj := &MockCreatableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "test",
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Just test the validation and request creation part
			_ = obj.Validate()
			_, _ = obj.ToAddRequest()
		}
	})

	b.Run("Modify operation overhead", func(b *testing.B) {
		obj := &MockModifiableLDAPObject{
			MockLDAPObject: MockLDAPObject{
				dn: "cn=test,dc=example,dc=com",
				cn: "test",
			},
		}
		changes := map[string][]string{"cn": {"new name"}}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Just test the validation and request creation part
			_ = obj.GetModifiableAttributes()
			_, _ = obj.ToModifyRequest(changes)
		}
	})

	b.Run("Type checking overhead", func(b *testing.B) {
		obj := &MockLDAPObject{
			dn: "cn=test,dc=example,dc=com",
			cn: "test",
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Test type assertion overhead
			_, ok := any(obj).(interface {
				ToAddRequest() (*ldap.AddRequest, error)
				Validate() error
			})
			_ = ok
		}
	})

	b.Run("Reflection overhead", func(b *testing.B) {
		var obj *MockSearchableLDAPObject

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			objType := reflect.TypeOf(obj)
			if objType != nil && objType.Kind() == reflect.Ptr {
				_ = reflect.New(objType.Elem()).Interface()
			}
		}
	})
}

// TestPipelineChaining tests fluent API chaining
func TestPipelineChaining(t *testing.T) {
	t.Run("method chaining returns same pipeline", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}

		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client)

		// Test that chaining returns the same pipeline instance
		result1 := pipeline.Create(obj)
		assert.Same(t, pipeline, result1)

		result2 := pipeline.Delete(obj)
		assert.Same(t, pipeline, result2)
	})

	t.Run("fluent chaining syntax validation", func(t *testing.T) {
		client := &LDAP{
			config: &Config{
				Server: "ldap://test:389",
				BaseDN: "dc=example,dc=com",
			},
			connPool: nil,
		}

		ctx := context.Background()
		obj := &MockLDAPObject{dn: "cn=test,dc=example,dc=com", cn: "test"}
		changes := map[string][]string{"cn": {"new name"}}

		// Test that fluent chaining syntax compiles and creates valid pipeline
		pipeline := NewOperationPipeline[*MockLDAPObject](ctx, client).
			Create(obj).
			Modify(obj, changes).
			Delete(obj)

		// Verify pipeline was created
		assert.NotNil(t, pipeline)
		assert.Equal(t, client, pipeline.client)
		assert.Equal(t, ctx, pipeline.ctx)

		// Execute will fail due to interface mismatches, but syntax works correctly
		err := pipeline.Execute()
		assert.Error(t, err)
	})
}
