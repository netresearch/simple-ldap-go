// Package internal provides generic type safety using Go 1.18+ generics.
// This file requires Go 1.18 or later for generic type constraints and functions.
//go:build go1.18

package internal

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/go-ldap/ldap/v3"

	ldaplib "github.com/netresearch/simple-ldap-go"
	"github.com/netresearch/simple-ldap-go/objects"
)

// LDAPObject defines the constraint for all LDAP objects that can be used with generic functions.
// This interface ensures type safety for LDAP operations while providing common methods.
type LDAPObject interface {
	// DN returns the distinguished name of the object
	DN() string
	// CN returns the common name of the object
	CN() string
}

// Ensure our types implement the LDAPObject constraint
var _ LDAPObject = (*objects.User)(nil)
var _ LDAPObject = (*objects.Group)(nil)
var _ LDAPObject = (*objects.Computer)(nil)

// LDAPObjectPtr defines a constraint for pointers to LDAP objects.
// This is used for generic functions that need to work with object pointers.
type LDAPObjectPtr[T LDAPObject] interface {
	*T
}

// Searchable defines the constraint for LDAP objects that can be searched.
// This extends LDAPObject with search-specific methods.
type Searchable[T LDAPObject] interface {
	LDAPObject
	// FromEntry creates an object from an LDAP entry
	FromEntry(entry *ldap.Entry) (T, error)
	// GetObjectClass returns the LDAP object class for searching
	GetObjectClass() string
	// GetSearchAttributes returns the attributes to retrieve during search
	GetSearchAttributes() []string
}

// Creatable defines the constraint for LDAP objects that can be created.
// This extends LDAPObject with creation-specific methods.
type Creatable[T LDAPObject] interface {
	LDAPObject
	// ToAddRequest converts the object to an LDAP add request
	ToAddRequest() (*ldap.AddRequest, error)
	// Validate validates the object before creation
	Validate() error
}

// Modifiable defines the constraint for LDAP objects that can be modified.
// This extends LDAPObject with modification-specific methods.
type Modifiable[T LDAPObject] interface {
	LDAPObject
	// ToModifyRequest converts changes to an LDAP modify request
	ToModifyRequest(changes map[string][]string) (*ldap.ModifyRequest, error)
	// GetModifiableAttributes returns the attributes that can be modified
	GetModifiableAttributes() []string
}

// Search performs a generic search operation that returns typed results.
// This function provides type safety for LDAP searches while reducing code duplication.
//
// Type parameter T must implement LDAPObject and Searchable constraints.
//
// Parameters:
//   - ctx: Context for controlling the search timeout and cancellation
//   - l: LDAP client to use for the search
//   - filter: LDAP filter string for the search
//   - baseDN: Base distinguished name for the search (empty string uses client's base DN)
//
// Returns:
//   - []T: Slice of typed LDAP objects matching the search criteria
//   - error: Any error encountered during the search operation
//
// Example:
//
//	// Search for users
//	users, err := Search[*objects.User](ctx, client, "(objectClass=user)", "")
//	if err != nil {
//	    return err
//	}
//	for _, user := range users {
//	    fmt.Printf("Found user: %s\n", user.CN())
//	}
//
//	// Search for groups
//	groups, err := Search[*objects.Group](ctx, client, "(objectClass=group)", "")
//	if err != nil {
//	    return err
//	}
//	for _, group := range groups {
//	    fmt.Printf("Found group: %s\n", group.CN())
//	}
func Search[T LDAPObject](ctx context.Context, l *ldaplib.LDAP, filter string, baseDN string) ([]T, error) {
	if baseDN == "" {
		baseDN = l.config.BaseDN
	}

	// Get the zero value of T to access its methods
	var zero T
	zeroType := reflect.TypeOf(zero)
	if zeroType == nil {
		return nil, fmt.Errorf("cannot determine type for search")
	}

	// Create a new instance to get searchable methods
	zeroValue := reflect.New(zeroType.Elem()).Interface()
	searchable, ok := zeroValue.(interface {
		GetObjectClass() string
		GetSearchAttributes() []string
		FromEntry(entry *ldap.Entry) (T, error)
	})
	if !ok {
		return nil, fmt.Errorf("type %T does not implement required search methods", zero)
	}

	// Build search request
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		0, // No time limit
		false,
		filter,
		searchable.GetSearchAttributes(),
		nil,
	)

	// Execute search
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	result, err := conn.SearchWithPaging(searchReq, 1000)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", WrapLDAPError("Search", l.config.Server, err))
	}

	// Convert entries to typed objects
	objects := make([]T, 0, len(result.Entries))
	for _, entry := range result.Entries {
		obj, err := searchable.FromEntry(entry)
		if err != nil {
			l.logger.Warn("failed to convert entry to object",
				slog.String("dn", entry.DN),
				slog.String("error", err.Error()))
			continue
		}
		objects = append(objects, obj)
	}

	return objects, nil
}

// Create performs a generic create operation for LDAP objects.
// This function provides type safety for LDAP object creation.
//
// Type parameter T must implement LDAPObject and Creatable constraints.
//
// Parameters:
//   - ctx: Context for controlling the create timeout and cancellation
//   - l: LDAP client to use for the creation
//   - obj: The object to create in LDAP
//
// Returns:
//   - string: The distinguished name of the created object
//   - error: Any error encountered during the creation operation
//
// Example:
//
//	user := &FullUser{
//	    CN: "John Doe",
//	    SAMAccountName: "jdoe",
//	    Mail: stringPtr("john.doe@example.com"),
//	}
//
//	dn, err := Create[*FullUser](ctx, client, user)
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Created user with DN: %s\n", dn)
func Create[T LDAPObject](ctx context.Context, l *ldaplib.LDAP, obj T) (string, error) {
	creatable, ok := any(obj).(interface {
		ToAddRequest() (*ldap.AddRequest, error)
		Validate() error
	})
	if !ok {
		return "", fmt.Errorf("type %T does not implement Creatable interface", obj)
	}

	// Validate the object before creation
	if err := creatable.Validate(); err != nil {
		return "", fmt.Errorf("object validation failed: %w", err)
	}

	// Convert to add request
	addReq, err := creatable.ToAddRequest()
	if err != nil {
		return "", fmt.Errorf("failed to create add request: %w", err)
	}

	// Execute creation
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Add(addReq); err != nil {
		return "", fmt.Errorf("add operation failed: %w", WrapLDAPError("Add", l.config.Server, err))
	}

	return addReq.DN, nil
}

// Modify performs a generic modify operation for LDAP objects.
// This function provides type safety for LDAP object modifications.
//
// Type parameter T must implement LDAPObject and Modifiable constraints.
//
// Parameters:
//   - ctx: Context for controlling the modify timeout and cancellation
//   - l: LDAP client to use for the modification
//   - obj: The object to modify
//   - changes: Map of attribute names to new values
//
// Returns:
//   - error: Any error encountered during the modification operation
//
// Example:
//
//	changes := map[string][]string{
//	    "description": {"Updated description"},
//	    "mail": {"new.email@example.com"},
//	}
//
//	err := Modify[*objects.User](ctx, client, user, changes)
//	if err != nil {
//	    return err
//	}
func Modify[T LDAPObject](ctx context.Context, l *ldaplib.LDAP, obj T, changes map[string][]string) error {
	modifiable, ok := any(obj).(interface {
		ToModifyRequest(changes map[string][]string) (*ldap.ModifyRequest, error)
		GetModifiableAttributes() []string
	})
	if !ok {
		return fmt.Errorf("type %T does not implement Modifiable interface", obj)
	}

	// Validate that all changes are for modifiable attributes
	modifiableAttrs := modifiable.GetModifiableAttributes()
	modifiableMap := make(map[string]bool, len(modifiableAttrs))
	for _, attr := range modifiableAttrs {
		modifiableMap[attr] = true
	}

	for attr := range changes {
		if !modifiableMap[attr] {
			return fmt.Errorf("attribute %s is not modifiable", attr)
		}
	}

	// Convert to modify request
	modReq, err := modifiable.ToModifyRequest(changes)
	if err != nil {
		return fmt.Errorf("failed to create modify request: %w", err)
	}

	// Execute modification
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("modify operation failed: %w", WrapLDAPError("Modify", l.config.Server, err))
	}

	return nil
}

// Delete performs a generic delete operation for LDAP objects.
// This function provides type safety for LDAP object deletion.
//
// Type parameter T must implement LDAPObject constraint.
//
// Parameters:
//   - ctx: Context for controlling the delete timeout and cancellation
//   - l: LDAP client to use for the deletion
//   - obj: The object to delete (only DN is used)
//
// Returns:
//   - error: Any error encountered during the deletion operation
//
// Example:
//
//	err := Delete[*objects.User](ctx, client, user)
//	if err != nil {
//	    return err
//	}
func Delete[T LDAPObject](ctx context.Context, l *ldaplib.LDAP, obj T) error {
	return DeleteByDN(ctx, l, obj.DN())
}

// DeleteByDN performs a generic delete operation by distinguished name.
// This function provides a convenient way to delete objects by DN.
//
// Parameters:
//   - ctx: Context for controlling the delete timeout and cancellation
//   - l: LDAP client to use for the deletion
//   - dn: Distinguished name of the object to delete
//
// Returns:
//   - error: Any error encountered during the deletion operation
func DeleteByDN(ctx context.Context, l *ldaplib.LDAP, dn string) error {
	delReq := ldap.NewDelRequest(dn, nil)

	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Del(delReq); err != nil {
		return fmt.Errorf("delete operation failed: %w", WrapLDAPError("Del", l.config.Server, err))
	}

	return nil
}

// FindByDN performs a generic search by distinguished name.
// This function provides type safety for DN-based lookups.
//
// Type parameter T must implement LDAPObject constraint.
//
// Parameters:
//   - ctx: Context for controlling the search timeout and cancellation
//   - l: LDAP client to use for the search
//   - dn: Distinguished name to search for
//
// Returns:
//   - T: The found object
//   - error: Any error encountered during the search, including ErrNotFound if no object is found
//
// Example:
//
//	user, err := FindByDN[*objects.User](ctx, client, "CN=John Doe,OU=Users,DC=example,DC=com")
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Found user: %s\n", user.CN())
func FindByDN[T LDAPObject](ctx context.Context, l *ldaplib.LDAP, dn string) (T, error) {
	var zero T

	// Get the zero value of T to access its methods
	zeroType := reflect.TypeOf(zero)
	if zeroType == nil {
		return zero, fmt.Errorf("cannot determine type for search")
	}

	// Create a new instance to get searchable methods
	zeroValue := reflect.New(zeroType.Elem()).Interface()
	searchable, ok := zeroValue.(interface {
		GetSearchAttributes() []string
		FromEntry(entry *ldap.Entry) (T, error)
	})
	if !ok {
		return zero, fmt.Errorf("type %T does not implement required search methods", zero)
	}

	// Build search request for specific DN
	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, // Size limit 1
		0, // No time limit
		false,
		"(objectClass=*)",
		searchable.GetSearchAttributes(),
		nil,
	)

	// Execute search
	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return zero, fmt.Errorf("failed to get connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	result, err := conn.Search(searchReq)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return zero, ErrUserNotFound // This could be made generic
		}
		return zero, fmt.Errorf("search failed: %w", WrapLDAPError("Search", l.config.Server, err))
	}

	if len(result.Entries) == 0 {
		return zero, ErrUserNotFound // This could be made generic
	}

	if len(result.Entries) > 1 {
		return zero, ErrDNDuplicated
	}

	// Convert entry to typed object
	obj, err := searchable.FromEntry(result.Entries[0])
	if err != nil {
		return zero, fmt.Errorf("failed to convert entry to object: %w", err)
	}

	return obj, nil
}

// BatchOperation represents a batch operation that can be performed on multiple objects.
type BatchOperation[T LDAPObject] struct {
	Operation string // "create", "modify", "delete"
	Object    T
	Changes   map[string][]string // For modify operations
}

// BatchResult represents the result of a batch operation.
type BatchResult[T LDAPObject] struct {
	Object T
	Error  error
	DN     string // For create operations
}

// BatchProcess performs batch operations on multiple objects with type safety.
// This function provides efficient processing of multiple LDAP operations.
//
// Type parameter T must implement LDAPObject constraint.
//
// Parameters:
//   - ctx: Context for controlling the batch timeout and cancellation
//   - l: LDAP client to use for the operations
//   - operations: Slice of operations to perform
//
// Returns:
//   - []BatchResult[T]: Results for each operation, including any errors
//   - error: Any error that prevented the batch from running at all
//
// Example:
//
//	operations := []BatchOperation[*objects.User]{
//	    {Operation: "create", Object: newUser1},
//	    {Operation: "modify", Object: existingUser, Changes: changes},
//	    {Operation: "delete", Object: oldUser},
//	}
//
//	results, err := BatchProcess[*objects.User](ctx, client, operations)
//	if err != nil {
//	    return err
//	}
//
//	for i, result := range results {
//	    if result.Error != nil {
//	        fmt.Printf("Operation %d failed: %v\n", i, result.Error)
//	    }
//	}
func BatchProcess[T LDAPObject](ctx context.Context, l *ldaplib.LDAP, operations []BatchOperation[T]) ([]BatchResult[T], error) {
	results := make([]BatchResult[T], len(operations))

	// Process operations sequentially for now
	// This could be optimized with goroutines and connection pooling
	for i, op := range operations {
		result := BatchResult[T]{Object: op.Object}

		switch op.Operation {
		case "create":
			dn, err := Create[T](ctx, l, op.Object)
			result.DN = dn
			result.Error = err

		case "modify":
			result.Error = Modify[T](ctx, l, op.Object, op.Changes)

		case "delete":
			result.Error = Delete[T](ctx, l, op.Object)

		default:
			result.Error = fmt.Errorf("unknown operation: %s", op.Operation)
		}

		results[i] = result

		// Stop on first error if context is cancelled
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
	}

	return results, nil
}

// OperationPipeline provides a fluent API for chaining LDAP operations with type safety.
// This is different from the general-purpose Pipeline in concurrency.go
type OperationPipeline[T LDAPObject] struct {
	client *ldaplib.LDAP
	ctx    context.Context
	errors []error
}

// NewOperationPipeline creates a new typed pipeline for LDAP operations.
func NewOperationPipeline[T LDAPObject](ctx context.Context, l *ldaplib.LDAP) *OperationPipeline[T] {
	return &OperationPipeline[T]{
		client: l,
		ctx:    ctx,
		errors: make([]error, 0),
	}
}

// Create adds a create operation to the pipeline.
func (p *OperationPipeline[T]) Create(obj T) *OperationPipeline[T] {
	if len(p.errors) == 0 { // Only proceed if no previous errors
		_, err := Create[T](p.ctx, p.client, obj)
		if err != nil {
			p.errors = append(p.errors, fmt.Errorf("create failed: %w", err))
		}
	}
	return p
}

// Modify adds a modify operation to the pipeline.
func (p *OperationPipeline[T]) Modify(obj T, changes map[string][]string) *OperationPipeline[T] {
	if len(p.errors) == 0 { // Only proceed if no previous errors
		err := Modify[T](p.ctx, p.client, obj, changes)
		if err != nil {
			p.errors = append(p.errors, fmt.Errorf("modify failed: %w", err))
		}
	}
	return p
}

// Delete adds a delete operation to the pipeline.
func (p *OperationPipeline[T]) Delete(obj T) *OperationPipeline[T] {
	if len(p.errors) == 0 { // Only proceed if no previous errors
		err := Delete[T](p.ctx, p.client, obj)
		if err != nil {
			p.errors = append(p.errors, fmt.Errorf("delete failed: %w", err))
		}
	}
	return p
}

// Execute completes the pipeline and returns any accumulated errors.
func (p *OperationPipeline[T]) Execute() error {
	if len(p.errors) > 0 {
		return fmt.Errorf("pipeline failed with %d errors: %v", len(p.errors), p.errors)
	}
	return nil
}
