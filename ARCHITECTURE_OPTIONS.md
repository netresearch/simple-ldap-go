# Architecture Options: Avoiding Breaking Changes

## Goal
Improve project structure and organization WITHOUT breaking the existing API where users call `client.FindUserBySAMAccountName()`.

## Option 1: Keep Everything in Main Package (Recommended)
**Structure:**
```
github.com/netresearch/simple-ldap-go/
├── ldap.go           # Main LDAP client
├── users.go          # User-related methods on LDAP
├── groups.go         # Group-related methods on LDAP
├── computers.go      # Computer-related methods on LDAP
├── auth.go           # Authentication methods on LDAP
├── types.go          # All type definitions
└── internal/         # Private implementation details
    ├── cache/
    ├── pool/
    └── validation/
```

**Pros:**
- ✅ NO breaking changes - all methods stay on LDAP type
- ✅ Clean API: `client.FindUser()` works as before
- ✅ Can still organize code into logical files
- ✅ Internal package for private implementation

**Cons:**
- ❌ All types in same package (larger API surface)
- ❌ Single large package documentation

**Implementation:**
```go
// users.go - in main package
package ldap

func (l *LDAP) FindUserBySAMAccountName(sam string) (*User, error) {
    // Implementation here
}
```

## Option 2: Interface-Based Facade Pattern
**Structure:**
```
github.com/netresearch/simple-ldap-go/
├── ldap.go           # LDAP client with embedded interfaces
├── interfaces.go     # Define interfaces
└── objects/
    ├── users.go      # Implement UserManager interface
    └── groups.go     # Implement GroupManager interface
```

**Implementation:**
```go
// interfaces.go
type UserManager interface {
    FindUserBySAMAccountName(sam string) (*User, error)
    FindUsers() ([]User, error)
}

// ldap.go
type LDAP struct {
    UserManager   // Embedded interface
    GroupManager  // Embedded interface
    // ... other fields
}

// New creates LDAP with implementations
func New(config *Config, user, pass string) (*LDAP, error) {
    client := &LDAP{...}
    client.UserManager = objects.NewUserManager(client)
    return client
}

// Usage stays the same!
client.FindUserBySAMAccountName("jdoe") // Works via embedded interface
```

**Pros:**
- ✅ NO breaking changes
- ✅ Better separation of concerns
- ✅ Easier to mock/test individual components

**Cons:**
- ❌ More complex setup
- ❌ Circular dependency challenges

## Option 3: Subpackages for New Features Only
**Structure:**
```
github.com/netresearch/simple-ldap-go/
├── *.go              # All existing v1 code stays here
├── advanced/         # New features go in subpackages
│   ├── batch.go      # Batch operations
│   └── audit.go      # Audit logging
└── builders/         # Keep builders separate
    └── query.go
```

**Pros:**
- ✅ NO breaking changes to existing API
- ✅ New features organized in subpackages
- ✅ Gradual migration path

**Cons:**
- ❌ Inconsistent - old in main, new in subpackages
- ❌ Doesn't solve current organization issues

## Option 4: Type Aliases + Method Forwarding
**Structure:**
```
github.com/netresearch/simple-ldap-go/
├── ldap.go           # Main client with ALL methods as forwards
├── types.go          # Type aliases
└── v2/
    └── objects/      # New organized structure
        ├── users.go
        └── groups.go
```

**Implementation:**
```go
// ldap.go - Forward all methods to v2 functions
func (l *LDAP) FindUserBySAMAccountName(sam string) (*User, error) {
    return v2.FindUserBySAMAccountName(l, sam)
}

// Users can choose:
client.FindUserBySAMAccountName("jdoe")           // Old way still works
v2.FindUserBySAMAccountName(client, "jdoe")       // New way available
```

**Pros:**
- ✅ NO breaking changes
- ✅ Provides migration path
- ✅ Both APIs available

**Cons:**
- ❌ Duplicate API surface
- ❌ More maintenance

## Option 5: Internal Packages for Organization
**Structure:**
```
github.com/netresearch/simple-ldap-go/
├── *.go                      # Public API (thin layer)
└── internal/
    ├── operations/
    │   ├── users.go          # User operation logic
    │   ├── groups.go         # Group operation logic
    │   └── computers.go      # Computer operation logic
    ├── types/
    │   └── models.go         # Internal type definitions
    └── core/
        └── connection.go     # Core LDAP operations
```

**Implementation:**
```go
// ldap.go - Public API
package ldap

import "github.com/netresearch/simple-ldap-go/internal/operations"

func (l *LDAP) FindUserBySAMAccountName(sam string) (*User, error) {
    return operations.FindUserBySAMAccountName(l.conn, sam)
}
```

**Pros:**
- ✅ NO breaking changes
- ✅ Clean internal organization
- ✅ Implementation details hidden
- ✅ Easier to refactor internals

**Cons:**
- ❌ Public API still in one package
- ❌ Can't reuse internal packages

## RECOMMENDATION: Option 1 + Option 5 Hybrid

Best approach for this library:

```
github.com/netresearch/simple-ldap-go/
├── ldap.go           # LDAP client type and connection methods
├── users.go          # User-related methods on LDAP
├── groups.go         # Group-related methods on LDAP
├── computers.go      # Computer-related methods on LDAP
├── auth.go           # Authentication methods
├── types.go          # Public types (User, Group, etc.)
├── errors.go         # Error definitions
├── doc.go            # Package documentation
└── internal/         # Private implementation
    ├── cache/        # Caching logic
    ├── pool/         # Connection pooling
    ├── validation/   # Input validation
    ├── operations/   # Core LDAP operations
    └── converter/    # Type conversions
```

### Why This Works Best:

1. **NO Breaking Changes**: All existing code continues to work
2. **Logical Organization**: Code split into files by domain
3. **Hidden Complexity**: Internal package hides implementation
4. **Single Import**: Users only need one import
5. **Go Idiomatic**: Follows Go project patterns

### Implementation Plan:

1. **Move objects/ content BACK to main package**:
   - `objects/users.go` → `users.go` (convert functions back to methods)
   - `objects/groups.go` → `groups.go` (convert functions back to methods)
   - `objects/computers.go` → `computers.go` (convert functions back to methods)

2. **Create internal organization**:
   - Move complex logic to `internal/operations/`
   - Move helper functions to `internal/`

3. **Keep types in main package**:
   - All public types stay in main package
   - No import changes needed

### Example Implementation:

```go
// users.go - in main package
package ldap

import "github.com/netresearch/simple-ldap-go/internal/operations"

// Method on LDAP - preserves API
func (l *LDAP) FindUserBySAMAccountName(sam string) (*User, error) {
    return l.FindUserBySAMAccountNameContext(context.Background(), sam)
}

func (l *LDAP) FindUserBySAMAccountNameContext(ctx context.Context, sam string) (*User, error) {
    // Delegate to internal package for actual implementation
    entry, err := operations.SearchUserBySAMAccountName(ctx, l.conn, l.config, sam)
    if err != nil {
        return nil, err
    }
    return convertToUser(entry), nil
}
```

This preserves the entire v1 API while achieving better internal organization!