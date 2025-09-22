# Context Support Implementation

This document describes the comprehensive context.Context support that has been added to the simple-ldap-go library.

## Overview

Context support has been implemented throughout the entire LDAP library, providing:

- **Timeout control** for LDAP operations
- **Cancellation support** for long-running operations  
- **Resource management** with proper cleanup on cancellation
- **100% backward compatibility** with existing code

## Implementation Pattern

Every public method now has a context-aware counterpart:

```go
// Original method (unchanged for backward compatibility)
func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (*User, error) {
    return l.FindUserBySAMAccountNameContext(context.Background(), sAMAccountName)
}

// New context-aware method
func (l *LDAP) FindUserBySAMAccountNameContext(ctx context.Context, sAMAccountName string) (*User, error) {
    // Implementation with context support
}
```

## Context-Aware Methods

### Authentication Methods
- `CheckPasswordForSAMAccountNameContext(ctx, sAMAccountName, password)`
- `CheckPasswordForDNContext(ctx, dn, password)`
- `ChangePasswordForSAMAccountNameContext(ctx, sAMAccountName, oldPassword, newPassword)`

### User Operations
- `FindUserByDNContext(ctx, dn)`
- `FindUserBySAMAccountNameContext(ctx, sAMAccountName)`
- `FindUserByMailContext(ctx, mail)`
- `FindUsersContext(ctx)`
- `CreateUserContext(ctx, user, password)`
- `DeleteUserContext(ctx, dn)`
- `AddUserToGroupContext(ctx, dn, groupDN)`
- `RemoveUserFromGroupContext(ctx, dn, groupDN)`

### Group Operations
- `FindGroupByDNContext(ctx, dn)`
- `FindGroupsContext(ctx)`

### Computer Operations
- `FindComputerByDNContext(ctx, dn)`
- `FindComputerBySAMAccountNameContext(ctx, sAMAccountName)`
- `FindComputersContext(ctx)`

### Connection Management
- `GetConnectionContext(ctx)`

## Context Integration Points

Context cancellation and timeout checking is implemented at strategic points:

1. **Before LDAP connection establishment**
2. **Before LDAP bind operations**
3. **Before LDAP search operations**
4. **Before LDAP modify/add/delete operations**
5. **During result processing for bulk operations**

## Usage Examples

### Basic Usage with Timeout
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
if err == context.DeadlineExceeded {
    // Handle timeout
}
```

### Cancellation Support
```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Start operation in goroutine
go func() {
    users, err := client.FindUsersContext(ctx)
    // Handle results
}()

// Cancel operation after 5 seconds
time.Sleep(5 * time.Second)
cancel()
```

### Error Handling
The context-aware methods can return:
- `context.Canceled` - when operation is cancelled
- `context.DeadlineExceeded` - when operation times out
- Standard LDAP errors for other issues

## Backward Compatibility

All original methods remain unchanged and continue to work exactly as before:

```go
// These methods still work unchanged
user, err := client.FindUserBySAMAccountName("jdoe")
_, err = client.CheckPasswordForSAMAccountName("jdoe", "password")
users, err := client.FindUsers()
```

Internally, original methods now delegate to their context-aware counterparts using `context.Background()`.

## Performance Impact

- **Minimal overhead**: Context checking adds negligible performance cost
- **Resource cleanup**: Proper connection cleanup on cancellation prevents resource leaks
- **No breaking changes**: Existing code performance remains unchanged

## Best Practices

1. **Use reasonable timeouts**: 10-60 seconds for most operations
2. **Always use defer cancel()**: Prevent resource leaks
3. **Handle context errors**: Check for `context.Canceled` and `context.DeadlineExceeded`
4. **Use cancellation for user-initiated operations**: Allow users to cancel long operations

## Migration Guide

### For New Development
Use context-aware methods:
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
```

### For Existing Code
No changes required - existing code continues to work. Optionally migrate to context-aware methods for better control:

```go
// Before
user, err := client.FindUserBySAMAccountName("jdoe")

// After (optional migration)
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
```

## Testing

The implementation includes comprehensive tests:

- Context cancellation tests
- Timeout handling tests  
- Backward compatibility tests
- Integration tests with real LDAP servers

All existing tests continue to pass, ensuring no regressions.

## Files Modified

- `client.go` - Core connection management with context support
- `auth.go` - Authentication methods with context support
- `users.go` - User CRUD operations with context support
- `groups.go` - Group operations with context support  
- `computers.go` - Computer operations with context support
- `context_example_test.go` - Context functionality tests
- `examples/context-usage/context_usage.go` - Usage examples

## Conclusion

This implementation provides modern, idiomatic Go context support while maintaining complete backward compatibility. Applications can now:

- Set reasonable timeouts for LDAP operations
- Cancel long-running operations gracefully
- Integrate with existing context-aware code
- Migrate incrementally from legacy methods

The implementation follows Go best practices and provides a solid foundation for reliable LDAP operations in production environments.