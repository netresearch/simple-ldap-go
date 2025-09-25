# Migration Guide: v1.1.x to v2.0.0

Version 2.0.0 introduces a new package structure for better code organization. This is a **breaking change** due to circular import constraints that prevent backwards-compatible type aliases.

## What Changed

The library has been restructured from a single package into focused packages:

### Before (v1.1.x)
```go
import "github.com/netresearch/simple-ldap-go"

var user *ldap.User
var group *ldap.Group
var builder *ldap.UserBuilder
```

### After (v2.0.0)
```go
import (
    "github.com/netresearch/simple-ldap-go"
    "github.com/netresearch/simple-ldap-go/objects"
    "github.com/netresearch/simple-ldap-go/search"
)

var user *objects.User
var group *objects.Group
var builder *search.UserBuilder
```

## Package Structure

- **Main package** (`github.com/netresearch/simple-ldap-go`) - LDAP client and core functionality
- **`objects/`** - LDAP object types (User, Group, Computer, etc.)
- **`search/`** - Search builders and query construction
- **`auth/`** - Authentication operations
- **`internal/`** - Internal implementation details

## Migration Steps

### 1. Update Imports

**Old:**
```go
import "github.com/netresearch/simple-ldap-go"
```

**New:**
```go
import (
    "github.com/netresearch/simple-ldap-go"
    "github.com/netresearch/simple-ldap-go/objects"
    "github.com/netresearch/simple-ldap-go/search"
)
```

### 2. Update Type References

| Old Type | New Type |
|----------|----------|
| `ldap.User` | `objects.User` |
| `ldap.Group` | `objects.Group` |
| `ldap.Computer` | `objects.Computer` |
| `ldap.FullUser` | `objects.FullUser` |
| `ldap.FullGroup` | `objects.FullGroup` |
| `ldap.FullComputer` | `objects.FullComputer` |
| `ldap.Object` | `objects.Object` |
| `ldap.UAC` | `objects.UAC` |
| `ldap.UserBuilder` | `search.UserBuilder` |
| `ldap.GroupBuilder` | `search.GroupBuilder` |
| `ldap.ComputerBuilder` | `search.ComputerBuilder` |
| `ldap.ConfigBuilder` | `search.ConfigBuilder` |
| `ldap.QueryBuilder` | `search.QueryBuilder` |

### 3. Update Method Calls to Function Calls

| Old Method (v1.x) | New Function (v2.0) |
|-------------------|---------------------|
| `client.FindUserByDN(dn)` | `objects.FindUserByDN(client, dn)` |
| `client.FindUserBySAMAccountName(sam)` | `objects.FindUserBySAMAccountName(client, sam)` |
| `client.FindUserByMail(email)` | `objects.FindUserByMail(client, email)` |
| `client.FindUsers()` | `objects.FindUsers(client)` |
| `client.FindGroupByDN(dn)` | `objects.FindGroupByDN(client, dn)` |
| `client.FindGroups()` | `objects.FindGroups(client)` |
| `client.FindComputerByDN(dn)` | `objects.FindComputerByDN(client, dn)` |
| `client.FindComputers()` | `objects.FindComputers(client)` |
| `client.AddUserToGroup(u, g)` | `objects.AddUserToGroup(client, u, g)` |
| `client.RemoveUserFromGroup(u, g)` | `objects.RemoveUserFromGroup(client, u, g)` |
| `client.CreateUser(user, pass)` | `objects.CreateUser(client, user, pass)` |
| `client.DeleteUser(dn)` | `objects.DeleteUser(client, dn)` |

### 4. Update Constructor Calls

| Old Function | New Function |
|--------------|--------------|
| `ldap.NewUserBuilder()` | `search.NewUserBuilder()` |
| `ldap.NewGroupBuilder()` | `search.NewGroupBuilder()` |
| `ldap.NewComputerBuilder()` | `search.NewComputerBuilder()` |
| `ldap.NewConfigBuilder()` | `search.NewConfigBuilder()` |
| `ldap.NewQueryBuilder()` | `search.NewQueryBuilder()` |

## What Doesn't Change

✅ **LDAP Client Methods** - All methods on `ldap.LDAP` work exactly the same:
```go
client, err := ldap.New(config, username, password)
user, err := client.FindUserBySAMAccountName("jdoe")
users, err := client.FindUsers()
// All client methods unchanged!
```

✅ **Configuration** - `ldap.Config` and `ldap.New()` work the same

✅ **Error Types** - `ldap.ErrUserNotFound`, `ldap.ErrGroupNotFound`, etc.

## Example Migration

### Before (v1.1.x)
```go
package main

import (
    "log"
    "github.com/netresearch/simple-ldap-go"
)

func main() {
    config := &ldap.Config{
        Server: "ldaps://ldap.example.com:636",
        BaseDN: "dc=example,dc=com",
    }

    client, err := ldap.New(config, "user", "pass")
    if err != nil {
        log.Fatal(err)
    }

    // Old type reference
    var user *ldap.User
    user, err = client.FindUserBySAMAccountName("jdoe")

    // Old builder
    builder := ldap.NewUserBuilder()
}
```

### After (v2.0.0)
```go
package main

import (
    "log"
    "github.com/netresearch/simple-ldap-go"
    "github.com/netresearch/simple-ldap-go/objects"    // NEW
    "github.com/netresearch/simple-ldap-go/search"     // NEW
)

func main() {
    config := &ldap.Config{  // Unchanged
        Server: "ldaps://ldap.example.com:636",
        BaseDN: "dc=example,dc=com",
    }

    client, err := ldap.New(config, "user", "pass")  // Unchanged
    if err != nil {
        log.Fatal(err)
    }

    // New type reference
    var user *objects.User
    user, err = client.FindUserBySAMAccountName("jdoe")  // Method unchanged

    // New builder
    builder := search.NewUserBuilder()
}
```

## Benefits of New Structure

✅ **Better Organization** - Related functionality grouped together
✅ **Clearer Dependencies** - Explicit package boundaries
✅ **Smaller Imports** - Import only what you need
✅ **Type Safety** - Better separation of concerns
✅ **Easier Navigation** - Find code faster in smaller packages

## Need Help?

If you encounter issues during migration:

1. Check this guide for common patterns
2. Review the updated examples in `examples/`
3. Check the API documentation at pkg.go.dev
4. Open an issue on GitHub if you need assistance