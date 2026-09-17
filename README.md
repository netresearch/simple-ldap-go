# Simple LDAP Go

[![Template Drift](https://github.com/netresearch/simple-ldap-go/actions/workflows/check-template-drift.yml/badge.svg)](https://github.com/netresearch/simple-ldap-go/actions/workflows/check-template-drift.yml)
[![managed by netresearch/.github templates](https://img.shields.io/badge/template-netresearch%2F.github-2F99A4?logo=github)](https://github.com/netresearch/.github/tree/main/templates/go-app)

[![Go Reference](https://pkg.go.dev/badge/github.com/netresearch/simple-ldap-go.svg)](https://pkg.go.dev/github.com/netresearch/simple-ldap-go)
[![CI Status](https://github.com/netresearch/simple-ldap-go/actions/workflows/ci.yml/badge.svg)](https://github.com/netresearch/simple-ldap-go/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/netresearch/simple-ldap-go/graph/badge.svg)](https://codecov.io/gh/netresearch/simple-ldap-go)
[![Go Version](https://img.shields.io/github/go-mod/go-version/netresearch/simple-ldap-go)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Latest Release](https://img.shields.io/github/v/release/netresearch/simple-ldap-go)](https://github.com/netresearch/simple-ldap-go/releases)
[![Renovate enabled](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/netresearch/simple-ldap-go/graphs/commit-activity)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/netresearch/simple-ldap-go/pulls)

A simple Go library providing an easy-to-use wrapper around [go-ldap/ldap/v3](https://github.com/go-ldap/ldap) for common LDAP and Active Directory operations.

This package was extracted from [netresearch/raybeam](https://github.com/netresearch/raybeam) to provide a standalone, reusable LDAP client library.

## Why Use Simple LDAP Go?

Working with [go-ldap/ldap/v3](https://github.com/go-ldap/ldap) directly can be challenging for common LDAP operations. This library solves the pain points you'll encounter:

### Problems with Raw go-ldap

❌ **Complex Connection Management** - Manual connection pooling, health checks, and retry logic
❌ **Manual DN Construction** - Error-prone string building with security risks (DN injection)
❌ **No Caching** - Repeated LDAP queries for the same data slow down applications
❌ **Verbose Error Handling** - Generic LDAP errors without context or specific types
❌ **AD vs OpenLDAP Differences** - Different APIs and attributes require separate code paths
❌ **Security Pitfalls** - Easy to introduce vulnerabilities without proper input validation
❌ **Boilerplate Code** - Simple operations require dozens of lines of setup and teardown

### How Simple LDAP Go Solves These

✅ **Automatic Connection Pooling** - Built-in connection management with health checks and auto-retry
✅ **Safe DN Handling** - Automatic escaping and validation prevents injection attacks
✅ **Built-in Caching** - Intelligent caching layer reduces LDAP server load
✅ **Comprehensive Error Types** - Specific errors like `ErrUserNotFound` with detailed context
✅ **Unified API** - Same methods work seamlessly with Active Directory and OpenLDAP
✅ **Security by Default** - Input validation, proper escaping, and secure connection handling
✅ **Simple API** - Common operations in just a few lines of code

### Code Comparison

**Raw go-ldap**: Finding and authenticating a user (50+ lines)
```go
import "github.com/go-ldap/ldap/v3"

// Connect and bind
conn, err := ldap.DialURL("ldaps://ldap.example.com:636")
if err != nil {
    return err
}
defer conn.Close()

err = conn.Bind("cn=admin,dc=example,dc=com", "password")
if err != nil {
    return err
}

// Search for user (manual filter construction)
searchReq := ldap.NewSearchRequest(
    "dc=example,dc=com",
    ldap.ScopeWholeSubtree,
    ldap.NeverDerefAliases,
    0, 0, false,
    fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))",
        ldap.EscapeFilter(username)), // Manual escaping required
    []string{"dn", "cn", "mail"},
    nil,
)

sr, err := conn.Search(searchReq)
if err != nil {
    return err
}
if len(sr.Entries) == 0 {
    return errors.New("user not found") // Generic error
}

userDN := sr.Entries[0].DN

// Authenticate user (separate bind operation)
err = conn.Bind(userDN, password)
if err != nil {
    return err
}
// ... additional validation and error handling
```

**Simple LDAP Go**: Same operation (3 lines)
```go
import ldap "github.com/netresearch/simple-ldap-go"

client, _ := ldap.New(config, "cn=admin,dc=example,dc=com", "password")
user, err := client.CheckPasswordForSAMAccountName("username", "password")
// Returns structured User object with automatic error handling
```

## Features

- 🔐 **User Authentication** - One-line password verification with automatic DN resolution and secure binding
- 👥 **User Management** - Type-safe user operations with automatic attribute mapping and validation
- 🏢 **Group Operations** - Simplified group queries and membership management across AD and OpenLDAP
- 💻 **Computer Management** - Active Directory computer object support with automatic schema detection
- 🔑 **Password Management** - Secure password changes and admin resets with automatic LDAPS enforcement and policy validation
- 🛡️ **Active Directory Support** - Native AD features like SAMAccountName, UPN, and nested group resolution
- ⚡ **Connection Pooling** - Automatic connection management with health checks, retry logic, and resource cleanup
- 🎯 **Smart Caching** - Configurable caching layer that reduces server load for repeated queries
- 🔒 **Security by Default** - Built-in DN injection protection, input validation, and secure connection handling
- 📊 **Structured Errors** - Context-rich error types that make debugging and error handling straightforward
- 🌐 **Context Support** - Full `context.Context` integration for timeouts, cancellation, and request tracing
- 📝 **Structured Logging** - Integrated slog support for comprehensive operational visibility
- 🔓 **Account State** - Enable, disable and unlock Active Directory accounts; unlocking is separate from password reset, so reset callers need no extra rights
- 🔁 **Streaming Iterators** - `SearchIter`, `SearchPagedIter` and `GroupMembersIter` return `iter.Seq2` so large result sets never have to fit in memory
- 📦 **Bulk Operations** - Worker-pool create, modify and delete that report per-item results instead of failing the whole batch
- ⏳ **Password Expiry** - `PasswordExpiryFor` and `UsersWithExpiringPasswords`, for AD and for ppolicy-configured directories

## Installation

```bash
go get github.com/netresearch/simple-ldap-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
    // Configure LDAP connection
    config := ldap.Config{
        Server:            "ldaps://ldap.example.com:636",
        BaseDN:            "dc=example,dc=com",
        IsActiveDirectory: true, // Set to false for generic LDAP
    }

    // Create client with service account credentials
    client, err := ldap.New(config, "cn=admin,dc=example,dc=com", "password")
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate a user
    user, err := client.CheckPasswordForSAMAccountName("username", "password")
    if err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }
    
    fmt.Printf("Welcome, %s!\n", user.CN())
}
```

## Examples

Comprehensive examples are available in the [examples](examples/) directory:

- **[Basic Usage](examples/basic-usage/)** - Finding users, groups, and computers
- **[Authentication](examples/authentication/)** - User authentication, password changes, and admin resets  
- **[User Management](examples/user-management/)** - Creating, updating, and managing users

## API Reference

### Core Types

- **`Config`** - LDAP server configuration
- **`LDAP`** - Main client for LDAP operations
- **`User`** - Represents an LDAP user with common attributes
- **`Group`** - Represents an LDAP group with member information
- **`Computer`** - Represents a computer object (Active Directory)

### Key Operations

```go
// Client creation. New applies the library defaults; the convenience
// constructors are New with a preset Config.
client, err := ldap.New(config, username, password)
client, err := ldap.NewBasicClient(config, username, password)
client, err := ldap.NewReadOnlyClient(config, username, password)
client, err := ldap.NewHighPerformanceClient(config, username, password)
client, err := ldap.NewCachedClient(config, username, password, 1000, 5*time.Minute)
defer func() { _ = client.Close() }()

// User authentication
user, err := client.CheckPasswordForSAMAccountName("jdoe", "password")

// Find users. Caching, when enabled in the config, is transparent here.
user, err := client.FindUserBySAMAccountName("jdoe")
user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
users, err := client.FindUsers()

// User management. CreateUser takes the new account's password as its second
// argument (the container comes from FullUser) and returns the created DN.
dn, err := client.CreateUser(fullUser, "initialPassword")
err = client.DeleteUser("cn=John Doe,ou=Users,dc=example,dc=com")
err = client.ModifyUser(dn, map[string][]string{"description": {"Updated"}})

// Group operations
group, err := client.FindGroupByDNContext(ctx, "cn=Admins,dc=example,dc=com")
err = client.AddUserToGroup(userDN, groupDN)
err = client.RemoveUserFromGroup(userDN, groupDN)

// Password management
err = client.ChangePasswordForSAMAccountName("jdoe", "oldPass", "newPass") // self-service
err = client.ResetPasswordForSAMAccountName("jdoe", "newPass")             // admin reset

// Account state (Active Directory)
err = client.DisableUser(userDN)
err = client.EnableUser(userDN)
err = client.UnlockUser(userDN)                        // clears lockoutTime
err = client.UnlockUserForSAMAccountName("jdoe")

// Streaming large result sets without materialising them
for entry, err := range client.SearchPagedIter(ctx, searchRequest, 500) {
    if err != nil {
        return err
    }
    _ = entry
}
```

See the [Go Reference](https://pkg.go.dev/github.com/netresearch/simple-ldap-go) for complete API documentation.

## Configuration

### Basic Configuration

#### Generic LDAP Server
```go
config := ldap.Config{
    Server:            "ldap://ldap.example.com:389",
    BaseDN:            "dc=example,dc=com",
    IsActiveDirectory: false,
}
```

#### Microsoft Active Directory
```go
config := ldap.Config{
    Server:            "ldaps://ad.example.com:636", // LDAPS recommended
    BaseDN:            "dc=example,dc=com",
    IsActiveDirectory: true, // Enables AD-specific features
}
```

### Performance Configuration

Enable optimization features using configuration flags:

```go
config := ldap.Config{
    Server:               "ldaps://ad.example.com:636",
    BaseDN:               "dc=example,dc=com",
    IsActiveDirectory:    true,

    // Performance optimizations
    EnableOptimizations:  true, // Enable all optimizations
    EnableCache:         true,  // Enable caching separately
    EnableMetrics:       true,  // Enable performance metrics
    EnableBulkOps:       true,  // Enable bulk operations
}
```

Or configure specific features:

```go
// High-performance client with all optimizations
client, err := ldap.NewHighPerformanceClient(config, username, password)

// Custom configuration with specific features
// Use config flags to enable features:
config.EnableOptimizations = true  // Enable all optimizations
config.EnableCache = true         // Enable caching
config.EnableMetrics = true       // Enable metrics
config.EnableBulkOps = true       // Enable bulk operations

// Then create client with convenience constructors:
client, err := ldap.NewHighPerformanceClient(config, username, password)
// Or:
client, err := ldap.NewCachedClient(config, username, password, 1000, 5*time.Minute)
// Or:
client, err := ldap.NewPooledClient(config, username, password, 20)
```

## Security Best Practices

- ✅ **Use LDAPS** (TLS encryption) in production environments
- ✅ **Use service accounts** with minimal required permissions
- ✅ **Store credentials securely** using environment variables or key management
- ✅ **Validate certificates** in production deployments
- ⚠️ **Password changes require LDAPS** when using Active Directory

## Error Handling

The library provides specific error types for common scenarios:

```go
// Check for specific errors
_, err := client.FindUserBySAMAccountName("username")
if err == ldap.ErrUserNotFound {
    // Handle user not found
} else if err != nil {
    // Handle other errors
}
```

Available error types:
- `ErrUserNotFound` - User lookup failed
- `ErrGroupNotFound` - Group lookup failed
- `ErrComputerNotFound` - Computer lookup failed
- `ErrSAMAccountNameDuplicated` - Account name already exists
- `ErrMailDuplicated` - Email address already exists
- `ErrActiveDirectoryMustBeLDAPS` - LDAPS required for AD operations

## Requirements

- Go 1.26.0 or later. Every release is built and unit-tested on Go 1.26 and 1.27 (`make test-compat`, and the `go-compat` matrix in CI); the `go` directive in `go.mod` is the binding minimum.
- Access to an LDAP server (OpenLDAP, Active Directory, etc.)
- Appropriate credentials and permissions for desired operations

## Testing

Tests require a live LDAP server. Set the following environment variables:

```bash
export LDAP_SERVER="ldaps://your-server:636"
export LDAP_BASE_DN="dc=example,dc=com" 
export LDAP_READ_USER="cn=service,dc=example,dc=com"
export LDAP_READ_PASSWORD="password"
```

Then run tests:
```bash
go test -v ./...
```

## License

This package is licensed under the MIT License. See the included [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit messages
4. Use `gofmt` for code formatting
5. Add tests for new functionality
6. Submit a pull request

## Related Projects

- [go-ldap/ldap](https://github.com/go-ldap/ldap) - The underlying LDAP library
- [netresearch/raybeam](https://github.com/netresearch/raybeam) - Original project this was extracted from
