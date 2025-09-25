# Simple LDAP Go

[![Go Reference](https://pkg.go.dev/badge/github.com/netresearch/simple-ldap-go.svg)](https://pkg.go.dev/github.com/netresearch/simple-ldap-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/netresearch/simple-ldap-go)](https://goreportcard.com/report/github.com/netresearch/simple-ldap-go)

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
- 🔑 **Password Management** - Secure password changes with automatic LDAPS enforcement and policy validation
- 🛡️ **Active Directory Support** - Native AD features like SAMAccountName, UPN, and nested group resolution
- ⚡ **Connection Pooling** - Automatic connection management with health checks, retry logic, and resource cleanup
- 🎯 **Smart Caching** - Configurable caching layer that reduces server load for repeated queries
- 🔒 **Security by Default** - Built-in DN injection protection, input validation, and secure connection handling
- 📊 **Structured Errors** - Context-rich error types that make debugging and error handling straightforward
- 🌐 **Context Support** - Full `context.Context` integration for timeouts, cancellation, and request tracing
- 📝 **Structured Logging** - Integrated slog support for comprehensive operational visibility

## Installation

```bash
go get github.com/netresearch/simple-ldap-go
```

## Package Structure

Simple LDAP Go is organized into focused packages:

- **Main package (`github.com/netresearch/simple-ldap-go`)** - Core client and configuration
- **`auth/`** - Authentication operations and password management
- **`objects/`** - LDAP object types (User, Group, Computer)
- **`search/`** - Search builders and query construction
- **`internal/`** - Internal implementation details (not for public use)

The main package provides the core functionality, while specialized packages offer domain-specific operations.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/netresearch/simple-ldap-go"
)

func main() {
    // Configure LDAP connection
    config := &ldap.Config{
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
- **[Authentication](examples/authentication/)** - User authentication and password changes  
- **[User Management](examples/user-management/)** - Creating, updating, and managing users

## API Reference

### Core Types

- **`ldap.Config`** - LDAP server configuration
- **`ldap.LDAP`** - Main client for LDAP operations
- **`objects.User`** - Represents an LDAP user with common attributes
- **`objects.Group`** - Represents an LDAP group with member information
- **`objects.Computer`** - Represents a computer object (Active Directory)

### Key Operations

```go
import (
    "github.com/netresearch/simple-ldap-go"
    "github.com/netresearch/simple-ldap-go/objects"
)

// Client creation
config := &ldap.Config{...}
client, err := ldap.New(config, username, password)

// User authentication
user, err := client.CheckPasswordForSAMAccountName("jdoe", "password")

// Find users
user, err := client.FindUserBySAMAccountName("jdoe")
users, err := client.FindUsers()

// User management
err := client.CreateUser(fullUser, "ou=Users,dc=example,dc=com")
err := client.DeleteUser("cn=John Doe,ou=Users,dc=example,dc=com")

// Group operations
group, err := client.FindGroupByDN("cn=Admins,dc=example,dc=com")
err := client.AddUserToGroup(userDN, groupDN)
```

See the [Go Reference](https://pkg.go.dev/github.com/netresearch/simple-ldap-go) for complete API documentation.

## Configuration

### Generic LDAP Server
```go
config := ldap.Config{
    Server:            "ldap://ldap.example.com:389",
    BaseDN:            "dc=example,dc=com",
    IsActiveDirectory: false,
}
```

### Microsoft Active Directory
```go
config := ldap.Config{
    Server:            "ldaps://ad.example.com:636", // LDAPS recommended
    BaseDN:            "dc=example,dc=com", 
    IsActiveDirectory: true, // Enables AD-specific features
}
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

- Go 1.23.0 or later
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
