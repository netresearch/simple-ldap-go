# Simple LDAP Go

[![Go Reference](https://pkg.go.dev/badge/github.com/netresearch/simple-ldap-go.svg)](https://pkg.go.dev/github.com/netresearch/simple-ldap-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/netresearch/simple-ldap-go)](https://goreportcard.com/report/github.com/netresearch/simple-ldap-go)

A simple Go library providing an easy-to-use wrapper around [go-ldap/ldap/v3](https://github.com/go-ldap/ldap) for common LDAP and Active Directory operations.

This package was extracted from [netresearch/raybeam](https://github.com/netresearch/raybeam) to provide a standalone, reusable LDAP client library.

## Features

- 🔐 **User Authentication** - Password verification for LDAP users
- 👥 **User Management** - Create, find, update, and delete users
- 🏢 **Group Operations** - Query groups and manage memberships  
- 💻 **Computer Management** - Find and manage computer objects (Active Directory)
- 🔑 **Password Management** - Change user passwords (LDAPS required for AD)
- 🛡️ **Active Directory Support** - Special handling for AD-specific features
- ⚡ **Simple API** - Easy-to-use interface with comprehensive error handling

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
- **[Authentication](examples/authentication/)** - User authentication and password changes  
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
// Client creation
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
