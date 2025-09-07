# Simple LDAP Go Examples

This directory contains practical examples demonstrating how to use the simple-ldap-go library for common LDAP and Active Directory operations.

## Prerequisites

Before running these examples, you need:

1. **Go 1.23.0 or later**
2. **Access to an LDAP server** (generic LDAP or Active Directory)
3. **Appropriate credentials** with necessary permissions for the operations you want to perform

## Environment Setup

For testing purposes, you can set up environment variables (as used in the library's tests):

```bash
export LDAP_SERVER="ldaps://your-ldap-server.example.com:636"
export LDAP_BASE_DN="dc=example,dc=com"
export LDAP_READ_USER="cn=service-account,ou=Service Accounts,dc=example,dc=com"
export LDAP_READ_PASSWORD="your-service-account-password"
```

## Examples Overview

### 1. [basic-usage/](basic-usage/)
Demonstrates fundamental LDAP operations:
- Creating an LDAP client
- Finding users by different methods (SAM account name, email, DN)
- Listing all users
- Finding groups
- Listing computers (Active Directory only)

**Required Permissions**: Read access to user, group, and computer objects

**Run with**:
```bash
go run examples/basic-usage/basic_usage.go
```

### 2. [authentication/](authentication/)
Shows user authentication scenarios:
- Authenticating users by SAM account name
- Authenticating users by Distinguished Name
- Changing user passwords
- Using different client credentials

**Required Permissions**: 
- Read access to user objects
- Password reset permissions for password changes
- LDAPS connection required for Active Directory password operations

**Run with**:
```bash
go run examples/authentication/authentication.go
```

### 3. [user-management/](user-management/)
Covers comprehensive user management operations:
- Creating new users with full attribute sets
- Finding users by various methods
- Managing group memberships
- User deletion (with safety warnings)

**Required Permissions**: 
- Administrative privileges in LDAP/AD
- User creation/deletion permissions
- Group membership modification permissions

**Run with**:
```bash
go run examples/user-management/user_management.go
```

## Configuration Notes

### Generic LDAP Servers
```go
config := ldap.Config{
    Server:            "ldap://ldap.example.com:389",  // or ldaps://... for TLS
    BaseDN:            "dc=example,dc=com",
    IsActiveDirectory: false,  // Important: set to false for non-AD servers
}
```

### Microsoft Active Directory
```go
config := ldap.Config{
    Server:            "ldaps://ad.example.com:636",   // LDAPS recommended for AD
    BaseDN:            "dc=example,dc=com",
    IsActiveDirectory: true,   // Enables AD-specific features
}
```

## Security Considerations

1. **Always use LDAPS (port 636) in production** environments
2. **Use service accounts** with minimal required permissions
3. **Store credentials securely** (environment variables, key management systems)
4. **Never hardcode passwords** in your source code
5. **For Active Directory password operations**, LDAPS is mandatory
6. **Test thoroughly** in development environments before production deployment

## Error Handling

The examples demonstrate proper error handling for common scenarios:

- `ldap.ErrUserNotFound` - User lookup failed
- `ldap.ErrGroupNotFound` - Group lookup failed  
- `ldap.ErrSAMAccountNameDuplicated` - Account name already exists
- `ldap.ErrMailDuplicated` - Email address already exists
- `ldap.ErrActiveDirectoryMustBeLDAPS` - LDAPS required for AD password operations

Always check for these specific errors to provide appropriate user feedback and application behavior.

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Verify server address and port
   - Check firewall settings
   - Ensure LDAP service is running

2. **Authentication Failures**
   - Verify credentials format (DN vs username)
   - Check account permissions and status
   - For AD, ensure account is not disabled

3. **Permission Denied**
   - Verify service account has necessary privileges
   - Check LDAP/AD security groups and permissions
   - For user creation/deletion, administrative rights required

4. **Certificate Errors (LDAPS)**
   - Verify SSL/TLS certificate validity
   - Check certificate trust chain
   - Consider certificate validation options in production

### Getting Help

- Review the main [README.md](../README.md) for general library information
- Check the [GoDoc documentation](https://pkg.go.dev/github.com/netresearch/simple-ldap-go)
- Examine the library's test files for additional usage patterns
- Consult Microsoft documentation for Active Directory specific operations

## License

These examples are provided under the same MIT license as the simple-ldap-go library.