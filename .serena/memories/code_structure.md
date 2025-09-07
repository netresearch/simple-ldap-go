# Simple LDAP Go - Code Structure

## File Organization
The project follows a flat structure with domain-specific Go files:

### Core Files
- **client.go**: Main LDAP client implementation with Config and LDAP structs
- **auth.go**: Authentication methods including password checking and changing
- **users.go**: User management operations (find, create, delete, group membership)
- **groups.go**: Group management operations
- **computers.go**: Computer object management
- **object.go**: Common object operations and utilities
- **utils.go**: Utility functions for parsing and conversion
- **uac.go**: User Account Control constants and utilities
- **sam_account_type.go**: SAM Account Type constants

### Configuration Files
- **go.mod/go.sum**: Go module dependencies
- **renovate.json**: Dependency update automation
- **README.md**: Project documentation

### Testing
- **auth_test.go**: Authentication tests (requires LDAP server environment variables)
- **.github/workflows/test.yml.disabled**: CI configuration (disabled due to LDAP server requirement)

## Package Structure
All code is in the `ldap` package, providing a cohesive API surface.