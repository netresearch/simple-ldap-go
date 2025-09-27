// Package ldap provides a simple wrapper around go-ldap/ldap for common
// LDAP and Active Directory operations.
//
// This package simplifies common LDAP operations including:
//   - User authentication and password management
//   - User, group, and computer object queries
//   - User creation and deletion
//   - Group membership management
//
// The package is designed to work with both generic LDAP servers and
// Microsoft Active Directory, with special handling for AD-specific
// features like password changes and user account control flags.
//
// # Basic Usage
//
//	config := ldap.Config{
//		Server:            "ldaps://ldap.example.com:636",
//		BaseDN:            "dc=example,dc=com",
//		IsActiveDirectory: true,
//	}
//
//	client, err := ldap.New(config, "cn=admin,dc=example,dc=com", "password")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Authenticate a user
//	user, err := client.CheckPasswordForSAMAccountName("username", "password")
//	if err != nil {
//		log.Printf("Authentication failed: %v", err)
//		return
//	}
//	fmt.Printf("Authenticated user: %s\n", user.CN())
//
//	// Find users
//	users, err := client.FindUsers()
//	if err != nil {
//		log.Printf("Failed to find users: %v", err)
//		return
//	}
//	for _, u := range users {
//		fmt.Printf("User: %s (%s)\n", u.CN(), u.SAMAccountName)
//	}
//
// # Active Directory Considerations
//
// When working with Active Directory, set IsActiveDirectory to true in the
// Config. This enables AD-specific features:
//   - Password changes require LDAPS connection
//   - Proper handling of User Account Control flags
//   - Support for AD-specific attributes
//
// # Error Handling
//
// The package defines specific error variables for common scenarios:
//   - ErrUserNotFound: User lookup failed
//   - ErrGroupNotFound: Group lookup failed
//   - ErrComputerNotFound: Computer lookup failed
//   - ErrDNDuplicated: Distinguished name is not unique
//   - ErrSAMAccountNameDuplicated: SAM account name already exists
//   - ErrMailDuplicated: Email address already exists
//   - ErrActiveDirectoryMustBeLDAPS: LDAPS required for AD password operations
//
// Always check for these specific errors when appropriate to provide
// better error handling in your applications.
package ldap
