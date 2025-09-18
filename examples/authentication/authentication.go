// Package main demonstrates authentication operations using simple-ldap-go
package main

import (
	"fmt"
	"log"

	ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
	// LDAP configuration for authentication
	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}

	// Create LDAP client with service account credentials
	client, err := ldap.New(&config, "cn=service-account,ou=Service Accounts,dc=example,dc=com", "servicePassword")
	if err != nil {
		log.Fatalf("Failed to create LDAP client: %v", err)
	}

	// Example 1: Authenticate user with SAM account name
	fmt.Println("=== User Authentication by SAM Account Name ===")
	authenticateUserBySAM(client, "jdoe", "userPassword123")

	// Example 2: Authenticate user with Distinguished Name
	fmt.Println("\n=== User Authentication by Distinguished Name ===")
	authenticateUserByDN(client, "cn=Jane Doe,ou=Users,dc=example,dc=com", "userPassword123")

	// Example 3: Change user password (requires LDAPS for Active Directory)
	fmt.Println("\n=== Password Change ===")
	changeUserPassword(client, "jdoe", "newPassword456")

	// Example 4: Using different credentials
	fmt.Println("\n=== Using Different Credentials ===")
	usesDifferentCredentials(client)
}

func authenticateUserBySAM(client *ldap.LDAP, samAccountName, password string) {
	user, err := client.CheckPasswordForSAMAccountName(samAccountName, password)
	if err != nil {
		switch err {
		case ldap.ErrUserNotFound:
			fmt.Printf("User '%s' not found\n", samAccountName)
		default:
			// This could be invalid password, account disabled, etc.
			fmt.Printf("Authentication failed for '%s': %v\n", samAccountName, err)
		}
		return
	}

	fmt.Printf("✓ Authentication successful for %s\n", user.CN())
	fmt.Printf("  SAM Account: %s\n", user.SAMAccountName)
	if user.Mail != nil {
		fmt.Printf("  Email: %s\n", *user.Mail)
	} else {
		fmt.Printf("  Email: (not set)\n")
	}
	fmt.Printf("  Account Enabled: %t\n", user.Enabled)
}

func authenticateUserByDN(client *ldap.LDAP, userDN, password string) {
	user, err := client.CheckPasswordForDN(userDN, password)
	if err != nil {
		fmt.Printf("Authentication failed for DN '%s': %v\n", userDN, err)
		return
	}

	fmt.Printf("✓ Authentication successful for %s\n", user.CN())
	fmt.Printf("  DN: %s\n", user.DN())
}

func changeUserPassword(client *ldap.LDAP, samAccountName, newPassword string) {
	// For this example, we'll use a placeholder old password
	// In reality, you'd need the user's current password
	oldPassword := "currentPassword123"
	err := client.ChangePasswordForSAMAccountName(samAccountName, oldPassword, newPassword)
	if err != nil {
		switch err {
		case ldap.ErrUserNotFound:
			fmt.Printf("User '%s' not found\n", samAccountName)
		case ldap.ErrActiveDirectoryMustBeLDAPS:
			fmt.Printf("Password change requires LDAPS connection for Active Directory\n")
		default:
			fmt.Printf("Password change failed for '%s': %v\n", samAccountName, err)
		}
		return
	}

	fmt.Printf("✓ Password changed successfully for '%s'\n", samAccountName)
}

func usesDifferentCredentials(client *ldap.LDAP) {
	// Create a new client with different user credentials
	// This is useful when you need to perform operations as a specific user
	userClient, err := client.WithCredentials("cn=John Doe,ou=Users,dc=example,dc=com", "johnPassword")
	if err != nil {
		fmt.Printf("Failed to create client with user credentials: %v\n", err)
		return
	}

	// Now perform operations as John Doe
	// Note: This client will have John's permissions, not the service account's
	users, err := userClient.FindUsers()
	if err != nil {
		fmt.Printf("Failed to list users with John's credentials: %v\n", err)
		return
	}

	fmt.Printf("✓ Successfully performed operation as user, found %d users\n", len(users))
}
