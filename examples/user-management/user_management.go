// Package main demonstrates user management operations using simple-ldap-go
package main

import (
	"fmt"
	"log"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
	// LDAP configuration with administrative privileges required
	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true,
	}

	// Create LDAP client with administrative credentials
	// Note: User creation/deletion requires elevated privileges
	client, err := ldap.New(config, "cn=administrator,cn=Users,dc=example,dc=com", "adminPassword")
	if err != nil {
		log.Fatalf("Failed to create LDAP client: %v", err)
	}

	// Example 1: Create a new user
	fmt.Println("=== Creating New User ===")
	createUser(client)

	// Example 2: Find users by different methods
	fmt.Println("\n=== Finding Users ===")
	findUsers(client)

	// Example 3: Group membership management
	fmt.Println("\n=== Group Membership Management ===")
	manageGroupMembership(client)

	// Example 4: Delete a user (be careful!)
	fmt.Println("\n=== User Deletion ===")
	deleteUser(client)
}

func createUser(client *ldap.LDAP) {
	// Prepare user data for creation
	samAccountName := "testuser123"
	displayName := "Test User (123)"
	description := "Test user created by example program"
	email := "testuser123@example.com"

	newUser := ldap.FullUser{
		// Required fields
		CN:        "Test User 123",
		FirstName: "Test",
		LastName:  "User",

		// Optional fields
		SAMAccountName: &samAccountName,
		DisplayName:    &displayName,
		Description:    &description,
		Email:          &email,
	}

	userDN, err := client.CreateUser(newUser, "TempPassword123!")
	if err != nil {
		switch err {
		case ldap.ErrSAMAccountNameDuplicated:
			fmt.Printf("User with SAM account name '%s' already exists\n", *newUser.SAMAccountName)
		case ldap.ErrMailDuplicated:
			fmt.Printf("User with email '%s' already exists\n", *newUser.Email)
		default:
			fmt.Printf("Failed to create user: %v\n", err)
		}
		return
	}

	fmt.Printf("✓ User '%s' created successfully\n", newUser.CN)
	fmt.Printf("  DN: %s\n", userDN)
	fmt.Printf("  SAM Account: %s\n", *newUser.SAMAccountName)
	fmt.Printf("  Email: %s\n", *newUser.Email)
}

func findUsers(client *ldap.LDAP) {
	// Find user by SAM account name
	fmt.Println("Finding user by SAM account name...")
	user, err := client.FindUserBySAMAccountName("testuser123")
	if err != nil {
		if err == ldap.ErrUserNotFound {
			fmt.Println("  User not found")
		} else {
			fmt.Printf("  Error: %v\n", err)
		}
	} else {
		fmt.Printf("  ✓ Found: %s (%s)\n", user.CN(), user.SAMAccountName)
		fmt.Printf("    Enabled: %t\n", user.Enabled)
		if user.Mail != nil {
			fmt.Printf("    Email: %s\n", *user.Mail)
		} else {
			fmt.Printf("    Email: (not set)\n")
		}
		fmt.Printf("    Groups: %d\n", len(user.Groups))
	}

	// Find user by email
	fmt.Println("Finding user by email...")
	user, err = client.FindUserByMail("testuser123@example.com")
	if err != nil {
		if err == ldap.ErrUserNotFound {
			fmt.Println("  User not found")
		} else {
			fmt.Printf("  Error: %v\n", err)
		}
	} else {
		fmt.Printf("  ✓ Found: %s\n", user.CN())
	}

	// Find user by DN
	fmt.Println("Finding user by DN...")
	userDN := "cn=Test User 123,ou=Test Users,dc=example,dc=com"
	user, err = client.FindUserByDN(userDN)
	if err != nil {
		if err == ldap.ErrUserNotFound {
			fmt.Println("  User not found")
		} else {
			fmt.Printf("  Error: %v\n", err)
		}
	} else {
		fmt.Printf("  ✓ Found: %s\n", user.CN())
	}
}

func manageGroupMembership(client *ldap.LDAP) {
	userDN := "cn=Test User 123,ou=Test Users,dc=example,dc=com"
	groupDN := "cn=Test Group,ou=Groups,dc=example,dc=com"

	// Add user to group
	fmt.Printf("Adding user to group...\n")
	err := client.AddUserToGroup(userDN, groupDN)
	if err != nil {
		fmt.Printf("  Failed to add user to group: %v\n", err)
	} else {
		fmt.Printf("  ✓ User added to group successfully\n")
	}

	// Remove user from group
	fmt.Printf("Removing user from group...\n")
	err = client.RemoveUserFromGroup(userDN, groupDN)
	if err != nil {
		fmt.Printf("  Failed to remove user from group: %v\n", err)
	} else {
		fmt.Printf("  ✓ User removed from group successfully\n")
	}
}

func deleteUser(client *ldap.LDAP) {
	userDN := "cn=Test User 123,ou=Test Users,dc=example,dc=com"

	fmt.Printf("⚠️  WARNING: About to delete user with DN: %s\n", userDN)
	fmt.Printf("This operation is irreversible!\n")

	// In a real application, you would want confirmation here
	// For example purposes, we'll comment out the actual deletion
	/*
		err := client.DeleteUser(userDN)
		if err != nil {
			if err == ldap.ErrUserNotFound {
				fmt.Println("User not found (already deleted?)")
			} else {
				fmt.Printf("Failed to delete user: %v\n", err)
			}
			return
		}

		fmt.Printf("✓ User deleted successfully\n")
	*/

	fmt.Printf("User deletion skipped for safety (uncomment in code to enable)\n")
}

func formatTime(t *time.Time) string {
	if t == nil {
		return "Never"
	}
	return t.Format("2006-01-02 15:04:05")
}
