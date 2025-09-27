// Package main demonstrates basic LDAP operations using simple-ldap-go
package main

import (
	"fmt"
	"log"

	ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
	// Basic LDAP configuration
	config := ldap.Config{
		Server:            "ldaps://ldap.example.com:636",
		BaseDN:            "dc=example,dc=com",
		IsActiveDirectory: true, // Set to false for generic LDAP servers
	}

	// Create LDAP client with read-only credentials
	client, err := ldap.New(config, "cn=admin,dc=example,dc=com", "password")
	if err != nil {
		log.Fatalf("Failed to create LDAP client: %v", err)
	}

	// Example 1: Find a user by SAM account name
	fmt.Println("=== Finding User by SAM Account Name ===")
	user, err := client.FindUserBySAMAccountName("jdoe")
	if err != nil {
		if err == ldap.ErrUserNotFound {
			fmt.Println("User 'jdoe' not found")
		} else {
			log.Printf("Error finding user: %v", err)
		}
	} else {
		fmt.Printf("Found user: %s (%s)\n", user.CN(), user.SAMAccountName)
		if user.Mail != nil {
			fmt.Printf("Email: %s\n", *user.Mail)
		} else {
			fmt.Printf("Email: (not set)\n")
		}
		fmt.Printf("DN: %s\n", user.DN())
	}

	// Example 2: List all users
	fmt.Println("\n=== Listing All Users ===")
	users, err := client.FindUsers()
	if err != nil {
		log.Printf("Error listing users: %v", err)
	} else {
		fmt.Printf("Found %d users:\n", len(users))
		for _, u := range users {
			fmt.Printf("  - %s (%s)\n", u.CN(), u.SAMAccountName)
		}
	}

	// Example 3: Find a group
	fmt.Println("\n=== Finding Group ===")
	group, err := client.FindGroupByDN("cn=Administrators,cn=Builtin,dc=example,dc=com")
	if err != nil {
		if err == ldap.ErrGroupNotFound {
			fmt.Println("Administrators group not found")
		} else {
			log.Printf("Error finding group: %v", err)
		}
	} else {
		fmt.Printf("Found group: %s\n", group.CN())
		fmt.Printf("Members: %d\n", len(group.Members))
	}

	// Example 4: List computers (Active Directory)
	if config.IsActiveDirectory {
		fmt.Println("\n=== Listing Computers ===")
		computers, err := client.FindComputers()
		if err != nil {
			log.Printf("Error listing computers: %v", err)
		} else {
			fmt.Printf("Found %d computers:\n", len(computers))
			for _, c := range computers {
				fmt.Printf("  - %s (%s)\n", c.CN(), c.SAMAccountName)
			}
		}
	}
}
