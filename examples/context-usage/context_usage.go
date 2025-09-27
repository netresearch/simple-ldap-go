package main

import (
	"context"
	"fmt"
	"log"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
	// Example configuration - update with your LDAP server details
	config := ldap.Config{
		Server:            "ldap://localhost:389", // or "ldaps://ad.company.com:636"
		BaseDN:            "DC=example,DC=com",    // Your domain base DN
		IsActiveDirectory: false,                  // Set to true for Active Directory
	}

	// Admin credentials for connecting to LDAP server
	adminDN := "CN=admin,DC=example,DC=com"
	adminPassword := "admin-password"

	// Create LDAP client
	client, err := ldap.New(config, adminDN, adminPassword)
	if err != nil {
		log.Fatalf("Failed to create LDAP client: %v", err)
	}

	fmt.Println("=== Context-Aware LDAP Operations Example ===\\n")

	// Example 1: Using context with timeout for operations
	fmt.Println("1. Finding user with 30 second timeout...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	user, err := client.FindUserBySAMAccountNameContext(ctx, "testuser")
	if err != nil {
		fmt.Printf("   Error finding user: %v\\n", err)
	} else {
		fmt.Printf("   Found user: %s (DN: %s)\\n", user.SAMAccountName, user.DN())
	}

	// Example 2: Authentication with context timeout
	fmt.Println("\\n2. Authenticating user with timeout...")
	authCtx, authCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer authCancel()

	authenticatedUser, err := client.CheckPasswordForSAMAccountNameContext(authCtx, "testuser", "password")
	if err != nil {
		fmt.Printf("   Authentication failed: %v\\n", err)
	} else {
		fmt.Printf("   Authentication successful for: %s\\n", authenticatedUser.SAMAccountName)
	}

	// Example 3: Bulk operations with context cancellation capability
	fmt.Println("\\n3. Searching all users with cancellable context...")
	searchCtx, searchCancel := context.WithCancel(context.Background())
	defer searchCancel()

	// Start search in a goroutine to demonstrate cancellation
	resultChan := make(chan []ldap.User, 1)
	errorChan := make(chan error, 1)

	go func() {
		users, err := client.FindUsersContext(searchCtx)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- users
		}
	}()

	// Simulate cancelling the operation after 5 seconds
	time.Sleep(5 * time.Second)
	searchCancel()

	select {
	case users := <-resultChan:
		fmt.Printf("   Found %d users\\n", len(users))
		for i, u := range users {
			if i >= 5 { // Show only first 5 users
				fmt.Printf("   ... and %d more users\\n", len(users)-5)
				break
			}
			fmt.Printf("   - %s (%s)\\n", u.SAMAccountName, u.CN())
		}
	case err := <-errorChan:
		if err == context.Canceled {
			fmt.Printf("   Search was cancelled after 5 seconds\\n")
		} else {
			fmt.Printf("   Search failed: %v\\n", err)
		}
	}

	// Example 4: Group operations with context
	fmt.Println("\\n4. Finding groups with context...")
	groupCtx, groupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer groupCancel()

	groups, err := client.FindGroupsContext(groupCtx)
	if err != nil {
		fmt.Printf("   Error finding groups: %v\\n", err)
	} else {
		fmt.Printf("   Found %d groups\\n", len(groups))
		for i, g := range groups {
			if i >= 3 { // Show only first 3 groups
				fmt.Printf("   ... and %d more groups\\n", len(groups)-3)
				break
			}
			fmt.Printf("   - %s (%d members)\\n", g.CN(), len(g.Members))
		}
	}

	// Example 5: Computer operations with context
	fmt.Println("\\n5. Finding computers with context...")
	computerCtx, computerCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer computerCancel()

	computers, err := client.FindComputersContext(computerCtx)
	if err != nil {
		fmt.Printf("   Error finding computers: %v\\n", err)
	} else {
		fmt.Printf("   Found %d computers\\n", len(computers))
		for i, c := range computers {
			if i >= 3 { // Show only first 3 computers
				fmt.Printf("   ... and %d more computers\\n", len(computers)-3)
				break
			}
			fmt.Printf("   - %s (OS: %s, Enabled: %t)\\n", c.SAMAccountName, c.OS, c.Enabled)
		}
	}

	// Example 6: Connection management with context
	fmt.Println("\\n6. Direct connection management with context...")
	connCtx, connCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer connCancel()

	conn, err := client.GetConnectionContext(connCtx)
	if err != nil {
		fmt.Printf("   Failed to get connection: %v\\n", err)
	} else {
		fmt.Printf("   Successfully established connection\\n")
		defer func() {
			_ = conn.Close()
		}()

		// Use the connection for custom operations if needed
		// This demonstrates that context is properly propagated to the connection level
	}

	// Example 7: Handling context cancellation gracefully
	fmt.Println("\\n7. Demonstrating graceful context cancellation...")
	cancelCtx, immediateCancel := context.WithCancel(context.Background())
	immediateCancel() // Cancel immediately

	_, err = client.FindUserBySAMAccountNameContext(cancelCtx, "testuser")
	if err == context.Canceled {
		fmt.Printf("   Operation was cancelled as expected\\n")
	} else {
		fmt.Printf("   Unexpected error: %v\\n", err)
	}

	// Example 8: Demonstrating timeout handling
	fmt.Println("\\n8. Demonstrating timeout handling...")
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer timeoutCancel()

	// Sleep to ensure timeout occurs
	time.Sleep(1 * time.Millisecond)

	_, err = client.GetConnectionContext(timeoutCtx)
	if err == context.DeadlineExceeded {
		fmt.Printf("   Operation timed out as expected\\n")
	} else {
		fmt.Printf("   Unexpected error: %v\\n", err)
	}

	fmt.Println("\\n=== Backward Compatibility ===\\n")

	// Example 9: Show that original methods still work
	fmt.Println("9. Using original methods (backward compatibility)...")
	fmt.Printf("   Original methods work unchanged:\\n")
	fmt.Printf("   - client.FindUserBySAMAccountName()\\n")
	fmt.Printf("   - client.CheckPasswordForSAMAccountName()\\n")
	fmt.Printf("   - client.FindUsers()\\n")
	fmt.Printf("   - client.FindGroups()\\n")
	fmt.Printf("   - client.FindComputers()\\n")
	fmt.Printf("   - client.GetConnection()\\n")
	fmt.Printf("   All original methods now use context.Background() internally\\n")

	fmt.Println("\\n=== Usage Recommendations ===\\n")
	fmt.Printf("• Use context-aware methods (*Context) for new development\\n")
	fmt.Printf("• Set reasonable timeouts (10-60 seconds for most operations)\\n")
	fmt.Printf("• Use cancellation for long-running operations that users might cancel\\n")
	fmt.Printf("• Original methods remain available for backward compatibility\\n")
	fmt.Printf("• Context is checked at multiple points during LDAP operations\\n")
}
