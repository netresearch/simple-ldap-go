package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
	enhancedErrorsDemo()
}

// Example demonstrating the enhanced error handling features
func enhancedErrorsDemo() {
	fmt.Println("=== Enhanced Error Handling Examples ===")
	demonstrateEnhancedErrorHandling()
}

func demonstrateEnhancedErrorHandling() {
	// Create a structured logger for better error visibility
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Configure LDAP client with enhanced error handling
	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
		Logger:            logger,
	}

	// This example shows error handling without a real LDAP server
	// In practice, you'd use actual LDAP credentials
	client, err := ldap.New(config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		demonstrateErrorAnalysis("LDAP Client Creation", err)
		return
	}
	defer client.Close()

	// Example 1: Authentication with Enhanced Error Handling
	fmt.Println("=== Example 1: Authentication Error Handling ===")
	demonstrateAuthenticationErrors(client)

	// Example 2: User Search with Enhanced Error Handling  
	fmt.Println("\n=== Example 2: User Search Error Handling ===")
	demonstrateUserSearchErrors(client)

	// Example 3: Connection Error Handling
	fmt.Println("\n=== Example 3: Connection Error Handling ===")
	demonstrateConnectionErrors(client)

	// Example 4: Context-based Error Handling
	fmt.Println("\n=== Example 4: Context-based Error Handling ===")
	demonstrateContextErrors(client)
}

func demonstrateAuthenticationErrors(client *ldap.LDAP) {
	// Simulate authentication attempts
	testUsers := []struct {
		username string
		password string
		scenario string
	}{
		{"validuser", "wrongpassword", "invalid password"},
		{"nonexistent", "password", "user not found"},
		{"disableduser", "password", "account disabled"},
	}

	for _, test := range testUsers {
		fmt.Printf("\nTesting %s scenario:\n", test.scenario)
		
		user, err := client.CheckPasswordForSAMAccountName(test.username, test.password)
		if err != nil {
			// Demonstrate enhanced error analysis
			demonstrateErrorAnalysis("Authentication", err)
			
			// Show how to handle different error types
			handleAuthenticationError(test.username, err)
		} else {
			fmt.Printf("✅ Authentication successful for user: %s\n", user.SAMAccountName)
		}
	}
}

func demonstrateUserSearchErrors(client *ldap.LDAP) {
	// Simulate user search scenarios
	testUsernames := []string{"validuser", "nonexistent", ""}

	for _, username := range testUsernames {
		fmt.Printf("\nSearching for user: %q\n", username)
		
		user, err := client.FindUserBySAMAccountName(username)
		if err != nil {
			demonstrateErrorAnalysis("User Search", err)
			handleUserSearchError(username, err)
		} else {
			fmt.Printf("✅ User found: %s (DN: %s)\n", user.SAMAccountName, user.DN())
		}
	}
}

func demonstrateConnectionErrors(client *ldap.LDAP) {
	// Create a client with an invalid server to demonstrate connection errors
	invalidConfig := ldap.Config{
		Server: "ldaps://nonexistent.server.com:636",
		BaseDN: "DC=example,DC=com",
	}

	fmt.Println("\nTesting connection to invalid server:")
	invalidClient, err := ldap.New(invalidConfig, "user", "password")
	if err != nil {
		demonstrateErrorAnalysis("Connection", err)
		handleConnectionError(err)
	}
	if invalidClient != nil {
		invalidClient.Close()
	}
}

func demonstrateContextErrors(client *ldap.LDAP) {
	// Demonstrate context timeout handling
	fmt.Println("\nTesting context timeout:")
	
	// Create a very short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	
	// This will likely timeout due to the very short duration
	user, err := client.FindUserBySAMAccountNameContext(ctx, "someuser")
	if err != nil {
		demonstrateErrorAnalysis("Context Operation", err)
		handleContextError(err)
	} else if user != nil {
		fmt.Printf("✅ Unexpected success: %s\n", user.SAMAccountName)
	}
}

func demonstrateErrorAnalysis(operation string, err error) {
	fmt.Printf("📊 Error Analysis for %s:\n", operation)
	
	// Basic error information
	fmt.Printf("   Error: %s\n", err.Error())
	
	// Extract enhanced error information
	if ldapErr := extractLDAPError(err); ldapErr != nil {
		fmt.Printf("   Operation: %s\n", ldapErr.Op)
		fmt.Printf("   Server: %s\n", ldapErr.Server)
		if ldapErr.DN != "" {
			fmt.Printf("   DN: %s\n", ldapErr.DN)
		}
		if ldapErr.Code != 0 {
			fmt.Printf("   LDAP Code: %d\n", ldapErr.Code)
		}
		if len(ldapErr.Context) > 0 {
			fmt.Printf("   Context: %+v\n", ldapErr.Context)
		}
		fmt.Printf("   Timestamp: %s\n", ldapErr.Timestamp.Format(time.RFC3339))
	}
	
	// Error classification
	fmt.Printf("   Classifications:\n")
	fmt.Printf("     • Authentication Error: %v\n", ldap.IsAuthenticationError(err))
	fmt.Printf("     • Connection Error: %v\n", ldap.IsConnectionError(err))
	fmt.Printf("     • Not Found Error: %v\n", ldap.IsNotFoundError(err))
	fmt.Printf("     • Validation Error: %v\n", ldap.IsValidationError(err))
	fmt.Printf("     • Context Error: %v\n", ldap.IsContextError(err))
	
	// Error severity and retry information
	severity := ldap.GetErrorSeverity(err)
	retryable := ldap.IsRetryable(err)
	fmt.Printf("   Severity: %s\n", severity)
	fmt.Printf("   Retryable: %v\n", retryable)
	
	// Detailed error with full context
	detailed := ldap.FormatErrorWithContext(err)
	fmt.Printf("   Detailed: %s\n", detailed)
}

func handleAuthenticationError(username string, err error) {
	if ldap.IsAuthenticationError(err) {
		if ldap.IsNotFoundError(err) {
			fmt.Printf("🔍 User '%s' not found in directory\n", username)
			// Could suggest user creation or check spelling
		} else {
			fmt.Printf("🔐 Authentication failed for user '%s'\n", username)
			// Could increment failed login counter, log security event
			
			// Check specific authentication error types
			if errors.Is(err, ldap.ErrInvalidCredentials) {
				fmt.Printf("   → Invalid username or password\n")
			} else if errors.Is(err, ldap.ErrAccountDisabled) {
				fmt.Printf("   → Account is disabled\n")
			} else if errors.Is(err, ldap.ErrAccountLocked) {
				fmt.Printf("   → Account is locked\n")
			}
		}
	} else if ldap.IsConnectionError(err) {
		fmt.Printf("🌐 Connection issue during authentication\n")
		if ldap.IsRetryable(err) {
			fmt.Printf("   → This might be resolved by retrying\n")
		}
	} else {
		fmt.Printf("❓ Unexpected error during authentication\n")
	}
}

func handleUserSearchError(username string, err error) {
	if ldap.IsNotFoundError(err) {
		fmt.Printf("🔍 User '%s' not found\n", username)
		// Return 404 to client, suggest alternatives
	} else if ldap.IsValidationError(err) {
		fmt.Printf("⚠️  Invalid search parameters for '%s'\n", username)
		// Return 400 to client, provide correction hints
	} else if ldap.IsConnectionError(err) {
		fmt.Printf("🌐 Connection issue during search\n")
		if ldap.IsRetryable(err) {
			fmt.Printf("   → Consider implementing retry logic\n")
		}
	}
}

func handleConnectionError(err error) {
	if ldap.IsConnectionError(err) {
		severity := ldap.GetErrorSeverity(err)
		switch severity {
		case ldap.SeverityCritical:
			fmt.Printf("🚨 Critical connection failure - alert operations team\n")
			// Alert monitoring system, try failover server
		case ldap.SeverityError:
			fmt.Printf("❌ Connection error - log and monitor\n")
			// Log error, increment metrics
		}
		
		if ldap.IsRetryable(err) {
			fmt.Printf("   → Implement exponential backoff retry\n")
		} else {
			fmt.Printf("   → Check server configuration and network connectivity\n")
		}
	}
}

func handleContextError(err error) {
	if ldap.IsContextError(err) {
		if errors.Is(err, ldap.ErrContextCancelled) {
			fmt.Printf("⏹️  Operation was cancelled\n")
		} else if errors.Is(err, ldap.ErrContextDeadlineExceeded) {
			fmt.Printf("⏰ Operation timed out\n")
		}
		fmt.Printf("   → Clean up resources, don't retry automatically\n")
	}
}

// extractLDAPError safely extracts enhanced LDAP error information
func extractLDAPError(err error) *ldap.LDAPError {
	var ldapErr *ldap.LDAPError
	if errors.As(err, &ldapErr) {
		return ldapErr
	}
	return nil
}

// Example of how to integrate with structured logging
func logErrorWithContext(logger *slog.Logger, operation string, err error) {
	severity := ldap.GetErrorSeverity(err)
	
	attrs := []slog.Attr{
		slog.String("operation", operation),
		slog.String("error", err.Error()),
		slog.String("severity", severity.String()),
	}
	
	// Add LDAP-specific context if available
	if ldapErr := extractLDAPError(err); ldapErr != nil {
		attrs = append(attrs,
			slog.String("ldap_server", ldapErr.Server),
			slog.String("ldap_operation", ldapErr.Op))
		
		if ldapErr.DN != "" {
			attrs = append(attrs, slog.String("ldap_dn", ldapErr.DN))
		}
		
		if ldapErr.Code != 0 {
			attrs = append(attrs, slog.Int("ldap_code", ldapErr.Code))
		}
		
		// Add context information
		for key, value := range ldapErr.Context {
			attrs = append(attrs, slog.Any(fmt.Sprintf("context_%s", key), value))
		}
	}
	
	// Log with appropriate level based on severity
	level := slog.LevelError
	switch severity {
	case ldap.SeverityCritical:
		level = slog.LevelError
	case ldap.SeverityError:
		level = slog.LevelError
	case ldap.SeverityWarning:
		level = slog.LevelWarn
	case ldap.SeverityInfo:
		level = slog.LevelInfo
	}
	
	logger.LogAttrs(context.Background(), level, "ldap_operation_failed", attrs...)
}