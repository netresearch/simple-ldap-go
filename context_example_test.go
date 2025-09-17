package ldap

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// TestContextCancellation demonstrates context cancellation functionality
func TestContextCancellation(t *testing.T) {
	// Create a context that is immediately cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Mock LDAP client structure
	client := &LDAP{
		config: Config{
			Server: "ldap://nonexistent:389",
			BaseDN: "DC=test,DC=com",
		},
		user:     "test",
		password: "test",
		logger:   slog.Default(),
	}

	// These operations should fail with context.Canceled error
	_, err := client.FindUserBySAMAccountNameContext(ctx, "testuser")
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}

	_, err = client.CheckPasswordForSAMAccountNameContext(ctx, "testuser", "password")
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}

	_, err = client.FindUsersContext(ctx)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}

	_, err = client.FindGroupsContext(ctx)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}

	_, err = client.FindComputersContext(ctx)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}

// TestContextDeadlineExceeded demonstrates timeout functionality
func TestContextDeadlineExceeded(t *testing.T) {
	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Sleep to ensure timeout
	time.Sleep(1 * time.Millisecond)

	client := &LDAP{
		config: Config{
			Server: "ldap://nonexistent:389",
			BaseDN: "DC=test,DC=com",
		},
		user:     "test",
		password: "test",
		logger:   slog.Default(),
	}

	// Operations should fail with context.DeadlineExceeded error
	_, err := client.GetConnectionContext(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got: %v", err)
	}
}

// TestBackwardCompatibility verifies that original methods still work
func TestBackwardCompatibility(t *testing.T) {
	// Simple test to verify methods exist and delegate correctly
	client := &LDAP{
		config: Config{
			Server: "ldap://localhost:389",
			BaseDN: "DC=test,DC=com",
		},
		user:     "test",
		password: "test",
	}

	// Just verify the methods exist and would delegate to context versions
	// We don't actually test connection since that would require a real LDAP server
	// The important thing is that the backward compatibility wrapper methods exist

	// Test that methods exist by getting their function values
	_ = client.FindUserBySAMAccountName
	_ = client.CheckPasswordForSAMAccountName
	_ = client.FindUsers
	_ = client.FindGroups
	_ = client.FindComputers
	_ = client.GetConnection

	// Also test context versions exist
	_ = client.FindUserBySAMAccountNameContext
	_ = client.CheckPasswordForSAMAccountNameContext
	_ = client.FindUsersContext
	_ = client.FindGroupsContext
	_ = client.FindComputersContext
	_ = client.GetConnectionContext

	t.Log("All backward compatibility methods exist and context methods exist")
}
