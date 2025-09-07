package ldap

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestLDAPError tests the enhanced LDAP error functionality
func TestLDAPError(t *testing.T) {
	// Test basic error creation
	baseErr := errors.New("connection refused")
	ldapErr := NewLDAPError("TestOperation", "ldaps://test.com", baseErr)
	ldapErr.WithDN("CN=test,DC=example,DC=com").
		WithCode(int(ldap.LDAPResultServerDown)).
		WithContext("username", "testuser").
		WithContext("filter", "(objectClass=user)")

	// Test error message formatting
	expectedMsg := `ldap TestOperation failed for DN "CN=test,DC=example,DC=com" on server "ldaps://test.com": connection refused`
	if ldapErr.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, ldapErr.Error())
	}

	// Test error unwrapping
	if !errors.Is(ldapErr, baseErr) {
		t.Error("Expected enhanced error to wrap base error")
	}

	// Test context extraction
	context := GetErrorContext(ldapErr)
	if context == nil {
		t.Fatal("Expected non-nil context")
	}
	if context["username"] != "testuser" {
		t.Errorf("Expected username 'testuser', got %v", context["username"])
	}

	// Test DN extraction
	dn := ExtractDN(ldapErr)
	if dn != "CN=test,DC=example,DC=com" {
		t.Errorf("Expected DN 'CN=test,DC=example,DC=com', got %q", dn)
	}

	// Test operation extraction
	op := ExtractOperation(ldapErr)
	if op != "TestOperation" {
		t.Errorf("Expected operation 'TestOperation', got %q", op)
	}

	// Test LDAP result code extraction
	code := GetLDAPResultCode(ldapErr)
	if code != int(ldap.LDAPResultServerDown) {
		t.Errorf("Expected LDAP result code %d, got %d", int(ldap.LDAPResultServerDown), code)
	}
}

// TestErrorClassification tests error classification functions
func TestErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		isAuth   bool
		isConn   bool
		isNotFound bool
		isValid  bool
		isCtx    bool
	}{
		{
			name:   "Authentication Error",
			err:    ErrInvalidCredentials,
			isAuth: true,
		},
		{
			name:   "Connection Error",
			err:    ErrConnectionFailed,
			isConn: true,
		},
		{
			name:      "Not Found Error",
			err:       ErrUserNotFound,
			isNotFound: true,
		},
		{
			name:    "Validation Error",
			err:     ErrInvalidDN,
			isValid: true,
		},
		{
			name:  "Context Error",
			err:   ErrContextCancelled,
			isCtx: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsAuthenticationError(tt.err) != tt.isAuth {
				t.Errorf("IsAuthenticationError() = %v, want %v", IsAuthenticationError(tt.err), tt.isAuth)
			}
			if IsConnectionError(tt.err) != tt.isConn {
				t.Errorf("IsConnectionError() = %v, want %v", IsConnectionError(tt.err), tt.isConn)
			}
			if IsNotFoundError(tt.err) != tt.isNotFound {
				t.Errorf("IsNotFoundError() = %v, want %v", IsNotFoundError(tt.err), tt.isNotFound)
			}
			if IsValidationError(tt.err) != tt.isValid {
				t.Errorf("IsValidationError() = %v, want %v", IsValidationError(tt.err), tt.isValid)
			}
			if IsContextError(tt.err) != tt.isCtx {
				t.Errorf("IsContextError() = %v, want %v", IsContextError(tt.err), tt.isCtx)
			}
		})
	}
}

// TestWrapLDAPError tests the error wrapping functionality
func TestWrapLDAPError(t *testing.T) {
	tests := []struct {
		name           string
		op             string
		server         string
		baseErr        error
		expectedSentinel error
		expectedCode   int
	}{
		{
			name:           "Context Cancelled",
			op:             "TestOp",
			server:         "ldaps://test.com",
			baseErr:        context.Canceled,
			expectedSentinel: ErrContextCancelled,
		},
		{
			name:           "Context Deadline Exceeded",
			op:             "TestOp",
			server:         "ldaps://test.com",
			baseErr:        context.DeadlineExceeded,
			expectedSentinel: ErrContextDeadlineExceeded,
		},
		{
			name:           "LDAP Invalid Credentials",
			op:             "TestAuth",
			server:         "ldaps://test.com",
			baseErr:        &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: fmt.Errorf("invalid credentials")},
			expectedSentinel: ErrInvalidCredentials,
			expectedCode:   int(ldap.LDAPResultInvalidCredentials),
		},
		{
			name:           "LDAP No Such Object",
			op:             "TestSearch",
			server:         "ldaps://test.com",
			baseErr:        &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject, Err: fmt.Errorf("no such object")},
			expectedSentinel: ErrObjectNotFound,
			expectedCode:   int(ldap.LDAPResultNoSuchObject),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := WrapLDAPError(tt.op, tt.server, tt.baseErr)
			
			// For context errors, check sentinel error matching
			if tt.expectedSentinel == ErrContextCancelled || tt.expectedSentinel == ErrContextDeadlineExceeded {
				if !errors.Is(wrapped, tt.expectedSentinel) {
					t.Errorf("Expected wrapped error to be %v, got %v", tt.expectedSentinel, wrapped)
				}
			}

			if tt.expectedCode != 0 {
				code := GetLDAPResultCode(wrapped)
				if code != tt.expectedCode {
					t.Errorf("Expected LDAP code %d, got %d", tt.expectedCode, code)
				}
				
				// For LDAP errors, verify the error classification works
				switch tt.expectedCode {
				case int(ldap.LDAPResultInvalidCredentials):
					if !IsAuthenticationError(wrapped) {
						t.Errorf("Expected authentication error classification for invalid credentials")
					}
				case int(ldap.LDAPResultNoSuchObject):
					if !IsNotFoundError(wrapped) {
						t.Errorf("Expected not found error classification for no such object")
					}
				}
			}
		})
	}
}

// TestErrorSeverity tests error severity classification
func TestErrorSeverity(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		severity ErrorSeverity
	}{
		{
			name:     "Critical Connection Error",
			err:      ErrConnectionFailed,
			severity: SeverityCritical,
		},
		{
			name:     "Authentication Error",
			err:      ErrInvalidCredentials,
			severity: SeverityError,
		},
		{
			name:     "Not Found Warning",
			err:      ErrUserNotFound,
			severity: SeverityWarning,
		},
		{
			name:     "Context Info",
			err:      ErrContextCancelled,
			severity: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity := GetErrorSeverity(tt.err)
			if severity != tt.severity {
				t.Errorf("Expected severity %v, got %v", tt.severity, severity)
			}
		})
	}
}

// TestRetryableError tests retry capability detection
func TestRetryableError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "Connection Error - Retryable",
			err:       ErrConnectionFailed,
			retryable: true,
		},
		{
			name:      "Server Unavailable - Retryable", 
			err:       ErrServerUnavailable,
			retryable: true,
		},
		{
			name:      "Invalid Credentials - Not Retryable",
			err:       ErrInvalidCredentials,
			retryable: false,
		},
		{
			name:      "Context Cancelled - Not Retryable",
			err:       ErrContextCancelled,
			retryable: false,
		},
		{
			name:      "Object Not Found - Not Retryable",
			err:       ErrUserNotFound,
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retryable := IsRetryable(tt.err)
			if retryable != tt.retryable {
				t.Errorf("Expected retryable %v, got %v", tt.retryable, retryable)
			}
		})
	}
}

// TestEnhancedBackwardCompatibility tests that existing error checking still works
func TestEnhancedBackwardCompatibility(t *testing.T) {
	// Test that errors.Is still works with our enhanced errors
	baseErr := ErrUserNotFound
	wrappedErr := fmt.Errorf("failed to find user: %w", baseErr)
	
	if !errors.Is(wrappedErr, ErrUserNotFound) {
		t.Error("Backward compatibility broken: errors.Is doesn't work with wrapped errors")
	}

	// Test that LDAP result code checking still works
	ldapErr := &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject}
	classifiedErr := WrapLDAPError("TestOp", "ldaps://test.com", ldapErr)
	
	if !IsNoSuchObjectError(classifiedErr) {
		t.Error("Backward compatibility broken: LDAP result code checking doesn't work")
	}

	// Test that enhanced error doesn't break simple error checking
	simpleErr := errors.New("simple error")
	if IsAuthenticationError(simpleErr) {
		t.Error("Simple error incorrectly classified as authentication error")
	}
}

// TestFormatErrorWithContext tests detailed error formatting
func TestFormatErrorWithContext(t *testing.T) {
	baseErr := errors.New("connection timeout")
	ldapErr := NewLDAPError("TestOperation", "ldaps://test.com", baseErr).
		WithDN("CN=test,DC=example,DC=com").
		WithCode(int(ldap.LDAPResultTimeLimitExceeded)).
		WithContext("timeout_seconds", 30).
		WithContext("retry_count", 3)

	formatted := FormatErrorWithContext(ldapErr)
	
	// Check that formatted error contains key information
	expectedSubstrings := []string{
		"TestOperation",
		"ldaps://test.com", 
		"CN=test,DC=example,DC=com",
		"connection timeout",
		"LDAP code:",
		"timeout_seconds=30",
		"retry_count=3",
		"occurred at:",
	}

	for _, substr := range expectedSubstrings {
		if !contains(formatted, substr) {
			t.Errorf("Formatted error missing expected substring %q. Got: %s", substr, formatted)
		}
	}
}

// TestErrorSeverityString tests severity string representation
func TestErrorSeverityString(t *testing.T) {
	tests := []struct {
		severity ErrorSeverity
		expected string
	}{
		{SeverityInfo, "INFO"},
		{SeverityWarning, "WARNING"},
		{SeverityError, "ERROR"},
		{SeverityCritical, "CRITICAL"},
		{ErrorSeverity(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.severity.String() != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, tt.severity.String())
			}
		})
	}
}

// TestRetryableErrorInterface tests the RetryableError interface
func TestRetryableErrorInterface(t *testing.T) {
	baseErr := errors.New("temporary failure")
	retryableErr := WithRetryInfo(baseErr, true)
	nonRetryableErr := WithRetryInfo(baseErr, false)

	// Test that the interface works correctly
	if !retryableErr.IsRetryable() {
		t.Error("Expected retryable error to be retryable")
	}

	if nonRetryableErr.IsRetryable() {
		t.Error("Expected non-retryable error to not be retryable")
	}

	// Test error message preservation
	if retryableErr.Error() != baseErr.Error() {
		t.Error("RetryableError should preserve original error message")
	}

	// Test unwrapping
	if !errors.Is(retryableErr, baseErr) {
		t.Error("RetryableError should unwrap to original error")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && 
		(s == substr || 
		 s[:len(substr)] == substr || 
		 s[len(s)-len(substr):] == substr ||
		 containsAt(s, substr)))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkErrorCreation benchmarks error creation performance
func BenchmarkErrorCreation(b *testing.B) {
	baseErr := errors.New("test error")
	
	b.Run("SimpleError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = fmt.Errorf("operation failed: %w", baseErr)
		}
	})
	
	b.Run("EnhancedError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewLDAPError("TestOp", "ldaps://test.com", baseErr).
				WithDN("CN=test,DC=example,DC=com").
				WithContext("key", "value")
		}
	})
}

// BenchmarkErrorClassification benchmarks error classification performance
func BenchmarkErrorClassification(b *testing.B) {
	err := ErrInvalidCredentials
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsAuthenticationError(err)
	}
}

// ExampleLDAPError demonstrates how to use enhanced error handling
func ExampleLDAPError() {
	// Simulate an authentication failure
	baseErr := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials}
	
	// Wrap with enhanced context
	enhancedErr := WrapLDAPError("AuthenticateUser", "ldaps://ad.company.com", baseErr)
	
	// Check error type
	if IsAuthenticationError(enhancedErr) {
		fmt.Println("Authentication failed")
	}
	
	// Get severity for logging
	severity := GetErrorSeverity(enhancedErr)
	fmt.Printf("Error severity: %s\n", severity)
	
	// Check if retryable
	if IsRetryable(enhancedErr) {
		fmt.Println("This error might be resolved by retrying")
	} else {
		fmt.Println("This error requires different credentials or configuration")
	}
	
	// Output:
	// Authentication failed
	// Error severity: ERROR
	// This error requires different credentials or configuration
}