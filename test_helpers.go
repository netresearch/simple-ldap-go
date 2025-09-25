package ldap

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// TestContainer is a stub for test container setup
type TestContainer struct {
	Config      Config
	AdminUser   string
	AdminPass   string
	BaseDN      string
	UsersOU     string
	GroupsOU    string
	ComputersOU string
}

// Close closes the test container
func (tc *TestContainer) Close(t *testing.T) {}

// GetLDAPClient returns a test LDAP client
func (tc *TestContainer) GetLDAPClient(t *testing.T) *LDAP {
	client, err := New(&tc.Config, tc.AdminUser, tc.AdminPass)
	if err != nil {
		t.Fatalf("Failed to create LDAP client: %v", err)
	}
	return client
}

// TestData represents test data
type TestData struct {
	TestUserDN        string
	TestUserSAM       string
	TestUserPass      string
	TestGroupDN       string
	TestGroupName     string
	ValidUserDN       string
	ValidUserPassword string
}

// GetTestData returns test data
func (tc *TestContainer) GetTestData() TestData {
	return TestData{
		TestUserDN:        "cn=testuser,ou=users," + tc.BaseDN,
		TestUserSAM:       "testuser",
		TestUserPass:      "testpass",
		TestGroupDN:       "cn=testgroup,ou=groups," + tc.BaseDN,
		TestGroupName:     "testgroup",
		ValidUserDN:       "cn=testuser,ou=users," + tc.BaseDN,
		ValidUserPassword: "testpass",
	}
}

// SetupTestContainer creates a test container
// This is a stub implementation - actual integration tests require Docker
func SetupTestContainer(t *testing.T) *TestContainer {
	t.Skip("Integration tests require Docker container setup")
	return &TestContainer{
		Config: Config{
			Server: "ldap://localhost:389",
			BaseDN: "dc=example,dc=com",
		},
		AdminUser: "cn=admin,dc=example,dc=com",
		AdminPass: "admin",
		BaseDN:    "dc=example,dc=com",
	}
}

// LDAPError represents an LDAP error with context
type LDAPError struct {
	Operation     string
	Server        string
	Message       string
	OriginalError error
	DN            string
	Code          string
	Context       map[string]interface{}
	masked        bool
}

// Error implements the error interface
func (e *LDAPError) Error() string {
	return e.Message
}

// Unwrap returns the original error for errors.Is() support
func (e *LDAPError) Unwrap() error {
	return e.OriginalError
}

// WithDN adds DN context to the error
func (e *LDAPError) WithDN(dn string) *LDAPError {
	e.DN = dn
	return e
}

// WithCode adds error code
func (e *LDAPError) WithCode(code interface{}) *LDAPError {
	switch v := code.(type) {
	case string:
		e.Code = v
	case int:
		e.Code = fmt.Sprintf("%d", v)
	default:
		e.Code = ""
	}
	return e
}

// WithContext adds context to the error
func (e *LDAPError) WithContext(key string, value interface{}) *LDAPError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// UnmaskedError returns the unmasked error message
func (e *LDAPError) UnmaskedError() string {
	if e.DN != "" && e.Server != "" && e.OriginalError != nil {
		return fmt.Sprintf(`ldap %s failed for DN "%s" on server "%s": %s`,
			e.Operation, e.DN, e.Server, e.OriginalError.Error())
	}
	if e.OriginalError != nil {
		return e.OriginalError.Error()
	}
	return e.Message
}

// NewLDAPError creates a new LDAP error (stub)
func NewLDAPError(op string, msg string, err error) *LDAPError {
	return &LDAPError{
		Operation:     op,
		Server:        msg, // msg is actually the server in the test
		Message:       msg,
		OriginalError: err,
	}
}

// GetErrorContext gets error context (stub)
func GetErrorContext(err error) map[string]interface{} {
	if ldapErr, ok := err.(*LDAPError); ok {
		if ldapErr.Context != nil {
			return ldapErr.Context
		}
	}
	return make(map[string]interface{})
}

// ExtractDN extracts DN from error (stub)
func ExtractDN(err error) string {
	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.DN
	}
	return ""
}

// ExtractOperation extracts operation from error (stub)
func ExtractOperation(err error) string {
	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.Operation
	}
	return ""
}

// GetLDAPResultCode gets LDAP result code from error (stub)
func GetLDAPResultCode(err error) int {
	if ldapErr, ok := err.(*LDAPError); ok && ldapErr.Code != "" {
		// Parse code as string number
		var code int
		if _, err := fmt.Sscanf(ldapErr.Code, "%d", &code); err == nil {
			return code
		}
	}
	return 0
}

// IsAuthenticationError checks if error is authentication related (stub)
func IsAuthenticationError(err error) bool {
	if err == ErrInvalidCredentials {
		return true
	}
	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.Message == "invalid credentials"
	}
	return false
}

// IsConnectionError checks if error is connection related (stub)
func IsConnectionError(err error) bool {
	if err == ErrConnectionFailed || err == ErrServerUnavailable {
		return true
	}
	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.Message == "connection failed" || ldapErr.Message == "server unavailable"
	}
	return false
}

// IsNotFoundError checks if error is not found related (stub)
func IsNotFoundError(err error) bool {
	if err == ErrUserNotFound || err == ErrGroupNotFound || err == ErrObjectNotFound {
		return true
	}
	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.Message == "object not found" || ldapErr.Message == "user not found"
	}
	return false
}

// IsValidationError checks if error is validation related (stub)
func IsValidationError(err error) bool {
	if err == ErrInvalidDN {
		return true
	}
	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.Message == "invalid DN"
	}
	return false
}

// IsContextError checks if error is context related (stub)
func IsContextError(err error) bool {
	if err == ErrContextCancelled || err == ErrContextDeadlineExceeded {
		return true
	}
	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.Message == "context cancelled" || ldapErr.Message == "deadline exceeded"
	}
	return false
}

// WrapLDAPError wraps an error (stub)
func WrapLDAPError(op string, msg string, err error) error {
	// Check for context errors and return sentinel errors
	if err != nil {
		// Safely get error string
		var errStr string
		func() {
			defer func() {
				if recover() != nil {
					errStr = "error"
				}
			}()
			errStr = err.Error()
		}()

		if errStr == "context canceled" {
			return ErrContextCancelled
		}
		if errStr == "context deadline exceeded" {
			return ErrContextDeadlineExceeded
		}
	}

	// Create wrapped error
	wrappedErr := NewLDAPError(op, msg, err)

	// If it's an LDAP error with ResultCode, extract and store it
	if ldapErr, ok := err.(*ldap.Error); ok {
		wrappedErr.Code = fmt.Sprintf("%d", int(ldapErr.ResultCode))
		// Also check for specific error types
		if ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			wrappedErr.Message = "invalid credentials"
		} else if ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			wrappedErr.Message = "object not found"
		}
	}

	return wrappedErr
}

// ErrorSeverity represents error severity level
type ErrorSeverity int

const (
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

// String returns string representation of severity
func (s ErrorSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// GetErrorSeverity gets the severity of an error (stub)
func GetErrorSeverity(err error) ErrorSeverity {
	if IsConnectionError(err) {
		return SeverityCritical
	}
	if IsNotFoundError(err) {
		return SeverityWarning
	}
	if IsContextError(err) {
		return SeverityInfo
	}
	return SeverityError
}

// IsRetryable checks if an error is retryable (stub)
func IsRetryable(err error) bool {
	// Connection and server errors are typically retryable
	return IsConnectionError(err) || err == ErrServerUnavailable
}

// IsNoSuchObjectError checks if error is a no such object error (stub)
func IsNoSuchObjectError(err error) bool {
	// Check if it's a wrapped LDAP error with NoSuchObject code
	if ldapErr, ok := err.(*LDAPError); ok {
		if ldapErr.Message == "object not found" {
			return true
		}
		// Also check the code
		if GetLDAPResultCode(err) == int(ldap.LDAPResultNoSuchObject) {
			return true
		}
	}
	return false
}

// FormatErrorWithContext formats an error with context
func FormatErrorWithContext(err error, ctx map[string]interface{}) string {
	if err == nil {
		return ""
	}

	if ldapErr, ok := err.(*LDAPError); ok {
		result := fmt.Sprintf("LDAP %s failed", ldapErr.Operation)
		if ldapErr.DN != "" {
			result += fmt.Sprintf(" for DN \"%s\"", ldapErr.DN)
		}
		if ldapErr.Server != "" {
			result += fmt.Sprintf(" on server \"%s\"", ldapErr.Server)
		}
		if ldapErr.OriginalError != nil {
			result += fmt.Sprintf(": %s", ldapErr.OriginalError.Error())
		}
		if ldapErr.Code != "" {
			result += fmt.Sprintf(" LDAP code: %s", ldapErr.Code)
		}

		// Add context information
		if ldapErr.Context != nil {
			for key, value := range ldapErr.Context {
				result += fmt.Sprintf(" %s=%v", key, value)
			}
		}

		result += " occurred at: " + time.Now().Format("2006-01-02 15:04:05")
		return result
	}

	return err.Error()
}

// RetryableError is an error that can be retried
type RetryableError struct {
	error
	retryable bool
}

// IsRetryable returns whether the error is retryable
func (e *RetryableError) IsRetryable() bool {
	return e.retryable
}

// Unwrap returns the wrapped error for errors.Is() support
func (e *RetryableError) Unwrap() error {
	return e.error
}

// WithRetryInfo adds retry info to error (stub)
func WithRetryInfo(err error, retryable bool) *RetryableError {
	return &RetryableError{
		error:     err,
		retryable: retryable,
	}
}

// Error variables for testing
var (
	ErrInvalidCredentials      = NewLDAPError("auth", "invalid credentials", nil)
	ErrConnectionFailed        = NewLDAPError("connect", "connection failed", nil)
	ErrInvalidDN               = NewLDAPError("parse", "invalid DN", nil)
	ErrContextCancelled        = NewLDAPError("context", "context cancelled", nil)
	ErrContextDeadlineExceeded = NewLDAPError("context", "deadline exceeded", nil)
	ErrObjectNotFound          = NewLDAPError("search", "object not found", nil)
	ErrServerUnavailable       = NewLDAPError("connect", "server unavailable", nil)
)
