package ldap

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPError represents an enhanced error with rich context for LDAP operations.
// It wraps underlying errors while providing operation-specific context for debugging.
type LDAPError struct {
	// Op is the operation name (e.g., "FindUserBySAMAccountName", "CheckPassword")
	Op string
	// DN is the distinguished name involved in the operation (if applicable)
	DN string
	// Server is the LDAP server URL
	Server string
	// Code is the LDAP result code (if applicable)
	Code int
	// Err is the underlying error
	Err error
	// Context contains additional context information for debugging
	Context map[string]interface{}
	// mu protects the Context map for thread-safe operations
	mu sync.RWMutex
	// Timestamp indicates when the error occurred
	Timestamp time.Time
}

// Error implements the error interface, providing a formatted error message.
// Sensitive information is masked to prevent data leakage in logs.
func (e *LDAPError) Error() string {
	maskedServer := maskSensitiveData(e.Server)
	if e.DN != "" {
		maskedDN := maskSensitiveData(e.DN)
		return fmt.Sprintf("ldap %s failed for DN %q on server %q: %v", e.Op, maskedDN, maskedServer, e.Err)
	}
	return fmt.Sprintf("ldap %s failed on server %q: %v", e.Op, maskedServer, e.Err)
}

// UnmaskedError returns the error message without masking sensitive data.
// This method is intended for testing and debugging purposes only.
func (e *LDAPError) UnmaskedError() string {
	if e.DN != "" {
		return fmt.Sprintf("ldap %s failed for DN %q on server %q: %v", e.Op, e.DN, e.Server, e.Err)
	}
	return fmt.Sprintf("ldap %s failed on server %q: %v", e.Op, e.Server, e.Err)
}

// Unwrap implements the Go 1.13+ error unwrapping interface.
func (e *LDAPError) Unwrap() error {
	return e.Err
}

// Is implements the Go 1.13+ error comparison interface for compatibility with errors.Is.
func (e *LDAPError) Is(target error) bool {
	if ldapErr, ok := target.(*LDAPError); ok {
		return e.Op == ldapErr.Op && e.Code == ldapErr.Code
	}
	return false
}

// NewLDAPError creates a new enhanced LDAP error with the specified operation, server, and underlying error.
// The error includes a timestamp and empty context map for additional information.
func NewLDAPError(op, server string, err error) *LDAPError {
	return &LDAPError{
		Op:        op,
		Server:    server,
		Err:       err,
		Context:   make(map[string]interface{}),
		Timestamp: time.Now(),
	}
}

// WithDN adds a distinguished name to the error context.
func (e *LDAPError) WithDN(dn string) *LDAPError {
	e.DN = dn
	return e
}

// WithCode adds an LDAP result code to the error context.
func (e *LDAPError) WithCode(code int) *LDAPError {
	e.Code = code
	return e
}

// WithContext adds additional context information to the error.
// This method is thread-safe.
func (e *LDAPError) WithContext(key string, value interface{}) *LDAPError {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Context[key] = value
	return e
}

// WrapLDAPError wraps an error with LDAP-specific context information.
// This function analyzes the underlying error to extract LDAP-specific information
// and classify the error type for proper handling.
func WrapLDAPError(op, server string, err error) error {
	if err == nil {
		return nil
	}

	// Handle context errors
	if errors.Is(err, ErrContextCancelled) || fmt.Sprintf("%v", err) == "context canceled" {
		return fmt.Errorf("%s: %w", op, ErrContextCancelled)
	}
	if errors.Is(err, ErrContextDeadlineExceeded) || fmt.Sprintf("%v", err) == "context deadline exceeded" {
		return fmt.Errorf("%s: %w", op, ErrContextDeadlineExceeded)
	}

	// Handle LDAP-specific errors
	if ldapErr, ok := err.(*ldap.Error); ok {
		return classifyLDAPError(op, server, ldapErr)
	}

	// Default wrapping for other errors
	return NewLDAPError(op, server, err)
}

// classifyLDAPError classifies LDAP errors and maps them to specific error types.
func classifyLDAPError(op, server string, ldapErr *ldap.Error) error {
	enhanced := NewLDAPError(op, server, ldapErr).WithCode(int(ldapErr.ResultCode))

	switch ldapErr.ResultCode {
	case ldap.LDAPResultInvalidCredentials:
		enhanced.Err = ErrInvalidCredentials
	case ldap.LDAPResultNoSuchObject:
		enhanced.Err = ErrObjectNotFound
	case ldap.LDAPResultServerDown:
		enhanced.Err = ErrConnectionFailed
	case ldap.LDAPResultUnavailable:
		enhanced.Err = ErrServerUnavailable
	case ldap.LDAPResultTimeLimitExceeded:
		enhanced.Err = ErrTimeoutExceeded
	case ldap.LDAPResultInvalidDNSyntax:
		enhanced.Err = ErrInvalidDN
	default:
		// Keep the original LDAP error
	}

	return enhanced
}

// GetErrorContext extracts context information from an error.
// Returns nil if the error doesn't contain context information.
func GetErrorContext(err error) map[string]interface{} {
	var enhancedErr *LDAPError
	if !errors.As(err, &enhancedErr) {
		return nil
	}

	enhancedErr.mu.RLock()
	defer enhancedErr.mu.RUnlock()

	// Return a copy to prevent external modification
	contextCopy := make(map[string]interface{})
	for k, v := range enhancedErr.Context {
		contextCopy[k] = v
	}

	return contextCopy
}

// ExtractDN extracts the distinguished name from an LDAP error.
// Returns empty string if no DN is available.
func ExtractDN(err error) string {
	var enhancedErr *LDAPError
	if !errors.As(err, &enhancedErr) {
		return ""
	}
	return enhancedErr.DN
}

// ExtractOperation extracts the operation name from an LDAP error.
// Returns empty string if no operation is available.
func ExtractOperation(err error) string {
	var enhancedErr *LDAPError
	if !errors.As(err, &enhancedErr) {
		return ""
	}
	return enhancedErr.Op
}

// GetLDAPResultCode extracts the LDAP result code from an error.
// Returns 0 if no LDAP result code is available.
func GetLDAPResultCode(err error) int {
	var enhancedErr *LDAPError
	if !errors.As(err, &enhancedErr) {
		return 0
	}
	return enhancedErr.Code
}

// IsAuthenticationError checks if an error is related to authentication.
func IsAuthenticationError(err error) bool {
	return errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrAccountLocked) ||
		errors.Is(err, ErrAccountDisabled) ||
		errors.Is(err, ErrPasswordExpired) ||
		isLDAPCodeMatch(err, uint16(ldap.LDAPResultInvalidCredentials), uint16(ldap.LDAPResultConstraintViolation))
}

// IsConnectionError checks if an error is related to connection issues.
func IsConnectionError(err error) bool {
	return errors.Is(err, ErrConnectionFailed) ||
		errors.Is(err, ErrServerUnavailable) ||
		isLDAPCodeMatch(err, uint16(ldap.LDAPResultServerDown), uint16(ldap.LDAPResultUnavailable))
}

// IsNotFoundError checks if an error indicates that an object was not found.
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrGroupNotFound) ||
		errors.Is(err, ErrObjectNotFound) ||
		isLDAPCodeMatch(err, uint16(ldap.LDAPResultNoSuchObject))
}

// IsValidationError checks if an error is related to input validation.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidDN) ||
		errors.Is(err, ErrInvalidFilter) ||
		isLDAPCodeMatch(err, uint16(ldap.LDAPResultInvalidDNSyntax), uint16(ldap.LDAPResultFilterError))
}

// IsContextError checks if an error is related to context operations.
func IsContextError(err error) bool {
	return errors.Is(err, ErrContextCancelled) ||
		errors.Is(err, ErrContextDeadlineExceeded)
}

// IsNoSuchObjectError checks if an error indicates no such object was found.
func IsNoSuchObjectError(err error) bool {
	return isLDAPCodeMatch(err, uint16(ldap.LDAPResultNoSuchObject))
}

// isLDAPCodeMatch checks if an error has any of the specified LDAP result codes.
func isLDAPCodeMatch(err error, codes ...uint16) bool {
	code := GetLDAPResultCode(err)
	if code == 0 {
		return false
	}

	for _, c := range codes {
		if code == int(c) {
			return true
		}
	}
	return false
}

// FormatErrorWithContext returns a detailed error description including context information.
// Sensitive information is masked to prevent data leakage.
func FormatErrorWithContext(err error) string {
	var enhancedErr *LDAPError
	if !errors.As(err, &enhancedErr) {
		return err.Error()
	}

	msg := enhancedErr.Error()

	if enhancedErr.Code != 0 {
		msg += fmt.Sprintf(" (LDAP code: %d)", enhancedErr.Code)
	}

	// Thread-safe access to context
	enhancedErr.mu.RLock()
	contextLen := len(enhancedErr.Context)
	if contextLen > 0 {
		msg += " - Context:"
		for key, value := range enhancedErr.Context {
			// Mask sensitive context values
			maskedValue := maskContextValue(key, value)
			msg += fmt.Sprintf(" %s=%v", key, maskedValue)
		}
	}
	enhancedErr.mu.RUnlock()

	if !enhancedErr.Timestamp.IsZero() {
		msg += fmt.Sprintf(" (occurred at: %s)", enhancedErr.Timestamp.Format(time.RFC3339))
	}

	return msg
}

// ErrorSeverity represents the severity level of an error.
type ErrorSeverity int

const (
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

// String returns the string representation of the error severity.
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

// GetErrorSeverity determines the severity level of an error.
func GetErrorSeverity(err error) ErrorSeverity {
	// Context errors are informational as they represent user/system intent
	if IsContextError(err) {
		return SeverityInfo
	}

	// Connection errors are critical as they indicate infrastructure issues
	if IsConnectionError(err) {
		return SeverityCritical
	}

	// Authentication errors are errors but not critical
	if IsAuthenticationError(err) {
		return SeverityError
	}

	// Not found errors are warnings - data might exist elsewhere
	if IsNotFoundError(err) {
		return SeverityWarning
	}

	// Default to error level for unknown error types
	return SeverityError
}

// RetryableError interface defines errors that can be retried.
type RetryableError interface {
	error
	IsRetryable() bool
}

// retryableError implements the RetryableError interface.
type retryableError struct {
	error
	retryable bool
}

// IsRetryable returns whether this error can be retried.
func (r *retryableError) IsRetryable() bool {
	return r.retryable
}

// Unwrap returns the underlying error.
func (r *retryableError) Unwrap() error {
	return r.error
}

// WithRetryInfo wraps an error with retry information.
func WithRetryInfo(err error, retryable bool) RetryableError {
	return &retryableError{
		error:     err,
		retryable: retryable,
	}
}

// IsRetryable determines if an error is retryable based on its type.
func IsRetryable(err error) bool {
	// Check if the error implements RetryableError interface
	if retryableErr, ok := err.(RetryableError); ok {
		return retryableErr.IsRetryable()
	}

	// Default classification based on error types
	if IsConnectionError(err) || errors.Is(err, ErrServerUnavailable) {
		return true
	}

	// Authentication and validation errors are generally not retryable
	if IsAuthenticationError(err) || IsValidationError(err) || IsContextError(err) {
		return false
	}

	// Not found errors are not retryable
	if IsNotFoundError(err) {
		return false
	}

	// Unknown errors default to not retryable for safety
	return false
}

// ValidationError represents input validation errors with field-specific details.
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
	Code    string
}

// Error implements the error interface.
func (v *ValidationError) Error() string {
	maskedValue := maskContextValue(v.Field, v.Value)
	return fmt.Sprintf("validation failed for field %s (value: %v): %s", v.Field, maskedValue, v.Message)
}

// NewValidationError creates a new validation error.
func NewValidationError(field string, value interface{}, message, code string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
		Code:    code,
	}
}

// IsValidationErrorCode checks if a validation error has a specific code.
func IsValidationErrorCode(err error, code string) bool {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return validationErr.Code == code
	}
	return false
}

// MultiError represents multiple errors that occurred together.
type MultiError struct {
	Errors []error
}

// Error implements the error interface.
func (m *MultiError) Error() string {
	if len(m.Errors) == 0 {
		return "no errors"
	}
	if len(m.Errors) == 1 {
		return m.Errors[0].Error()
	}

	var msgs []string
	for _, err := range m.Errors {
		msgs = append(msgs, err.Error())
	}
	return fmt.Sprintf("multiple errors: %s", strings.Join(msgs, "; "))
}

// Unwrap returns the first error for compatibility with errors.Is/As.
func (m *MultiError) Unwrap() error {
	if len(m.Errors) == 0 {
		return nil
	}
	return m.Errors[0]
}

// Is implements error matching for all contained errors.
func (m *MultiError) Is(target error) bool {
	for _, err := range m.Errors {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// As implements error type matching for all contained errors.
func (m *MultiError) As(target interface{}) bool {
	for _, err := range m.Errors {
		if errors.As(err, target) {
			return true
		}
	}
	return false
}

// Add appends an error to the multi-error.
func (m *MultiError) Add(err error) {
	if err != nil {
		m.Errors = append(m.Errors, err)
	}
}

// HasErrors returns true if there are any errors.
func (m *MultiError) HasErrors() bool {
	return len(m.Errors) > 0
}

// NewMultiError creates a new multi-error from the provided errors.
func NewMultiError(errors ...error) *MultiError {
	me := &MultiError{}
	for _, err := range errors {
		me.Add(err)
	}
	return me
}

// maskContextValue masks sensitive context values based on the key name
func maskContextValue(key string, value interface{}) interface{} {
	// List of context keys that contain sensitive information
	sensitiveKeys := map[string]bool{
		"samAccountName": true,
		"username":       true,
		"dn":             true,
		"distinguishedName": true,
		"server":         true,
		"password":       true,
		"credential":     true,
		"token":          true,
		"secret":         true,
	}

	// Check if this key contains sensitive information
	if sensitiveKeys[strings.ToLower(key)] {
		if str, ok := value.(string); ok {
			return maskSensitiveData(str)
		}
	}

	return value
}

// Note: maskSensitiveData function is defined in security.go

// Standard LDAP errors - these are sentinel errors for error classification
var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrPasswordExpired    = errors.New("password expired")

	// Connection errors
	ErrConnectionFailed   = errors.New("connection failed")
	ErrServerUnavailable  = errors.New("server unavailable")
	ErrTimeoutExceeded    = errors.New("timeout exceeded")

	// Search/Object errors
	ErrObjectNotFound = errors.New("object not found")

	// Validation errors
	ErrInvalidDN     = errors.New("invalid distinguished name")
	ErrInvalidFilter = errors.New("invalid LDAP filter")

	// Context errors
	ErrContextCancelled        = errors.New("context cancelled")
	ErrContextDeadlineExceeded = errors.New("context deadline exceeded")
)

// Circuit breaker error - with fields expected by resilience.go
type CircuitBreakerError struct {
	State       string
	Failures    int
	LastFailure time.Time
	NextRetry   time.Time
}

func (e *CircuitBreakerError) Error() string {
	return fmt.Sprintf("circuit breaker %s, failures: %d", e.State, e.Failures)
}

// TimeoutError with constructor expected by resilience.go
type TimeoutError struct {
	Operation      string
	Duration       time.Duration
	TimeoutPeriod  time.Duration  // renamed from Timeout to avoid method name conflict
	Err            error
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("operation %s timed out after %v (timeout: %v)", e.Operation, e.Duration, e.TimeoutPeriod)
}

func (e *TimeoutError) Timeout() bool {
	return true
}

func (e *TimeoutError) Temporary() bool {
	return true
}

// NewTimeoutError creates a new timeout error - matches resilience.go signature
func NewTimeoutError(operation string, duration, timeout time.Duration, err ...error) *TimeoutError {
	te := &TimeoutError{
		Operation:     operation,
		Duration:      duration,
		TimeoutPeriod: timeout,
	}
	if len(err) > 0 {
		te.Err = err[0]
	}
	return te
}

// ResourceExhaustionError with constructor expected by resilience.go
type ResourceExhaustionError struct {
	Resource  string
	Current   int64
	Limit     int64
	Action    string
	Retryable bool
}

func (e *ResourceExhaustionError) Error() string {
	return fmt.Sprintf("resource %s exhausted: %d/%d, action: %s", e.Resource, e.Current, e.Limit, e.Action)
}

func (e *ResourceExhaustionError) Temporary() bool {
	return e.Retryable
}

// NewResourceExhaustionError creates a new resource exhaustion error - matches resilience.go signature
func NewResourceExhaustionError(resource string, current, limit int64, action string, retryable ...bool) *ResourceExhaustionError {
	retry := false
	if len(retryable) > 0 {
		retry = retryable[0]
	}
	return &ResourceExhaustionError{
		Resource:  resource,
		Current:   current,
		Limit:     limit,
		Action:    action,
		Retryable: retry,
	}
}