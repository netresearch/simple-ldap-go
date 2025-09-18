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

// Unwrap implements the Go 1.13+ error unwrapping interface.
func (e *LDAPError) Unwrap() error {
	return e.Err
}

// Is implements the Go 1.13+ error comparison interface for compatibility with errors.Is.
func (e *LDAPError) Is(target error) bool {
	if ldapErr, ok := target.(*LDAPError); ok {
		return e.Op == ldapErr.Op && e.Code == ldapErr.Code
	}
	return errors.Is(e.Err, target)
}

// Sentinel errors for common LDAP operation failures.
// These provide a stable API for error classification while maintaining backward compatibility.
var (
	// Connection errors
	ErrConnectionFailed  = errors.New("ldap: connection failed")
	ErrServerUnavailable = errors.New("ldap: server unavailable")

	// Authentication errors
	ErrAuthenticationFailed = errors.New("ldap: authentication failed")
	ErrInvalidCredentials   = errors.New("ldap: invalid credentials")
	ErrAccountDisabled      = errors.New("ldap: account disabled")
	ErrAccountLocked        = errors.New("ldap: account locked")
	ErrPasswordExpired      = errors.New("ldap: password expired")

	// Authorization errors
	ErrInsufficientAccess = errors.New("ldap: insufficient access")
	ErrPermissionDenied   = errors.New("ldap: permission denied")

	// Data validation errors
	ErrInvalidDN        = errors.New("ldap: invalid distinguished name")
	ErrInvalidFilter    = errors.New("ldap: invalid filter")
	ErrInvalidAttribute = errors.New("ldap: invalid attribute")
	ErrMalformedEntry   = errors.New("ldap: malformed entry")

	// Object existence errors
	ErrObjectNotFound      = errors.New("ldap: object not found")
	ErrObjectExists        = errors.New("ldap: object already exists")
	ErrConstraintViolation = errors.New("ldap: constraint violation")

	// Protocol errors
	ErrProtocolError        = errors.New("ldap: protocol error")
	ErrUnsupportedOperation = errors.New("ldap: unsupported operation")
	ErrTimeout              = errors.New("ldap: operation timeout")

	// Context errors
	ErrContextCancelled        = errors.New("ldap: context cancelled")
	ErrContextDeadlineExceeded = errors.New("ldap: context deadline exceeded")
)

// NewLDAPError creates a new enhanced LDAP error with the specified context.
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

	// Create enhanced error for other types
	return NewLDAPError(op, server, err)
}

// classifyLDAPError analyzes LDAP result codes and classifies errors appropriately.
func classifyLDAPError(op, server string, ldapErr *ldap.Error) error {
	ldapError := NewLDAPError(op, server, ldapErr).WithCode(int(ldapErr.ResultCode))

	// Classify based on LDAP result code and preserve the original LDAP code
	switch ldapErr.ResultCode {
	// Authentication failures
	case ldap.LDAPResultInvalidCredentials:
		return ldapError.WithContext("error_type", "authentication")
	case ldap.LDAPResultInsufficientAccessRights:
		return ldapError.WithContext("error_type", "authorization")
	case ldap.LDAPResultUnwillingToPerform:
		// Often indicates account disabled or policy violations
		return ldapError.WithContext("error_type", "account_disabled")

	// Object existence
	case ldap.LDAPResultNoSuchObject:
		return ldapError.WithContext("error_type", "not_found")
	case ldap.LDAPResultEntryAlreadyExists:
		return ldapError.WithContext("error_type", "already_exists")

	// Data validation
	case ldap.LDAPResultInvalidDNSyntax:
		return ldapError.WithContext("error_type", "invalid_dn")
	case ldap.LDAPResultInvalidAttributeSyntax:
		return ldapError.WithContext("error_type", "invalid_attribute")
	case ldap.LDAPResultConstraintViolation:
		return ldapError.WithContext("error_type", "constraint_violation")

	// Connection issues
	case ldap.LDAPResultUnavailable, ldap.LDAPResultServerDown:
		return ldapError.WithContext("error_type", "server_unavailable")
	case ldap.LDAPResultTimeLimitExceeded:
		return ldapError.WithContext("error_type", "timeout")
	case ldap.LDAPResultBusy:
		return ldapError.WithContext("error_type", "server_busy")

	// Protocol errors
	case ldap.LDAPResultProtocolError:
		return ldapError.WithContext("error_type", "protocol_error")
	case ldap.LDAPResultOperationsError:
		return ldapError.WithContext("error_type", "unsupported_operation")

	default:
		// Return the enhanced error for unknown result codes
		return ldapError.WithContext("error_type", "unknown")
	}
}

// Error Classification Helper Functions

// IsAuthenticationError checks if the error is related to authentication failure.
func IsAuthenticationError(err error) bool {
	if errors.Is(err, ErrAuthenticationFailed) ||
		errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrAccountDisabled) ||
		errors.Is(err, ErrAccountLocked) ||
		errors.Is(err, ErrPasswordExpired) {
		return true
	}

	// Check for LDAP error with authentication-related result codes
	var enhancedErr *LDAPError
	if errors.As(err, &enhancedErr) {
		switch enhancedErr.Code {
		case int(ldap.LDAPResultInvalidCredentials),
			int(ldap.LDAPResultInsufficientAccessRights),
			int(ldap.LDAPResultUnwillingToPerform):
			return true
		}
		if errorType, exists := enhancedErr.Context["error_type"]; exists {
			switch errorType {
			case "authentication", "authorization", "account_disabled":
				return true
			}
		}
	}

	return false
}

// IsConnectionError checks if the error is related to connection issues.
func IsConnectionError(err error) bool {
	return errors.Is(err, ErrConnectionFailed) ||
		errors.Is(err, ErrPoolExhausted) ||
		errors.Is(err, ErrServerUnavailable) ||
		errors.Is(err, ErrTimeout)
}

// IsNotFoundError checks if the error indicates an object was not found.
func IsNotFoundError(err error) bool {
	if errors.Is(err, ErrObjectNotFound) ||
		errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrGroupNotFound) ||
		errors.Is(err, ErrComputerNotFound) {
		return true
	}

	// Check for LDAP error with not-found result codes
	var enhancedErr *LDAPError
	if errors.As(err, &enhancedErr) {
		if enhancedErr.Code == int(ldap.LDAPResultNoSuchObject) {
			return true
		}
		if errorType, exists := enhancedErr.Context["error_type"]; exists {
			return errorType == "not_found"
		}
	}

	return false
}

// IsValidationError checks if the error is related to data validation.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidDN) ||
		errors.Is(err, ErrInvalidFilter) ||
		errors.Is(err, ErrInvalidAttribute) ||
		errors.Is(err, ErrMalformedEntry)
}

// IsContextError checks if the error is related to context cancellation or timeout.
func IsContextError(err error) bool {
	return errors.Is(err, ErrContextCancelled) ||
		errors.Is(err, ErrContextDeadlineExceeded)
}

// GetLDAPResultCode extracts the LDAP result code from an error, if available.
// Returns -1 if no LDAP result code is found.
func GetLDAPResultCode(err error) int {
	// Check for direct LDAP error
	if ldapErr, ok := err.(*ldap.Error); ok {
		return int(ldapErr.ResultCode)
	}

	// Check for wrapped enhanced LDAP error
	var enhancedErr *LDAPError
	if errors.As(err, &enhancedErr) {
		return enhancedErr.Code
	}

	return -1
}

// ExtractDN extracts the distinguished name from an error context, if available.
// Returns an empty string if no DN is found.
func ExtractDN(err error) string {
	var enhancedErr *LDAPError
	if errors.As(err, &enhancedErr) {
		return enhancedErr.DN
	}
	return ""
}

// ExtractOperation extracts the operation name from an error context, if available.
// Returns an empty string if no operation is found.
func ExtractOperation(err error) string {
	var enhancedErr *LDAPError
	if errors.As(err, &enhancedErr) {
		return enhancedErr.Op
	}
	return ""
}

// GetErrorContext extracts the context information from an enhanced error.
// Returns nil if the error is not an enhanced LDAP error.
// This method is thread-safe.
func GetErrorContext(err error) map[string]interface{} {
	var enhancedErr *LDAPError
	if errors.As(err, &enhancedErr) {
		enhancedErr.mu.RLock()
		defer enhancedErr.mu.RUnlock()
		// Return a copy to prevent external mutation
		contextCopy := make(map[string]interface{})
		for k, v := range enhancedErr.Context {
			contextCopy[k] = v
		}
		return contextCopy
	}
	return nil
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

// GetErrorSeverity determines the severity level of an error based on its type and context.
func GetErrorSeverity(err error) ErrorSeverity {
	if IsConnectionError(err) {
		return SeverityCritical
	}

	if IsAuthenticationError(err) {
		return SeverityError
	}

	if IsNotFoundError(err) {
		return SeverityWarning
	}

	if IsValidationError(err) {
		return SeverityWarning
	}

	if IsContextError(err) {
		return SeverityInfo
	}

	// Check LDAP result codes for severity
	code := GetLDAPResultCode(err)
	switch code {
	case int(ldap.LDAPResultServerDown), int(ldap.LDAPResultUnavailable):
		return SeverityCritical
	case int(ldap.LDAPResultInvalidCredentials), int(ldap.LDAPResultInsufficientAccessRights):
		return SeverityError
	case int(ldap.LDAPResultNoSuchObject):
		return SeverityWarning
	default:
		return SeverityError
	}
}

// RetryableError indicates whether an error condition might be resolved by retrying the operation.
type RetryableError interface {
	error
	IsRetryable() bool
}

// retryableError wraps an error with retry information.
type retryableError struct {
	err       error
	retryable bool
}

func (r *retryableError) Error() string {
	return r.err.Error()
}

func (r *retryableError) Unwrap() error {
	return r.err
}

func (r *retryableError) IsRetryable() bool {
	return r.retryable
}

// WithRetryInfo wraps an error with information about whether it's retryable.
func WithRetryInfo(err error, retryable bool) RetryableError {
	return &retryableError{err: err, retryable: retryable}
}

// IsRetryable determines if an error condition might be resolved by retrying the operation.
func IsRetryable(err error) bool {
	// Check for explicit retry information
	if retryErr, ok := err.(RetryableError); ok {
		return retryErr.IsRetryable()
	}

	// Determine retry capability based on error type
	if IsConnectionError(err) && !errors.Is(err, ErrPoolExhausted) {
		return true // Connection issues might be temporary
	}

	if IsContextError(err) {
		return false // Context errors should not be retried
	}

	// Check LDAP result codes
	code := GetLDAPResultCode(err)
	switch code {
	case int(ldap.LDAPResultBusy), int(ldap.LDAPResultUnavailable):
		return true // Server might recover
	case int(ldap.LDAPResultTimeLimitExceeded):
		return true // Might succeed with different timing
	case int(ldap.LDAPResultInvalidCredentials), int(ldap.LDAPResultInsufficientAccessRights):
		return false // Authentication/authorization issues won't resolve by retrying
	case int(ldap.LDAPResultNoSuchObject), int(ldap.LDAPResultEntryAlreadyExists):
		return false // Object existence state won't change
	default:
		return false // Conservative approach for unknown errors
	}
}

// Legacy error compatibility helpers to maintain backward compatibility
func isLDAPErrorCode(err error, code uint16) bool {
	ldapCode := GetLDAPResultCode(err)
	return ldapCode == int(code)
}

// IsInvalidCredentialsError checks if error is specifically about invalid credentials
func IsInvalidCredentialsError(err error) bool {
	return errors.Is(err, ErrInvalidCredentials) ||
		isLDAPErrorCode(err, ldap.LDAPResultInvalidCredentials)
}

// IsInsufficientAccessError checks if error is about insufficient access rights
func IsInsufficientAccessError(err error) bool {
	return errors.Is(err, ErrInsufficientAccess) ||
		isLDAPErrorCode(err, ldap.LDAPResultInsufficientAccessRights)
}

// IsNoSuchObjectError checks if error indicates object doesn't exist
func IsNoSuchObjectError(err error) bool {
	return IsNotFoundError(err) ||
		isLDAPErrorCode(err, ldap.LDAPResultNoSuchObject)
}

// IsConstraintViolationError checks if error is about constraint violations
func IsConstraintViolationError(err error) bool {
	return errors.Is(err, ErrConstraintViolation) ||
		isLDAPErrorCode(err, ldap.LDAPResultConstraintViolation)
}

// ValidationError represents a validation error with detailed field information.
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
	Err     error
}

// Error implements the error interface.
// Sensitive field values are masked to prevent data leakage.
func (v *ValidationError) Error() string {
	if v.Field != "" {
		// Mask potentially sensitive field values
		maskedValue := maskContextValue(v.Field, v.Value)
		if maskedValue != v.Value {
			// Field was considered sensitive, include masked value in message
			return fmt.Sprintf("validation failed for field %q (value: %v): %s", v.Field, maskedValue, v.Message)
		}
		return fmt.Sprintf("validation failed for field %q: %s", v.Field, v.Message)
	}
	return fmt.Sprintf("validation failed: %s", v.Message)
}

// Unwrap implements error unwrapping.
func (v *ValidationError) Unwrap() error {
	return v.Err
}

// WithDetail adds detailed field information to a validation error.
func (v *ValidationError) WithDetail(field string, value interface{}) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: v.Message,
		Err:     v.Err,
	}
}

// ErrInvalidSecurityConfig indicates invalid security configuration.
var ErrInvalidSecurityConfig = &ValidationError{
	Message: "invalid security configuration",
}

// NewValidationError creates a new validation error.
func NewValidationError(field string, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// MultiError represents multiple errors that occurred during an operation.
type MultiError struct {
	Errors []error
	Op     string
}

// Error implements the error interface.
func (m *MultiError) Error() string {
	if len(m.Errors) == 0 {
		return "no errors"
	}

	if len(m.Errors) == 1 {
		if m.Op != "" {
			return fmt.Sprintf("%s: %v", m.Op, m.Errors[0])
		}
		return m.Errors[0].Error()
	}

	var msgs []string
	for _, err := range m.Errors {
		msgs = append(msgs, err.Error())
	}

	if m.Op != "" {
		return fmt.Sprintf("%s: multiple errors: %s", m.Op, strings.Join(msgs, "; "))
	}
	return fmt.Sprintf("multiple errors: %s", strings.Join(msgs, "; "))
}

// Unwrap implements error unwrapping for the first error.
func (m *MultiError) Unwrap() error {
	if len(m.Errors) == 0 {
		return nil
	}
	return m.Errors[0]
}

// Is implements error comparison.
func (m *MultiError) Is(target error) bool {
	for _, err := range m.Errors {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// Add adds an error to the multi-error.
func (m *MultiError) Add(err error) {
	if err != nil {
		m.Errors = append(m.Errors, err)
	}
}

// HasErrors returns true if there are any errors.
func (m *MultiError) HasErrors() bool {
	return len(m.Errors) > 0
}

// ErrorOrNil returns the MultiError if it has errors, otherwise nil.
func (m *MultiError) ErrorOrNil() error {
	if m.HasErrors() {
		return m
	}
	return nil
}

// NewMultiError creates a new MultiError.
func NewMultiError(op string) *MultiError {
	return &MultiError{
		Errors: make([]error, 0),
		Op:     op,
	}
}

// JoinErrors joins multiple errors into a MultiError.
func JoinErrors(op string, errors ...error) error {
	multiErr := NewMultiError(op)
	for _, err := range errors {
		multiErr.Add(err)
	}
	return multiErr.ErrorOrNil()
}

// ConfigError represents configuration-related errors.
type ConfigError struct {
	Field   string
	Value   interface{}
	Message string
}

// Error implements the error interface.
func (c *ConfigError) Error() string {
	if c.Field != "" {
		return fmt.Sprintf("configuration error in field %q: %s", c.Field, c.Message)
	}
	return fmt.Sprintf("configuration error: %s", c.Message)
}

// NewConfigError creates a new configuration error.
func NewConfigError(field, message string) *ConfigError {
	return &ConfigError{
		Field:   field,
		Message: message,
	}
}

// OperationError represents errors that occur during LDAP operations.
type OperationError struct {
	Operation string
	DN        string
	Server    string
	Err       error
	Retryable bool
	Code      int
}

// Error implements the error interface.
// Sensitive information is masked to prevent data leakage.
func (o *OperationError) Error() string {
	maskedServer := maskSensitiveData(o.Server)
	if o.DN != "" {
		maskedDN := maskSensitiveData(o.DN)
		return fmt.Sprintf("operation %s failed for DN %q on server %q: %v", o.Operation, maskedDN, maskedServer, o.Err)
	}
	return fmt.Sprintf("operation %s failed on server %q: %v", o.Operation, maskedServer, o.Err)
}

// Unwrap implements error unwrapping.
func (o *OperationError) Unwrap() error {
	return o.Err
}

// IsRetryable implements the RetryableError interface.
func (o *OperationError) IsRetryable() bool {
	return o.Retryable
}

// NewOperationError creates a new operation error.
func NewOperationError(operation, dn, server string, err error) *OperationError {
	retryable := IsRetryable(err)
	code := GetLDAPResultCode(err)

	return &OperationError{
		Operation: operation,
		DN:        dn,
		Server:    server,
		Err:       err,
		Retryable: retryable,
		Code:      code,
	}
}

// Security utility functions for masking sensitive data in error messages
// Note: maskSensitiveData function is defined in utils.go

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

// Error Recovery and Graceful Degradation Mechanisms

// RecoveryStrategy represents different error recovery approaches
type RecoveryStrategy int

const (
	RecoveryRetry RecoveryStrategy = iota
	RecoveryFallback
	RecoveryDegrade
	RecoveryFail
)

// String returns the string representation of the recovery strategy
func (r RecoveryStrategy) String() string {
	switch r {
	case RecoveryRetry:
		return "RETRY"
	case RecoveryFallback:
		return "FALLBACK"
	case RecoveryDegrade:
		return "DEGRADE"
	case RecoveryFail:
		return "FAIL"
	default:
		return "UNKNOWN"
	}
}

// RecoveryAction represents an action that can be taken to recover from an error
type RecoveryAction struct {
	Strategy    RecoveryStrategy
	MaxAttempts int
	Backoff     time.Duration
	Description string
	Handler     func() error
}

// RecoverableError extends the error interface with recovery capabilities
type RecoverableError interface {
	error
	GetRecoveryActions() []RecoveryAction
	GetSeverity() ErrorSeverity
	CanRecover() bool
}

// enhancedRecoverableError implements RecoverableError
type enhancedRecoverableError struct {
	err             error
	recoveryActions []RecoveryAction
	severity        ErrorSeverity
}

func (e *enhancedRecoverableError) Error() string {
	return e.err.Error()
}

func (e *enhancedRecoverableError) Unwrap() error {
	return e.err
}

func (e *enhancedRecoverableError) GetRecoveryActions() []RecoveryAction {
	return e.recoveryActions
}

func (e *enhancedRecoverableError) GetSeverity() ErrorSeverity {
	return e.severity
}

func (e *enhancedRecoverableError) CanRecover() bool {
	return len(e.recoveryActions) > 0
}

// WithRecovery wraps an error with recovery capabilities
func WithRecovery(err error, actions ...RecoveryAction) RecoverableError {
	return &enhancedRecoverableError{
		err:             err,
		recoveryActions: actions,
		severity:        GetErrorSeverity(err),
	}
}

// GetRecoveryStrategy determines the best recovery strategy for an error
func GetRecoveryStrategy(err error) RecoveryStrategy {
	if IsConnectionError(err) {
		// Connection errors can often be retried
		return RecoveryRetry
	}

	if IsAuthenticationError(err) {
		// Authentication errors usually require different credentials
		return RecoveryFail
	}

	if IsNotFoundError(err) {
		// Not found errors might benefit from fallback searches
		return RecoveryFallback
	}

	if IsValidationError(err) {
		// Validation errors need input correction
		return RecoveryFail
	}

	if IsContextError(err) {
		// Context errors should not be retried
		return RecoveryFail
	}

	// Check LDAP result codes for more specific strategies
	code := GetLDAPResultCode(err)
	switch code {
	case int(ldap.LDAPResultBusy), int(ldap.LDAPResultUnavailable):
		return RecoveryRetry
	case int(ldap.LDAPResultTimeLimitExceeded):
		return RecoveryDegrade // Maybe with simplified search
	case int(ldap.LDAPResultSizeLimitExceeded):
		return RecoveryDegrade // Reduce scope or pagination
	case int(ldap.LDAPResultInvalidCredentials):
		return RecoveryFail
	default:
		return RecoveryRetry
	}
}

// CircuitBreakerError represents errors related to circuit breaker functionality
type CircuitBreakerError struct {
	State       string
	Failures    int
	LastFailure time.Time
	NextRetry   time.Time
}

func (c *CircuitBreakerError) Error() string {
	return fmt.Sprintf("circuit breaker %s: %d failures, next retry at %s",
		c.State, c.Failures, c.NextRetry.Format(time.RFC3339))
}

// TimeoutError represents timeout-related errors with context
type TimeoutError struct {
	Operation string
	Timeout   time.Duration
	Elapsed   time.Duration
	Err       error
}

func (t *TimeoutError) Error() string {
	return fmt.Sprintf("operation %s timed out after %v (elapsed: %v): %v",
		t.Operation, t.Timeout, t.Elapsed, t.Err)
}

func (t *TimeoutError) Unwrap() error {
	return t.Err
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(operation string, timeout, elapsed time.Duration, err error) *TimeoutError {
	return &TimeoutError{
		Operation: operation,
		Timeout:   timeout,
		Elapsed:   elapsed,
		Err:       err,
	}
}

// ResourceExhaustionError represents resource exhaustion scenarios
type ResourceExhaustionError struct {
	Resource    string
	Current     int64
	Limit       int64
	Suggestion  string
	Recoverable bool
}

func (r *ResourceExhaustionError) Error() string {
	return fmt.Sprintf("resource %s exhausted: %d/%d - %s",
		r.Resource, r.Current, r.Limit, r.Suggestion)
}

func (r *ResourceExhaustionError) IsRetryable() bool {
	return r.Recoverable
}

// NewResourceExhaustionError creates a new resource exhaustion error
func NewResourceExhaustionError(resource string, current, limit int64, suggestion string, recoverable bool) *ResourceExhaustionError {
	return &ResourceExhaustionError{
		Resource:    resource,
		Current:     current,
		Limit:       limit,
		Suggestion:  suggestion,
		Recoverable: recoverable,
	}
}

// HealthCheckError represents health check failures with recovery suggestions
type HealthCheckError struct {
	Component   string
	CheckType   string
	Expected    interface{}
	Actual      interface{}
	Suggestion  string
	Recoverable bool
}

func (h *HealthCheckError) Error() string {
	return fmt.Sprintf("health check failed for %s (%s): expected %v, got %v - %s",
		h.Component, h.CheckType, h.Expected, h.Actual, h.Suggestion)
}

func (h *HealthCheckError) IsRetryable() bool {
	return h.Recoverable
}

// NewHealthCheckError creates a new health check error
func NewHealthCheckError(component, checkType string, expected, actual interface{}, suggestion string, recoverable bool) *HealthCheckError {
	return &HealthCheckError{
		Component:   component,
		CheckType:   checkType,
		Expected:    expected,
		Actual:      actual,
		Suggestion:  suggestion,
		Recoverable: recoverable,
	}
}

// GracefulDegradationError represents situations where functionality is reduced but operation continues
type GracefulDegradationError struct {
	OriginalOperation string
	DegradedOperation string
	Reason           string
	Impact           string
	Duration         time.Duration
}

func (g *GracefulDegradationError) Error() string {
	return fmt.Sprintf("graceful degradation: %s -> %s (%s) - impact: %s",
		g.OriginalOperation, g.DegradedOperation, g.Reason, g.Impact)
}

// NewGracefulDegradationError creates a new graceful degradation error
func NewGracefulDegradationError(original, degraded, reason, impact string, duration time.Duration) *GracefulDegradationError {
	return &GracefulDegradationError{
		OriginalOperation: original,
		DegradedOperation: degraded,
		Reason:           reason,
		Impact:           impact,
		Duration:         duration,
	}
}

// Error Recovery Helper Functions

// ExecuteWithGracefulDegradation attempts an operation and falls back to degraded mode on failure
func ExecuteWithGracefulDegradation(primary func() error, fallback func() error, degradationInfo string) error {
	err := primary()
	if err == nil {
		return nil
	}

	// Check if graceful degradation is appropriate
	if !IsRetryable(err) && !IsConnectionError(err) {
		return err
	}

	fallbackErr := fallback()
	if fallbackErr == nil {
		return NewGracefulDegradationError("primary_operation", "fallback_operation", err.Error(), degradationInfo, 0)
	}

	// Both primary and fallback failed
	return fmt.Errorf("operation failed and fallback also failed: primary=%w, fallback=%v", err, fallbackErr)
}

// RecoverFromError attempts to recover from an error using available strategies
func RecoverFromError(err error, maxAttempts int) error {
	if err == nil {
		return nil
	}

	// Check if this is a recoverable error
	if recoverable, ok := err.(RecoverableError); ok && recoverable.CanRecover() {
		actions := recoverable.GetRecoveryActions()

		for _, action := range actions {
			for attempt := 0; attempt < action.MaxAttempts && attempt < maxAttempts; attempt++ {
				if action.Handler != nil {
					if recoveryErr := action.Handler(); recoveryErr == nil {
						return nil // Recovery successful
					}
				}

				// Wait before next attempt if specified
				if action.Backoff > 0 && attempt < action.MaxAttempts-1 {
					time.Sleep(action.Backoff)
				}
			}
		}
	}

	// No recovery possible or all recovery attempts failed
	return err
}
