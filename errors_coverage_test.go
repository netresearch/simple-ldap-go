//go:build !integration

package ldap

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- LDAPError coverage ----------

func TestLDAPError_ErrorWithoutDN(t *testing.T) {
	err := NewLDAPError("Bind", "ldaps://prod.corp.local", errors.New("fail"))
	msg := err.Error()
	// Server should be masked (not test.com)
	assert.Contains(t, msg, "ldap Bind failed on server")
	assert.NotContains(t, msg, "prod.corp.local") // masked

	umsg := err.UnmaskedError()
	assert.Contains(t, umsg, "prod.corp.local")
	assert.NotContains(t, umsg, `for DN`)
}

func TestLDAPError_ErrorWithDN(t *testing.T) {
	err := NewLDAPError("Search", "ldaps://prod.corp.local", errors.New("fail")).
		WithDN("CN=admin,DC=corp,DC=local")
	msg := err.Error()
	assert.Contains(t, msg, "for DN")

	umsg := err.UnmaskedError()
	assert.Contains(t, umsg, "CN=admin,DC=corp,DC=local")
}

func TestLDAPError_Is(t *testing.T) {
	tests := []struct {
		name   string
		target error
		expect bool
	}{
		{
			name:   "same op and code",
			target: &LDAPError{Op: "Search", Code: 32},
			expect: true,
		},
		{
			name:   "different op",
			target: &LDAPError{Op: "Bind", Code: 32},
			expect: false,
		},
		{
			name:   "different code",
			target: &LDAPError{Op: "Search", Code: 49},
			expect: false,
		},
		{
			name:   "not an LDAPError",
			target: errors.New("other"),
			expect: false,
		},
	}

	err := &LDAPError{Op: "Search", Code: 32}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, err.Is(tt.target))
		})
	}
}

// ---------- WrapLDAPError coverage ----------

func TestWrapLDAPError_NilError(t *testing.T) {
	assert.Nil(t, WrapLDAPError("op", "server", nil))
}

func TestWrapLDAPError_ContextErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"context.Canceled", context.Canceled, ErrContextCancelled},
		{"context.DeadlineExceeded", context.DeadlineExceeded, ErrContextDeadlineExceeded},
		{"wrapped ErrContextCancelled", fmt.Errorf("wrap: %w", ErrContextCancelled), ErrContextCancelled},
		{"wrapped ErrContextDeadlineExceeded", fmt.Errorf("wrap: %w", ErrContextDeadlineExceeded), ErrContextDeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := WrapLDAPError("op", "server", tt.err)
			assert.True(t, errors.Is(wrapped, tt.sentinel))
		})
	}
}

func TestWrapLDAPError_NonLDAPError(t *testing.T) {
	baseErr := errors.New("network timeout")
	wrapped := WrapLDAPError("Search", "ldaps://srv", baseErr)
	var ldapErr *LDAPError
	require.True(t, errors.As(wrapped, &ldapErr))
	assert.Equal(t, "Search", ldapErr.Op)
}

// ---------- classifyLDAPError coverage ----------

func TestClassifyLDAPError_AllCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     uint16
		sentinel error
	}{
		{"InvalidCredentials", ldap.LDAPResultInvalidCredentials, ErrInvalidCredentials},
		{"NoSuchObject", ldap.LDAPResultNoSuchObject, ErrObjectNotFound},
		{"ServerDown", ldap.LDAPResultServerDown, ErrConnectionFailed},
		{"Unavailable", ldap.LDAPResultUnavailable, ErrServerUnavailable},
		{"TimeLimitExceeded", ldap.LDAPResultTimeLimitExceeded, ErrTimeoutExceeded},
		{"InvalidDNSyntax", ldap.LDAPResultInvalidDNSyntax, ErrInvalidDN},
		{"Default/Other", ldap.LDAPResultBusy, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ldapErr := &ldap.Error{ResultCode: tt.code, Err: errors.New("test")}
			wrapped := WrapLDAPError("op", "srv", ldapErr)
			var enhanced *LDAPError
			require.True(t, errors.As(wrapped, &enhanced))
			assert.Equal(t, int(tt.code), enhanced.Code)
			if tt.sentinel != nil {
				assert.True(t, errors.Is(enhanced.Err, tt.sentinel))
			}
		})
	}
}

// ---------- Extract functions with non-LDAPError ----------

func TestExtractDN_NonLDAPError(t *testing.T) {
	assert.Equal(t, "", ExtractDN(errors.New("plain")))
}

func TestExtractOperation_NonLDAPError(t *testing.T) {
	assert.Equal(t, "", ExtractOperation(errors.New("plain")))
}

func TestGetErrorContext_NonLDAPError(t *testing.T) {
	assert.Nil(t, GetErrorContext(errors.New("plain")))
}

func TestGetLDAPResultCode_NonLDAPError(t *testing.T) {
	assert.Equal(t, 0, GetLDAPResultCode(errors.New("plain")))
}

// ---------- FormatErrorWithContext coverage ----------

func TestFormatErrorWithContext_NonLDAPError(t *testing.T) {
	err := errors.New("plain error")
	assert.Equal(t, "plain error", FormatErrorWithContext(err))
}

func TestFormatErrorWithContext_NoCode(t *testing.T) {
	err := NewLDAPError("Op", "ldaps://test.com", errors.New("fail"))
	msg := FormatErrorWithContext(err)
	assert.NotContains(t, msg, "LDAP code:")
	assert.Contains(t, msg, "occurred at:")
}

func TestFormatErrorWithContext_ZeroTimestamp(t *testing.T) {
	err := &LDAPError{
		Op:      "Op",
		Server:  "ldaps://test.com",
		Err:     errors.New("fail"),
		Context: make(map[string]any),
	}
	msg := FormatErrorWithContext(err)
	assert.NotContains(t, msg, "occurred at:")
}

func TestFormatErrorWithContext_EmptyContext(t *testing.T) {
	err := NewLDAPError("Op", "ldaps://test.com", errors.New("fail")).
		WithCode(49)
	msg := FormatErrorWithContext(err)
	assert.Contains(t, msg, "LDAP code: 49")
	assert.NotContains(t, msg, "Context:")
}

func TestFormatErrorWithContext_SensitiveContextKeys(t *testing.T) {
	err := NewLDAPError("Op", "ldaps://test.com", errors.New("fail")).
		WithContext("password", "supersecret123").
		WithContext("token", "abc123token").
		WithContext("safe_key", "visible_value")
	msg := FormatErrorWithContext(err)
	assert.Contains(t, msg, "Context:")
	assert.NotContains(t, msg, "supersecret123")
	assert.Contains(t, msg, "visible_value")
}

// ---------- GetErrorSeverity coverage ----------

func TestGetErrorSeverity_UnknownError(t *testing.T) {
	err := errors.New("something unknown")
	assert.Equal(t, SeverityError, GetErrorSeverity(err))
}

func TestGetErrorSeverity_ValidationError(t *testing.T) {
	// Validation errors should fall through to default (SeverityError)
	assert.Equal(t, SeverityError, GetErrorSeverity(ErrInvalidDN))
}

// ---------- IsRetryable coverage ----------

func TestIsRetryable_WithRetryableInterface(t *testing.T) {
	retryable := WithRetryInfo(errors.New("temp"), true)
	assert.True(t, IsRetryable(retryable))

	nonRetryable := WithRetryInfo(errors.New("perm"), false)
	assert.False(t, IsRetryable(nonRetryable))
}

func TestIsRetryable_UnknownError(t *testing.T) {
	err := errors.New("something random")
	assert.False(t, IsRetryable(err))
}

// ---------- IsValidationErrorCode ----------

func TestIsValidationErrorCode(t *testing.T) {
	ve := NewValidationError("email", "bad", "invalid format", "INVALID_FORMAT")
	assert.True(t, IsValidationErrorCode(ve, "INVALID_FORMAT"))
	assert.False(t, IsValidationErrorCode(ve, "OTHER_CODE"))
	assert.False(t, IsValidationErrorCode(errors.New("plain"), "INVALID_FORMAT"))
}

// ---------- MultiError ----------

func TestMultiError_Error(t *testing.T) {
	tests := []struct {
		name     string
		errs     []error
		expected string
	}{
		{
			name:     "no errors",
			errs:     nil,
			expected: "no errors",
		},
		{
			name:     "single error",
			errs:     []error{errors.New("one")},
			expected: "one",
		},
		{
			name:     "multiple errors",
			errs:     []error{errors.New("first"), errors.New("second")},
			expected: "multiple errors: first; second",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			me := NewMultiError(tt.errs...)
			assert.Equal(t, tt.expected, me.Error())
		})
	}
}

func TestMultiError_HasErrors(t *testing.T) {
	me := NewMultiError()
	assert.False(t, me.HasErrors())

	me.Add(errors.New("err"))
	assert.True(t, me.HasErrors())
}

func TestMultiError_AddNil(t *testing.T) {
	me := NewMultiError()
	me.Add(nil)
	assert.False(t, me.HasErrors())
}

func TestMultiError_Unwrap(t *testing.T) {
	e1 := errors.New("one")
	e2 := errors.New("two")
	me := NewMultiError(e1, e2)
	unwrapped := me.Unwrap()
	assert.Len(t, unwrapped, 2)
	assert.Equal(t, e1, unwrapped[0])
	assert.Equal(t, e2, unwrapped[1])
}

func TestNewMultiError_WithNils(t *testing.T) {
	me := NewMultiError(nil, errors.New("real"), nil)
	assert.Len(t, me.Errors, 1)
}

// ---------- maskContextValue ----------

func TestMaskContextValue(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    any
		masked   bool
	}{
		{"sensitive string key", "password", "mysecret", true},
		{"sensitive key - username", "username", "admin", true},
		{"sensitive key - dn", "dn", "CN=admin,DC=corp", true},
		{"sensitive key - token", "token", "abc123", true},
		{"sensitive key - server", "server", "ldaps://corp.local", true},
		{"sensitive key - credential", "credential", "cred123", true},
		{"sensitive key - secret", "secret", "s3cr3t", true},
		{"non-sensitive key", "filter", "(cn=test)", false},
		{"sensitive key non-string value", "password", 12345, false},
		{"case insensitive", "Password", "test12345678", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskContextValue(tt.key, tt.value)
			if tt.masked {
				assert.NotEqual(t, tt.value, result, "expected value to be masked")
			} else {
				assert.Equal(t, tt.value, result, "expected value to not be masked")
			}
		})
	}
}

// ---------- TimeoutError ----------

func TestTimeoutError_Error(t *testing.T) {
	te := &TimeoutError{
		Operation:     "Search",
		Duration:      5 * time.Second,
		TimeoutPeriod: 3 * time.Second,
	}
	msg := te.Error()
	assert.Contains(t, msg, "Search")
	assert.Contains(t, msg, "timed out")
}

func TestNewTimeoutError(t *testing.T) {
	// Without wrapped error
	te := NewTimeoutError("Bind", 5*time.Second, 3*time.Second)
	assert.Equal(t, "Bind", te.Operation)
	assert.Equal(t, 5*time.Second, te.Duration)
	assert.Equal(t, 3*time.Second, te.TimeoutPeriod)
	assert.Nil(t, te.Err)
	assert.True(t, te.Timeout())
	assert.True(t, te.Temporary())

	// With wrapped error
	baseErr := errors.New("deadline")
	te2 := NewTimeoutError("Search", 10*time.Second, 8*time.Second, baseErr)
	assert.Equal(t, baseErr, te2.Err)
	assert.True(t, errors.Is(te2, baseErr))
}

// ---------- ResourceExhaustionError ----------

func TestNewResourceExhaustionError(t *testing.T) {
	// Without retryable
	re := NewResourceExhaustionError("connections", 100, 100, "reject")
	assert.Equal(t, "connections", re.Resource)
	assert.Equal(t, int64(100), re.Current)
	assert.Equal(t, int64(100), re.Limit)
	assert.Equal(t, "reject", re.Action)
	assert.False(t, re.Retryable)
	assert.False(t, re.Temporary())
	assert.Nil(t, re.Unwrap())
	assert.Contains(t, re.Error(), "connections")

	// With retryable=true
	re2 := NewResourceExhaustionError("pool", 50, 50, "wait", true)
	assert.True(t, re2.Retryable)
	assert.True(t, re2.Temporary())
}

// ---------- ValidationError.Error ----------

func TestValidationError_Error(t *testing.T) {
	ve := NewValidationError("email", "bad@", "invalid format", "INVALID")
	msg := ve.Error()
	assert.Contains(t, msg, "validation failed for field email")
	assert.Contains(t, msg, "invalid format")

	// With sensitive field
	ve2 := NewValidationError("password", "secret123", "too weak", "WEAK")
	msg2 := ve2.Error()
	assert.Contains(t, msg2, "validation failed for field password")
	assert.NotContains(t, msg2, "secret123") // should be masked
}

// ---------- error_helpers.go ----------

func TestAuthenticationError(t *testing.T) {
	t.Run("with non-LDAPError", func(t *testing.T) {
		err := authenticationError("Bind", "user1", errors.New("bad password"))
		assert.Contains(t, err.Error(), "authentication failed for user1")
		var ldapErr *LDAPError
		require.True(t, errors.As(err, &ldapErr))
		assert.Equal(t, "Bind", ldapErr.Op)
	})

	t.Run("with LDAPError", func(t *testing.T) {
		ldapErr := NewLDAPError("Auth", "ldaps://test.com", errors.New("invalid"))
		err := authenticationError("Auth", "user2", ldapErr)
		assert.Contains(t, err.Error(), "authentication failed for user2")
	})
}

func TestConnectionError(t *testing.T) {
	err := connectionError("Search", "user lookup", errors.New("timeout"))
	assert.Contains(t, err.Error(), "failed to get connection for Search user lookup")
}

// ---------- isLDAPCodeMatch with LDAP error codes ----------

func TestIsAuthenticationError_WithLDAPCodes(t *testing.T) {
	tests := []struct {
		name   string
		code   uint16
		expect bool
	}{
		{"InvalidCredentials code", ldap.LDAPResultInvalidCredentials, true},
		{"ConstraintViolation code", ldap.LDAPResultConstraintViolation, true},
		{"NoSuchObject code", ldap.LDAPResultNoSuchObject, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewLDAPError("op", "srv", errors.New("test")).WithCode(int(tt.code))
			assert.Equal(t, tt.expect, IsAuthenticationError(err))
		})
	}
}

func TestIsConnectionError_WithLDAPCodes(t *testing.T) {
	tests := []struct {
		name   string
		code   uint16
		expect bool
	}{
		{"ServerDown code", ldap.LDAPResultServerDown, true},
		{"Unavailable code", ldap.LDAPResultUnavailable, true},
		{"Success code", ldap.LDAPResultSuccess, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewLDAPError("op", "srv", errors.New("test")).WithCode(int(tt.code))
			assert.Equal(t, tt.expect, IsConnectionError(err))
		})
	}
}

func TestIsNotFoundError_WithLDAPCodes(t *testing.T) {
	err := NewLDAPError("op", "srv", errors.New("test")).WithCode(int(ldap.LDAPResultNoSuchObject))
	assert.True(t, IsNotFoundError(err))
}

func TestIsValidationError_WithLDAPCodes(t *testing.T) {
	tests := []struct {
		name   string
		code   uint16
		expect bool
	}{
		{"InvalidDNSyntax", ldap.LDAPResultInvalidDNSyntax, true},
		{"FilterError", ldap.LDAPResultFilterError, true},
		{"Other", ldap.LDAPResultBusy, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewLDAPError("op", "srv", errors.New("test")).WithCode(int(tt.code))
			assert.Equal(t, tt.expect, IsValidationError(err))
		})
	}
}

// ---------- CircuitBreakerError ----------

func TestCircuitBreakerError(t *testing.T) {
	cbe := &CircuitBreakerError{
		State:       "open",
		Failures:    5,
		LastFailure: time.Now(),
		NextRetry:   time.Now().Add(time.Minute),
	}
	assert.Contains(t, cbe.Error(), "circuit breaker open")
	assert.Contains(t, cbe.Error(), "failures: 5")
	assert.Nil(t, cbe.Unwrap())
}

// ---------- GetErrorSeverity comprehensive ----------

func TestGetErrorSeverity_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		severity ErrorSeverity
	}{
		{"context cancelled", ErrContextCancelled, SeverityInfo},
		{"context deadline", ErrContextDeadlineExceeded, SeverityInfo},
		{"connection failed", ErrConnectionFailed, SeverityCritical},
		{"server unavailable", ErrServerUnavailable, SeverityCritical},
		{"invalid credentials", ErrInvalidCredentials, SeverityError},
		{"account locked", ErrAccountLocked, SeverityError},
		{"account disabled", ErrAccountDisabled, SeverityError},
		{"password expired", ErrPasswordExpired, SeverityError},
		{"user not found", ErrUserNotFound, SeverityWarning},
		{"group not found", ErrGroupNotFound, SeverityWarning},
		{"object not found", ErrObjectNotFound, SeverityWarning},
		{"unknown error", errors.New("random"), SeverityError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.severity, GetErrorSeverity(tt.err))
		})
	}
}
