# Enhanced Error Handling in simple-ldap-go

This document describes the enhanced error handling system implemented in simple-ldap-go, which provides rich error context, proper error classification, and improved debugging capabilities.

## Overview

The enhanced error handling system uses Go 1.13+ error wrapping features to provide:

- **Rich Error Context**: Errors include operation names, distinguished names, server information, and additional context
- **Proper Classification**: Errors are automatically classified by type (authentication, connection, validation, etc.)
- **LDAP Result Code Preservation**: Original LDAP result codes are preserved for detailed debugging
- **Backward Compatibility**: Existing error checking with `errors.Is()` continues to work
- **Retry Capability Detection**: Automatic detection of whether errors might be resolved by retrying
- **Severity Classification**: Errors are classified by severity for appropriate logging and alerting

## Enhanced Error Types

### LDAPError Structure

```go
type LDAPError struct {
    Op        string                 // Operation name (e.g., "FindUserBySAMAccountName")
    DN        string                 // Distinguished Name involved
    Server    string                 // LDAP server URL
    Code      int                    // LDAP result code (if applicable)
    Err       error                  // Underlying error
    Context   map[string]interface{} // Additional context
    Timestamp time.Time              // When error occurred
}
```

### Sentinel Errors

The following sentinel errors are available for classification:

#### Connection Errors
- `ErrConnectionFailed`: General connection failure
- `ErrServerUnavailable`: LDAP server unavailable
- `ErrTimeout`: Operation timeout

#### Authentication Errors
- `ErrAuthenticationFailed`: General authentication failure
- `ErrInvalidCredentials`: Invalid username/password
- `ErrAccountDisabled`: Account is disabled
- `ErrAccountLocked`: Account is locked
- `ErrPasswordExpired`: Password has expired

#### Authorization Errors
- `ErrInsufficientAccess`: Insufficient access rights
- `ErrPermissionDenied`: Permission denied

#### Data Validation Errors
- `ErrInvalidDN`: Invalid distinguished name
- `ErrInvalidFilter`: Invalid LDAP filter
- `ErrInvalidAttribute`: Invalid attribute
- `ErrMalformedEntry`: Malformed LDAP entry

#### Object Existence Errors
- `ErrObjectNotFound`: Object not found
- `ErrObjectExists`: Object already exists
- `ErrConstraintViolation`: Constraint violation

#### Context Errors
- `ErrContextCancelled`: Context was cancelled
- `ErrContextDeadlineExceeded`: Context deadline exceeded

## Error Classification Functions

### Authentication Errors
```go
if IsAuthenticationError(err) {
    // Handle authentication failure
    // Log security event
    // Increment failed login counter
}
```

### Connection Errors
```go
if IsConnectionError(err) {
    // Handle connection issues
    // Try alternative server
    // Implement exponential backoff
}
```

### Not Found Errors
```go
if IsNotFoundError(err) {
    // Handle missing objects
    // Return 404 to client
    // Suggest creating object
}
```

### Validation Errors
```go
if IsValidationError(err) {
    // Handle input validation
    // Return 400 to client
    // Provide correction hints
}
```

### Context Errors
```go
if IsContextError(err) {
    // Handle cancellation/timeout
    // Clean up resources
    // Don't retry automatically
}
```

## Error Information Extraction

### LDAP Result Code
```go
code := GetLDAPResultCode(err)
if code == int(ldap.LDAPResultInvalidCredentials) {
    // Handle specific LDAP error code
}
```

### Distinguished Name
```go
dn := ExtractDN(err)
if dn != "" {
    log.Printf("Error occurred with DN: %s", dn)
}
```

### Operation Context
```go
context := GetErrorContext(err)
if username, exists := context["samAccountName"]; exists {
    log.Printf("Error for user: %v", username)
}
```

### Formatted Error with Context
```go
detailed := FormatErrorWithContext(err)
log.Printf("Detailed error: %s", detailed)
```

## Severity and Retry Logic

### Error Severity
```go
severity := GetErrorSeverity(err)
switch severity {
case SeverityCritical:
    // Alert operations team
case SeverityError:
    // Log error, notify monitoring
case SeverityWarning:
    // Log warning
case SeverityInfo:
    // Debug log only
}
```

### Retry Capability
```go
if IsRetryable(err) {
    // Implement exponential backoff retry
    time.Sleep(backoffDelay)
    return retryOperation()
}
// Don't retry, handle error appropriately
```

### Custom Retry Information
```go
retryableErr := WithRetryInfo(originalErr, true)
if retryableErr.IsRetryable() {
    // Custom retry logic
}
```

## Usage Examples

### Basic Error Handling with Classification
```go
user, err := client.FindUserBySAMAccountName("jdoe")
if err != nil {
    if IsNotFoundError(err) {
        return fmt.Errorf("user jdoe not found: %w", err)
    }
    if IsAuthenticationError(err) {
        return fmt.Errorf("authentication failed: %w", err)
    }
    if IsConnectionError(err) && IsRetryable(err) {
        // Implement retry logic
        return retryWithBackoff(func() error {
            user, err = client.FindUserBySAMAccountName("jdoe")
            return err
        })
    }
    return fmt.Errorf("unexpected error: %w", err)
}
```

### Advanced Error Context Usage
```go
err := client.CheckPasswordForSAMAccountName("jdoe", "wrongpass")
if err != nil {
    // Extract detailed information
    op := ExtractOperation(err)
    dn := ExtractDN(err)
    code := GetLDAPResultCode(err)
    severity := GetErrorSeverity(err)
    
    logger.Error("authentication_failed",
        "operation", op,
        "dn", dn,
        "ldap_code", code,
        "severity", severity.String(),
        "error", err.Error())
    
    // Security logging
    if IsAuthenticationError(err) {
        securityLogger.Warn("failed_login_attempt",
            "username", "jdoe",
            "source_ip", getClientIP(),
            "error_details", FormatErrorWithContext(err))
    }
}
```

### Structured Error Handling in Web Applications
```go
func (h *Handler) authenticateUser(w http.ResponseWriter, r *http.Request) {
    user, err := h.ldapClient.CheckPasswordForSAMAccountName(username, password)
    if err != nil {
        severity := GetErrorSeverity(err)
        
        switch severity {
        case SeverityCritical:
            // Service unavailable
            http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
            h.alertOps("LDAP service down", err)
            
        case SeverityError:
            if IsAuthenticationError(err) {
                http.Error(w, "Invalid credentials", http.StatusUnauthorized)
                h.logSecurityEvent("failed_login", username, r.RemoteAddr, err)
            } else {
                http.Error(w, "Authentication error", http.StatusInternalServerError)
            }
            
        case SeverityWarning:
            if IsNotFoundError(err) {
                http.Error(w, "User not found", http.StatusNotFound)
            }
            
        default:
            http.Error(w, "Internal error", http.StatusInternalServerError)
        }
        
        // Log with appropriate level
        h.logger.Log(severityToLogLevel(severity), "authentication_error",
            "error", FormatErrorWithContext(err))
        return
    }
    
    // Success case
    h.handleSuccessfulLogin(w, user)
}
```

## Migration Guide

### Existing Error Handling
Existing code using `errors.Is()` continues to work:

```go
// This continues to work unchanged
if errors.Is(err, ErrUserNotFound) {
    // Handle user not found
}
```

### Enhanced Error Handling
New code can use the enhanced features:

```go
// New classification approach
if IsNotFoundError(err) {
    // Works for ErrUserNotFound, ErrGroupNotFound, ErrComputerNotFound, etc.
    // Also detects LDAP result code ldap.LDAPResultNoSuchObject
}

// Extract additional context
if context := GetErrorContext(err); context != nil {
    if samAccount := context["samAccountName"]; samAccount != nil {
        log.Printf("Error for user: %v", samAccount)
    }
}
```

## Performance Considerations

The enhanced error handling system is designed for minimal performance impact:

- Error classification uses type assertions and map lookups
- Context information is only collected when errors occur
- Error creation has negligible overhead in success cases
- Memory allocation is optimized for error paths

## Best Practices

1. **Use Classification Functions**: Prefer `IsAuthenticationError(err)` over checking specific error types
2. **Check Retry Capability**: Use `IsRetryable(err)` before implementing retry logic
3. **Extract Context Appropriately**: Use context extraction for debugging and logging, not business logic
4. **Respect Severity Levels**: Use `GetErrorSeverity(err)` for appropriate logging and alerting
5. **Preserve Original Errors**: Always use error wrapping to maintain the error chain
6. **Log with Context**: Use `FormatErrorWithContext(err)` for detailed logging

## Testing Error Handling

The enhanced error system includes comprehensive test coverage:

```bash
# Run all error handling tests
go test -v -run "TestLDAPError|TestErrorClassification|TestWrapLDAPError"

# Run performance benchmarks
go test -bench=BenchmarkError -benchmem

# Test backward compatibility
go test -v -run TestEnhancedBackwardCompatibility
```

## Monitoring and Observability

### Metrics to Track
- Error count by classification type
- Error severity distribution
- Retry success rates
- LDAP result code frequency

### Logging Integration
```go
// Structured logging with error context
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

if err != nil {
    severity := GetErrorSeverity(err)
    attrs := []slog.Attr{
        slog.String("error", err.Error()),
        slog.String("severity", severity.String()),
        slog.String("operation", ExtractOperation(err)),
    }
    
    if dn := ExtractDN(err); dn != "" {
        attrs = append(attrs, slog.String("dn", dn))
    }
    
    if code := GetLDAPResultCode(err); code > 0 {
        attrs = append(attrs, slog.Int("ldap_code", code))
    }
    
    logger.LogAttrs(context.Background(), severityToSlogLevel(severity), 
        "ldap_operation_failed", attrs...)
}
```

This enhanced error handling system provides comprehensive error management capabilities while maintaining backward compatibility and focusing on debugging efficiency and operational observability.