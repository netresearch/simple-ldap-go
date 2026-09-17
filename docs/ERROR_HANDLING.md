# Error Handling Patterns

## Table of Contents

1. [Overview](#overview)
2. [Error Types](#error-types)
3. [Error Wrapping](#error-wrapping)
4. [Error Handling Strategies](#error-handling-strategies)
5. [Context-Aware Errors](#context-aware-errors)
6. [Recovery Patterns](#recovery-patterns)
7. [Logging and Monitoring](#logging-and-monitoring)
8. [Best Practices](#best-practices)
9. [Testing Error Scenarios](#testing-error-scenarios)
10. [Common Pitfalls](#common-pitfalls)

## Overview

The simple-ldap-go library implements a comprehensive error handling system that provides clear error context, enables proper error recovery, and maintains clean error chains for debugging. The approach follows Go's idiomatic error handling patterns while adding domain-specific enhancements for LDAP operations.

### Design Principles

- **Explicit Error Handling**: No hidden failures or silent errors
- **Error Context Preservation**: Wrap errors with meaningful context
- **Type Safety**: Custom error types for specific scenarios
- **Recovery Support**: Distinguish between recoverable and fatal errors
- **Observability**: Structured logging with error context

## Error Types

### Standard Errors

```go
// errors.go - the sentinels this library returns
var (
    // Entity not found
    ErrUserNotFound     = errors.New("user not found")
    ErrGroupNotFound    = errors.New("group not found")
    ErrComputerNotFound = errors.New("computer not found")
    ErrObjectNotFound   = errors.New("object not found")

    // Authentication
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrPasswordExpired    = errors.New("password expired")
    ErrAccountLocked      = errors.New("account locked")
    ErrAccountDisabled    = errors.New("account disabled")

    // Connection and pool
    ErrConnectionFailed    = errors.New("connection failed")
    ErrServerUnavailable   = errors.New("server unavailable")
    ErrTimeoutExceeded     = errors.New("timeout exceeded")
    ErrPoolExhausted       = errors.New("connection pool exhausted")
    ErrPoolClosed          = errors.New("connection pool is closed")
    ErrConnectionUnhealthy = errors.New("connection is unhealthy")

    // Validation
    ErrInvalidDN     = errors.New("invalid distinguished name")
    ErrInvalidFilter = errors.New("invalid LDAP filter")

    // Context
    ErrContextCancelled        = errors.New("context cancelled")
    ErrContextDeadlineExceeded = errors.New("context deadline exceeded")

    // Uniqueness
    ErrDNDuplicated             = errors.New("DN is not unique")
    ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")
    ErrMailDuplicated           = errors.New("mail is not unique")

    // Cache
    ErrCacheDisabled    = errors.New("cache is disabled")
    ErrCacheKeyNotFound = errors.New("cache key not found")
    ErrCacheFull        = errors.New("cache is full")
)
```

### Custom Error Types

```go
// errors.go:45 - Custom error type with context
type LDAPError struct {
    Op       string    // Operation that failed
    DN       string    // Distinguished name involved
    Code     int       // LDAP result code
    Message  string    // Error message
    Cause    error     // Underlying error
    Time     time.Time // When error occurred
}

func (e *LDAPError) Error() string {
    if e.Cause != nil {
        return fmt.Sprintf("LDAP %s failed for %s: %s (code: %d): %v",
            e.Op, e.DN, e.Message, e.Code, e.Cause)
    }
    return fmt.Sprintf("LDAP %s failed for %s: %s (code: %d)",
        e.Op, e.DN, e.Message, e.Code)
}

func (e *LDAPError) Unwrap() error {
    return e.Cause
}

// errors.go:78 - Validation error with details
type ValidationError struct {
    Field   string
    Value   interface{}
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed for %s: %s (value: %v)",
        e.Field, e.Message, e.Value)
}

// errors.go:92 - Multi-error for batch operations
type MultiError struct {
    Errors []error
}

func (m *MultiError) Error() string {
    if len(m.Errors) == 0 {
        return "no errors"
    }

    var messages []string
    for _, err := range m.Errors {
        messages = append(messages, err.Error())
    }

    return fmt.Sprintf("multiple errors occurred: %s",
        strings.Join(messages, "; "))
}

func (m *MultiError) Add(err error) {
    if err != nil {
        m.Errors = append(m.Errors, err)
    }
}

func (m *MultiError) HasErrors() bool {
    return len(m.Errors) > 0
}
```

## Error Wrapping

### Basic Wrapping Pattern

```go
// users.go:234 - Error wrapping with context
func (l *LDAP) FindUserByDN(dn string) (*User, error) {
    // Validate input
    if err := ValidateDN(dn); err != nil {
        return nil, fmt.Errorf("invalid user DN %s: %w", dn, err)
    }

    // Get connection
    conn, err := l.pool.Get()
    if err != nil {
        return nil, fmt.Errorf("failed to get connection for user lookup: %w", err)
    }
    defer l.pool.Put(conn)

    // Search for user
    result, err := conn.Search(searchRequest)
    if err != nil {
        return nil, fmt.Errorf("LDAP search failed for user %s: %w", dn, err)
    }

    if len(result.Entries) == 0 {
        return nil, fmt.Errorf("user %s: %w", dn, ErrUserNotFound)
    }

    // Parse user
    user, err := l.parseUser(result.Entries[0])
    if err != nil {
        return nil, fmt.Errorf("failed to parse user %s: %w", dn, err)
    }

    return user, nil
}
```

### Advanced Wrapping with Context

```go
// errors.go:145 - Context-aware error wrapping
func WrapLDAPError(op string, dn string, err error) error {
    if err == nil {
        return nil
    }

    // Check if already an LDAPError
    var ldapErr *LDAPError
    if errors.As(err, &ldapErr) {
        return err
    }

    // Extract LDAP error code if available
    code := extractLDAPCode(err)

    return &LDAPError{
        Op:        op,
        DN:        dn,
        Code:      code,
        Err:       err,
        Timestamp: time.Now(),
    }
}

// Usage example
func (l *LDAP) ModifyUser(dn string, mods []ldap.Modify) error {
    err := l.performModify(dn, mods)
    if err != nil {
        return WrapLDAPError("ModifyUser", dn, err)
    }
    return nil
}
```

### Error Chain Preservation

```go
// auth.go:189 - Preserving error chain for debugging
func (l *LDAP) AuthenticateWithContext(ctx context.Context, username, password string) error {
    // Find user
    user, err := l.FindUserBySAMAccountName(username)
    if err != nil {
        if errors.Is(err, ErrUserNotFound) {
            // Don't reveal whether user exists
            return ErrInvalidCredentials
        }
        return fmt.Errorf("authentication lookup failed: %w", err)
    }

    // Check account status
    if err := l.checkAccountStatus(user); err != nil {
        return fmt.Errorf("account status check failed for %s: %w", username, err)
    }

    // Attempt bind
    if err := l.bindWithCredentials(user.DN(), password); err != nil {
        // Analyze specific LDAP error
        if isInvalidCredentialsError(err) {
            return ErrInvalidCredentials
        }
        return fmt.Errorf("bind failed for %s: %w", username, err)
    }

    return nil
}
```

## Error Handling Strategies

### 1. Fail-Fast Pattern

```go
// validation.go:56 - Fail fast on validation errors
func (l *LDAP) CreateUser(user FullUser) (string, error) {
    // Validate all inputs first
    if err := l.validateUser(user); err != nil {
        return "", fmt.Errorf("user validation failed: %w", err)
    }

    if err := l.checkDuplicateUser(user); err != nil {
        return "", fmt.Errorf("duplicate check failed: %w", err)
    }

    // Only proceed if all validations pass
    return l.createUserInternal(user)
}

func (l *LDAP) validateUser(user FullUser) error {
    var validationErr ValidationError

    if user.CN() == "" {
        return &ValidationError{
            Field:   "CN",
            Value:   user.CN(),
            Message: "common name is required",
        }
    }

    if !isValidEmail(user.Mail) {
        return &ValidationError{
            Field:   "Mail",
            Value:   user.Mail,
            Message: "invalid email format",
        }
    }

    return nil
}
```

### 2. Retry Pattern

The library does not retry for you: there is no retry runner and no backoff in
it. `ldap.IsRetryable(err)` classifies an error, and everything below is caller
code you own.

> `ConnectionOptions` declares `MaxRetries` and `RetryDelay`
> (`options.go`) and `DefaultConnectionOptions` fills them in, but no
> code reads either field. Setting them has no effect today.

```go
// Caller-side retry with exponential backoff.
type RetryConfig struct {
    MaxAttempts int
    InitialDelay time.Duration
    MaxDelay     time.Duration
    Multiplier   float64
}

func WithRetry(config RetryConfig, operation func() error) error {
    var lastErr error
    delay := config.InitialDelay

    for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
        err := operation()
        if err == nil {
            return nil
        }

        lastErr = err

        // Check if error is retryable
        if !isRetryable(err) {
            return fmt.Errorf("non-retryable error: %w", err)
        }

        if attempt < config.MaxAttempts {
            slog.Debug("retrying operation",
                "attempt", attempt,
                "delay", delay,
                "error", err)

            time.Sleep(delay)

            // Calculate next delay with backoff
            delay = time.Duration(float64(delay) * config.Multiplier)
            if delay > config.MaxDelay {
                delay = config.MaxDelay
            }
        }
    }

    return fmt.Errorf("operation failed after %d attempts: %w",
        config.MaxAttempts, lastErr)
}

func isRetryable(err error) bool {
    // The library's own classification, for errors that carry retry information.
    if ldap.IsRetryable(err) {
        return true
    }

    // Transient connection and pool conditions.
    if errors.Is(err, ldap.ErrConnectionFailed) ||
        errors.Is(err, ldap.ErrServerUnavailable) ||
        errors.Is(err, ldap.ErrConnectionUnhealthy) ||
        errors.Is(err, ldap.ErrPoolExhausted) ||
        errors.Is(err, ldap.ErrTimeoutExceeded) {
        return true
    }

    // A cancelled context is the caller's decision, never retry it.
    if errors.Is(err, ldap.ErrContextCancelled) ||
        errors.Is(err, ldap.ErrContextDeadlineExceeded) {
        return false
    }

    return false
}
```

### 3. Circuit Breaker Pattern

The circuit breaker ships with the library (`resilience.go`). It is off by
default, for backward compatibility, and is enabled through the configuration:

```go
config.Resilience = &ldap.ResilienceConfig{
    EnableCircuitBreaker: true,
    CircuitBreaker: &ldap.CircuitBreakerConfig{
        MaxFailures:         5,
        Timeout:             time.Minute,
        HalfOpenMaxRequests: 1,
    },
}

client, err := ldap.New(config, bindDN, password)
```

`ldap.DefaultCircuitBreakerConfig()` returns the same shape with defaults. A
breaker can also be driven directly:

```go
cb := ldap.NewCircuitBreaker("directory", ldap.DefaultCircuitBreakerConfig(), logger)

err := cb.Execute(func() error {
    _, err := client.FindUserBySAMAccountName(username)
    return err
})

// Open circuit: the call was not attempted.
var cbErr *ldap.CircuitBreakerError
if errors.As(err, &cbErr) {
    return fmt.Errorf("directory unavailable, circuit open: %w", err)
}
```

`cb.GetStats()` reports the counters and `cb.Reset()` closes the circuit;
`client.GetCircuitBreakerStats()` returns the same for the breaker the client
built itself.

### 4. Batch Error Handling

`BulkCreateUsers` reports per item rather than failing as a whole: it returns one
`WorkResult[FullUser]` per input, each carrying its own `Error`. The returned
error is non-nil only when the batch could not run at all, so the per-item errors
have to be read even on success.

```go
results, err := client.BulkCreateUsers(users, initialPassword)
if err != nil {
    return fmt.Errorf("bulk create could not run: %w", err)
}

var failed int
for _, r := range results {
    if r.Error != nil {
        failed++
        slog.Error("user creation failed in bulk operation",
            slog.String("id", r.ID),
            slog.String("user", r.Data.SAMAccountName),
            slog.Duration("duration", r.Duration),
            slog.String("error", r.Error.Error()))
        continue
    }
}

if failed > 0 {
    return fmt.Errorf("bulk operation partially failed: %d of %d succeeded",
        len(results)-failed, len(results))
}
```

`BulkCreateUsersContext` takes a `context.Context` and a `*WorkerPoolConfig` for
the concurrency, instead of the defaults this call uses.

## Context-Aware Errors

### Timeout Handling

```go
// Context-aware timeout handling
func (l *LDAP) SearchWithTimeout(ctx context.Context, filter string, timeout time.Duration) ([]*User, error) {
    // Create timeout context
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    // Channel for results
    type result struct {
        users []*User
        err   error
    }
    resultChan := make(chan result, 1)

    // Execute search in goroutine
    go func() {
        users, err := l.performSearch(filter)
        resultChan <- result{users, err}
    }()

    // Wait for result or timeout
    select {
    case <-ctx.Done():
        if errors.Is(ctx.Err(), context.DeadlineExceeded) {
            return nil, fmt.Errorf("search timeout after %v: %w",
                timeout, ErrOperationTimeout)
        }
        return nil, fmt.Errorf("search cancelled: %w", ctx.Err())

    case res := <-resultChan:
        if res.err != nil {
            return nil, fmt.Errorf("search failed: %w", res.err)
        }
        return res.users, nil
    }
}
```

### Cancellation Propagation

```go
// Proper cancellation handling
func (l *LDAP) ProcessUsersWithContext(ctx context.Context, processor func(*User) error) error {
    users, err := l.FindUsersContext(ctx)
    if err != nil {
        return fmt.Errorf("failed to retrieve users: %w", err)
    }

    g, gCtx := errgroup.WithContext(ctx)
    sem := make(chan struct{}, 10)

    for _, user := range users {
        user := user // Capture loop variable

        g.Go(func() error {
            select {
            case <-gCtx.Done():
                return gCtx.Err()
            case sem <- struct{}{}:
                defer func() { <-sem }()

                if err := processor(user); err != nil {
                    return fmt.Errorf("failed to process user %s: %w",
                        user.SAMAccountName, err)
                }
                return nil
            }
        })
    }

    if err := g.Wait(); err != nil {
        if errors.Is(err, context.Canceled) {
            return fmt.Errorf("processing cancelled: %w", err)
        }
        return err
    }

    return nil
}
```

## Recovery Patterns

### 1. Graceful Degradation

```go
// Fallback to degraded service
func (l *LDAP) GetUserWithFallback(username string) (*User, error) {
    // Try the directory first.
    user, err := l.FindUserBySAMAccountName(username)
    if err == nil {
        return user, nil
    }

    l.log.Warn("optimized lookup failed, falling back",
        slog.String("user", username),
        slog.String("error", err.Error()))

    // Try cache-only lookup
    if cached, ok := l.cache.Get(fmt.Sprintf("user:%s", username)); ok {
        l.log.Info("serving from cache due to lookup failure")
        return cached.(*User), nil
    }

    // Nothing else to try: the directory is the only source, and a second
    // identical lookup would fail for the same reason the first did. Return
    // the original error rather than retrying it.
    return nil, fmt.Errorf("all lookup methods failed for %s: %w", username, err)
}
```

### 2. Connection Recovery

Recovery is not something a caller drives. With a pool configured, a broken
connection is detected by the health check on `HealthCheckInterval` and closed
(`pool.go`), and one that a caller never returned is evicted after
`LeakEvictionThreshold` (`pool.go`). The next `Get` dials a replacement.

What a caller owns is returning the connection, so the pool can tell a busy
connection from a lost one:

```go
conn, err := pool.Get(ctx)
if err != nil {
    // ErrPoolExhausted means every connection is checked out and GetTimeout
    // elapsed - a sizing or a leak problem, not a server problem.
    return fmt.Errorf("no pooled connection: %w", err)
}
defer func() {
    // Put returns the connection; skipping it is what produces LeakedConnections.
    if err := pool.Put(conn); err != nil {
        slog.Warn("returning connection failed", slog.String("error", err.Error()))
    }
}()
```

Without a pool, a failed operation is retried by reconnecting - that is, by
building a new client with `ldap.New` and the same `Config`, under the
caller-side retry above.

### 3. Partial Result Handling

```go
// Handle partial failures gracefully
type PartialResult struct {
    Data     []interface{}
    Errors   []error
    Complete bool
}

func (l *LDAP) SearchWithPartialResults(filter string, continueOnError bool) (*PartialResult, error) {
    result := &PartialResult{
        Complete: true,
    }

    entries, err := l.search(filter)
    if err != nil {
        if !continueOnError {
            return nil, err
        }

        // Check if we got partial results
        if isPartialResultError(err) {
            result.Complete = false
            result.Errors = append(result.Errors, err)
            // Continue processing available entries
        } else {
            return nil, err
        }
    }

    // Process available entries
    for _, entry := range entries {
        data, err := l.parseEntry(entry)
        if err != nil {
            if continueOnError {
                result.Errors = append(result.Errors,
                    fmt.Errorf("failed to parse entry %s: %w", entry.DN, err))
                continue
            }
            return nil, err
        }
        result.Data = append(result.Data, data)
    }

    if len(result.Errors) > 0 {
        l.log.Warn("search completed with errors",
            slog.Int("results", len(result.Data)),
            slog.Int("errors", len(result.Errors)))
    }

    return result, nil
}
```

## Logging and Monitoring

### Structured Error Logging

```go
// Rich error context in logs
func LogError(logger *slog.Logger, err error, operation string, attrs ...slog.Attr) {
    // Base attributes
    logAttrs := []slog.Attr{
        slog.String("operation", operation),
        slog.String("error", err.Error()),
        slog.Time("timestamp", time.Now()),
    }

    // Add custom attributes
    logAttrs = append(logAttrs, attrs...)

    // Check for specific error types
    var ldapErr *LDAPError
    if errors.As(err, &ldapErr) {
        logAttrs = append(logAttrs,
            slog.String("dn", ldapErr.DN),
            slog.Int("ldap_code", ldapErr.Code),
            slog.String("ldap_op", ldapErr.Op))
    }

    // Check error chain
    if unwrapped := errors.Unwrap(err); unwrapped != nil {
        logAttrs = append(logAttrs,
            slog.String("cause", unwrapped.Error()))
    }

    // Determine log level based on error type
    if isRetryable(err) {
        logger.LogAttrs(context.Background(), slog.LevelWarn, "retryable error", logAttrs...)
    } else if isFatal(err) {
        logger.LogAttrs(context.Background(), slog.LevelError, "fatal error", logAttrs...)
    } else {
        logger.LogAttrs(context.Background(), slog.LevelInfo, "handled error", logAttrs...)
    }
}

// Usage
LogError(l.log, err, "user_creation",
    slog.String("username", username),
    slog.String("request_id", requestID))
```

### Error Metrics

```go
// Error tracking for monitoring
type ErrorMetrics struct {
    mu sync.RWMutex

    totalErrors   int64
    errorsByType  map[string]int64
    errorsByOp    map[string]int64
    lastErrors    *ring.Ring
}

func (em *ErrorMetrics) RecordError(err error, operation string) {
    em.mu.Lock()
    defer em.mu.Unlock()

    em.totalErrors++

    // Track by error type
    errType := classifyError(err)
    em.errorsByType[errType]++

    // Track by operation
    em.errorsByOp[operation]++

    // Store in ring buffer
    em.lastErrors.Value = &ErrorRecord{
        Error:     err,
        Operation: operation,
        Timestamp: time.Now(),
    }
    em.lastErrors = em.lastErrors.Next()

    // Export metrics
    errorCounter.WithLabelValues(errType, operation).Inc()
}

func classifyError(err error) string {
    switch {
    case errors.Is(err, ErrUserNotFound):
        return "not_found"
    case errors.Is(err, ErrInvalidCredentials):
        return "auth_failed"
    case errors.Is(err, ErrConnectionFailed):
        return "connection"
    case errors.Is(err, ErrOperationTimeout):
        return "timeout"
    case errors.Is(err, context.Canceled):
        return "cancelled"
    default:
        return "unknown"
    }
}
```

## Best Practices

### 1. Error Message Guidelines

```go
// Good: Specific, actionable error messages
return fmt.Errorf("failed to create user %s in OU %s: %w", username, ou, err)

// Bad: Generic error messages
return fmt.Errorf("operation failed: %w", err)

// Good: Include relevant context
return fmt.Errorf("LDAP bind failed for %s (server: %s, port: %d): %w",
    username, config.Host, config.Port, err)

// Bad: Missing context
return fmt.Errorf("bind failed: %w", err)
```

### 2. Error Comparison

```go
// Proper error comparison
func HandleError(err error) {
    // Use errors.Is for sentinel errors
    if errors.Is(err, ErrUserNotFound) {
        // Handle not found case
    }

    // Use errors.As for error types
    var validationErr *ValidationError
    if errors.As(err, &validationErr) {
        // Handle validation error
        fmt.Printf("Field %s failed: %s\n", validationErr.Field, validationErr.Message)
    }

    // Never use string comparison
    // Bad: if err.Error() == "user not found"
}
```

### 3. Error Documentation

```go
// users.go - Document error conditions

// FindUserByDN retrieves a user by their distinguished name.
//
// Returns:
//   - *User: The user object if found
//   - error: Returns ErrUserNotFound if user doesn't exist,
//            ErrInvalidDN if DN format is invalid,
//            ErrConnectionFailed for connection issues
func (l *LDAP) FindUserByDN(dn string) (*User, error) {
    // Implementation
}
```

### 4. Error Aggregation

```go
// Collecting multiple errors
func (l *LDAP) ValidateUsers(users []FullUser) error {
    var multiErr MultiError

    for i, user := range users {
        if err := l.validateUser(user); err != nil {
            multiErr.Add(fmt.Errorf("user[%d] %s: %w",
                i, user.SAMAccountName, err))
        }
    }

    if multiErr.HasErrors() {
        return &multiErr
    }

    return nil
}
```

## Testing Error Scenarios

### Unit Testing Errors

```go
// errors_test.go:45 - Testing error handling
func TestErrorHandling(t *testing.T) {
    tests := []struct {
        name        string
        setupMock   func(*MockLDAP)
        expectedErr error
        checkErr    func(t *testing.T, err error)
    }{
        {
            name: "user not found",
            setupMock: func(m *MockLDAP) {
                m.On("Search", mock.Anything).Return(nil, ErrUserNotFound)
            },
            expectedErr: ErrUserNotFound,
            checkErr: func(t *testing.T, err error) {
                assert.True(t, errors.Is(err, ErrUserNotFound))
            },
        },
        {
            name: "connection failure with retry",
            setupMock: func(m *MockLDAP) {
                m.On("Search", mock.Anything).
                    Return(nil, ErrConnectionFailed).Times(2)
                m.On("Search", mock.Anything).
                    Return(&SearchResult{}, nil).Once()
            },
            expectedErr: nil,
            checkErr: func(t *testing.T, err error) {
                assert.NoError(t, err)
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mockLDAP := new(MockLDAP)
            tt.setupMock(mockLDAP)

            err := performOperation(mockLDAP)

            if tt.checkErr != nil {
                tt.checkErr(t, err)
            } else {
                if tt.expectedErr != nil {
                    assert.ErrorIs(t, err, tt.expectedErr)
                } else {
                    assert.NoError(t, err)
                }
            }
        })
    }
}
```

### Integration Testing

```go
// Testing error recovery
func TestConnectionRecovery(t *testing.T) {
    // Setup test LDAP with testcontainers
    ctx := context.Background()
    container, err := setupTestLDAP(ctx)
    require.NoError(t, err)
    defer container.Terminate(ctx)

    client := setupClient(container)

    // Simulate connection failure
    container.Stop(ctx, nil)

    // Operation should fail
    _, err = client.FindUserByDN("cn=test,dc=example,dc=com")
    assert.Error(t, err)

    // Restart container
    container.Start(ctx)

    // Wait for recovery
    time.Sleep(2 * time.Second)

    // Operation should succeed after recovery
    _, err = client.FindUserByDN("cn=test,dc=example,dc=com")
    assert.NoError(t, err)
}
```

### Error Injection Testing

```go
// Inject errors for testing
type ErrorInjector struct {
    client     *LDAP
    errorRate  float64
    errorTypes []error
}

func (ei *ErrorInjector) InjectError() error {
    if rand.Float64() < ei.errorRate {
        // Return random error type
        idx := rand.Intn(len(ei.errorTypes))
        return ei.errorTypes[idx]
    }
    return nil
}

func TestWithErrorInjection(t *testing.T) {
    injector := &ErrorInjector{
        client:     client,
        errorRate:  0.1, // 10% error rate
        errorTypes: []error{
            ErrConnectionFailed,
            ErrOperationTimeout,
            context.Canceled,
        },
    }

    // Run operations with injected errors
    results := runBulkOperations(injector)

    // Verify error handling
    assert.True(t, results.SuccessRate > 0.85) // Allow for some failures
    assert.True(t, results.RecoveryRate > 0.95) // Most errors should recover
}
```

## Common Pitfalls

### 1. Swallowing Errors

```go
// BAD: Silently ignoring errors
func BadExample(client *ldap.LDAP) {
    user, _ := client.FindUserBySAMAccountName("john") // Error ignored!
    processUser(user) // May panic if user is nil
}

// GOOD: Always handle errors
func GoodExample(client *ldap.LDAP) error {
    user, err := client.FindUserBySAMAccountName("john")
    if err != nil {
        return fmt.Errorf("failed to find user: %w", err)
    }
    return processUser(user)
}
```

### 2. Losing Error Context

```go
// BAD: Returning error without context
func BadUpdate(dn string) error {
    err := ldap.Modify(dn, mods)
    return err // Lost context about what was being updated
}

// GOOD: Adding meaningful context
func GoodUpdate(dn string, attributes map[string][]string) error {
    err := ldap.Modify(dn, mods)
    if err != nil {
        return fmt.Errorf("failed to update user %s with %d attributes: %w",
            dn, len(attributes), err)
    }
    return nil
}
```

### 3. Incorrect Error Checking

```go
// BAD: String comparison
if err.Error() == "connection refused" {
    // Fragile: depends on exact error text
}

// BAD: Direct equality
if err == ErrUserNotFound {
    // Won't work with wrapped errors
}

// GOOD: Using errors.Is
if errors.Is(err, ErrUserNotFound) {
    // Works with error wrapping
}

// GOOD: Using errors.As for types
var ldapErr *LDAPError
if errors.As(err, &ldapErr) {
    // Access typed error fields
}
```

### 4. Resource Leaks on Error

```go
// BAD: Resource leak on error
func BadResourceHandling() error {
    conn, err := pool.Get()
    if err != nil {
        return err
    }

    result, err := conn.Search(req)
    if err != nil {
        return err // Connection not returned to pool!
    }

    pool.Put(conn)
    return nil
}

// GOOD: Proper cleanup with defer
func GoodResourceHandling() error {
    conn, err := pool.Get()
    if err != nil {
        return fmt.Errorf("failed to get connection: %w", err)
    }
    defer pool.Put(conn) // Always executed

    result, err := conn.Search(req)
    if err != nil {
        return fmt.Errorf("search failed: %w", err)
    }

    return nil
}
```

---

*Error Handling Patterns Guide - Last Updated: 2026-09-17*
