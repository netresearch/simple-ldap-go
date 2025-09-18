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
// errors.go:12 - Common error definitions
var (
    // Entity not found errors
    ErrUserNotFound     = errors.New("user not found")
    ErrGroupNotFound    = errors.New("group not found")
    ErrComputerNotFound = errors.New("computer not found")

    // Authentication errors
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrPasswordExpired    = errors.New("password expired")
    ErrAccountLocked      = errors.New("account locked")
    ErrAccountDisabled    = errors.New("account disabled")

    // Connection errors
    ErrConnectionFailed = errors.New("connection failed")
    ErrConnectionClosed = errors.New("connection closed")
    ErrPoolExhausted    = errors.New("connection pool exhausted")

    // Validation errors
    ErrInvalidDN     = errors.New("invalid distinguished name")
    ErrInvalidFilter = errors.New("invalid LDAP filter")
    ErrInvalidInput  = errors.New("invalid input")

    // Operation errors
    ErrOperationTimeout = errors.New("operation timeout")
    ErrAccessDenied     = errors.New("access denied")
    ErrQuotaExceeded    = errors.New("quota exceeded")
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
        Op:      op,
        DN:      dn,
        Code:    code,
        Message: err.Error(),
        Cause:   err,
        Time:    time.Now(),
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
    if err := l.bindWithCredentials(user.DN, password); err != nil {
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

    if user.CN == "" {
        return &ValidationError{
            Field:   "CN",
            Value:   user.CN,
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

```go
// retry.go:23 - Retry with exponential backoff
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
    // Connection errors are retryable
    if errors.Is(err, ErrConnectionFailed) ||
       errors.Is(err, ErrConnectionClosed) {
        return true
    }

    // Timeout errors are retryable
    if errors.Is(err, ErrOperationTimeout) {
        return true
    }

    // Check for specific LDAP errors
    var ldapErr *LDAPError
    if errors.As(err, &ldapErr) {
        // Server busy, unavailable are retryable
        return ldapErr.Code == 51 || ldapErr.Code == 52
    }

    return false
}
```

### 3. Circuit Breaker Pattern

```go
// circuit_breaker.go:34 - Prevent cascading failures
type CircuitBreaker struct {
    maxFailures  int
    resetTimeout time.Duration

    mu           sync.RWMutex
    failures     int
    lastFailTime time.Time
    state        CircuitState
}

type CircuitState int

const (
    StateClosed CircuitState = iota
    StateOpen
    StateHalfOpen
)

func (cb *CircuitBreaker) Execute(fn func() error) error {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    // Check circuit state
    if cb.state == StateOpen {
        if time.Since(cb.lastFailTime) > cb.resetTimeout {
            cb.state = StateHalfOpen
            cb.failures = 0
        } else {
            return fmt.Errorf("circuit breaker is open")
        }
    }

    // Execute operation
    err := fn()
    if err != nil {
        cb.failures++
        cb.lastFailTime = time.Now()

        if cb.failures >= cb.maxFailures {
            cb.state = StateOpen
            return fmt.Errorf("circuit breaker opened: %w", err)
        }

        return err
    }

    // Success - reset state
    cb.failures = 0
    cb.state = StateClosed

    return nil
}
```

### 4. Batch Error Handling

```go
// bulk_operations.go:78 - Handling errors in batch operations
func (l *LDAP) BulkCreateUsers(users []FullUser) (*BulkResult, error) {
    result := &BulkResult{
        Total:     len(users),
        Succeeded: 0,
        Failed:    0,
        Errors:    make(map[string]error),
    }

    // Use semaphore for concurrency control
    sem := make(chan struct{}, 10)
    var wg sync.WaitGroup
    var mu sync.Mutex

    for i, user := range users {
        wg.Add(1)
        sem <- struct{}{}

        go func(idx int, u FullUser) {
            defer wg.Done()
            defer func() { <-sem }()

            dn, err := l.CreateUser(u)

            mu.Lock()
            defer mu.Unlock()

            if err != nil {
                result.Failed++
                result.Errors[u.SAMAccountName] = err

                // Log individual failure
                l.log.Error("failed to create user in bulk operation",
                    slog.String("user", u.SAMAccountName),
                    slog.Int("index", idx),
                    slog.String("error", err.Error()))
            } else {
                result.Succeeded++
                result.CreatedDNs = append(result.CreatedDNs, dn)
            }
        }(i, user)
    }

    wg.Wait()

    // Determine overall success/failure
    if result.Failed > 0 {
        return result, fmt.Errorf("bulk operation partially failed: %d/%d succeeded",
            result.Succeeded, result.Total)
    }

    return result, nil
}
```

## Context-Aware Errors

### Timeout Handling

```go
// context_errors.go:23 - Context-aware timeout handling
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
// context_errors.go:67 - Proper cancellation handling
func (l *LDAP) ProcessUsersWithContext(ctx context.Context, processor func(*User) error) error {
    users, err := l.GetAllUsers()
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
// degradation.go:34 - Fallback to degraded service
func (l *LDAP) GetUserWithFallback(username string) (*User, error) {
    // Try optimized path first
    user, err := l.GetUserOptimized(username)
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

    // Try basic lookup without optimizations
    user, err = l.GetUserBasic(username)
    if err != nil {
        return nil, fmt.Errorf("all lookup methods failed for %s: %w",
            username, err)
    }

    return user, nil
}
```

### 2. Connection Recovery

```go
// recovery.go:56 - Automatic connection recovery
func (l *LDAP) RecoverConnection(conn *ldap.Conn) (*ldap.Conn, error) {
    // Close bad connection
    if conn != nil {
        conn.Close()
    }

    // Attempt to establish new connection
    retryConfig := RetryConfig{
        MaxAttempts:  5,
        InitialDelay: 1 * time.Second,
        MaxDelay:     30 * time.Second,
        Multiplier:   2.0,
    }

    var newConn *ldap.Conn
    err := WithRetry(retryConfig, func() error {
        var err error
        newConn, err = l.connect()
        if err != nil {
            return fmt.Errorf("connection recovery failed: %w", err)
        }

        // Verify connection with bind
        if err := l.bindConnection(newConn); err != nil {
            newConn.Close()
            return fmt.Errorf("bind failed during recovery: %w", err)
        }

        return nil
    })

    if err != nil {
        return nil, err
    }

    l.log.Info("connection recovered successfully")
    return newConn, nil
}
```

### 3. Partial Result Handling

```go
// partial_results.go:23 - Handle partial failures gracefully
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
// logging.go:45 - Rich error context in logs
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
// metrics.go:67 - Error tracking for monitoring
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
// errors_best_practices.go:23 - Proper error comparison
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
// aggregation.go:34 - Collecting multiple errors
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
// errors_integration_test.go:67 - Testing error recovery
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
// chaos_testing.go:34 - Inject errors for testing
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
func BadExample() {
    user, _ := ldap.FindUser("john") // Error ignored!
    processUser(user) // May panic if user is nil
}

// GOOD: Always handle errors
func GoodExample() error {
    user, err := ldap.FindUser("john")
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

*Error Handling Patterns Guide v1.0.0 - simple-ldap-go Project*