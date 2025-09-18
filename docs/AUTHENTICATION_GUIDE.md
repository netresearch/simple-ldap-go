# Authentication Guide

## Overview

The simple-ldap-go library provides comprehensive authentication capabilities for LDAP and Active Directory environments. This guide covers authentication workflows, password management, and security best practices.

## Table of Contents

- [Quick Start](#quick-start)
- [Authentication Methods](#authentication-methods)
- [Password Management](#password-management)
- [Security Considerations](#security-considerations)
- [Error Handling](#error-handling)
- [Advanced Patterns](#advanced-patterns)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Authentication

```go
package main

import (
    "context"
    "log"
    "time"

    ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
    // Configure LDAP connection
    config := ldap.Config{
        Server:            "ldaps://ldap.example.com:636",
        BaseDN:            "dc=example,dc=com",
        IsActiveDirectory: true,
    }

    // Create admin client
    client, err := ldap.New(config, "admin@example.com", "adminPassword")
    if err != nil {
        log.Fatal("Failed to create LDAP client:", err)
    }

    // Authenticate a user
    user, err := client.CheckPasswordForSAMAccountName("jdoe", "userPassword")
    if err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    log.Printf("User authenticated: %s (%s)", user.CN(), user.Mail)
}
```

## Authentication Methods

### 1. SAM Account Name Authentication

The most common method for Active Directory environments.

```go
// Simple authentication
user, err := client.CheckPasswordForSAMAccountName("username", "password")

// With context and timeout
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

user, err := client.CheckPasswordForSAMAccountNameContext(ctx, "username", "password")
if err != nil {
    switch {
    case errors.Is(err, ldap.ErrUserNotFound):
        // User doesn't exist
    case errors.Is(err, context.DeadlineExceeded):
        // Timeout occurred
    default:
        // Other error
    }
}
```

### 2. Distinguished Name Authentication

Direct authentication using the user's DN.

```go
// Authenticate with DN
userDN := "cn=John Doe,ou=Users,dc=example,dc=com"
user, err := client.CheckPasswordForDN(userDN, "password")

// With context
user, err := client.CheckPasswordForDNContext(ctx, userDN, "password")
```

### 3. Email-Based Authentication

Find user by email, then authenticate.

```go
func authenticateByEmail(client *ldap.LDAP, email, password string) (*ldap.User, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Find user by email
    user, err := client.FindUserByMailContext(ctx, email)
    if err != nil {
        return nil, fmt.Errorf("user not found: %w", err)
    }

    // Authenticate with found DN
    return client.CheckPasswordForDNContext(ctx, user.DN(), password)
}
```

## Password Management

### Changing Passwords

```go
// Change password with old password verification
err := client.ChangePasswordForSAMAccountName(
    "username",
    "oldPassword",
    "newPassword123!",
)

// With context
err := client.ChangePasswordForSAMAccountNameContext(
    ctx,
    "username",
    "oldPassword",
    "newPassword123!",
)
```

### Password Reset (Admin)

```go
func resetUserPassword(client *ldap.LDAP, username, newPassword string) error {
    ctx := context.Background()

    // Find user
    user, err := client.FindUserBySAMAccountNameContext(ctx, username)
    if err != nil {
        return fmt.Errorf("user not found: %w", err)
    }

    // Admin reset (requires appropriate permissions)
    // Note: This is a simplified example - actual implementation depends on directory
    conn, err := client.GetConnectionContext(ctx)
    if err != nil {
        return err
    }
    defer conn.Close()

    // Encode password for Active Directory
    encodedPassword := encodePassword(newPassword)

    modify := ldap.NewModifyRequest(user.DN())
    modify.Replace("unicodePwd", []string{encodedPassword})

    return conn.Modify(modify)
}

func encodePassword(password string) string {
    // Convert to UTF-16LE and add quotes for AD
    utf16 := utf16.Encode([]rune("\"" + password + "\""))
    buf := make([]byte, len(utf16)*2)
    for i, r := range utf16 {
        binary.LittleEndian.PutUint16(buf[i*2:], r)
    }
    return string(buf)
}
```

## Security Considerations

### 1. Always Use LDAPS

```go
// ✅ Good - Secure
config := ldap.Config{
    Server: "ldaps://ldap.example.com:636",
}

// ❌ Bad - Insecure
config := ldap.Config{
    Server: "ldap://ldap.example.com:389",
}
```

### 2. Service Account Best Practices

```go
// Create a dedicated service account client
serviceConfig := ldap.Config{
    Server:            "ldaps://ldap.example.com:636",
    BaseDN:            "dc=example,dc=com",
    IsActiveDirectory: true,
}

// Use service account with minimal permissions
serviceClient, err := ldap.NewSecureClient(
    serviceConfig,
    "svc-app@example.com",
    os.Getenv("SERVICE_PASSWORD"), // From secure storage
)
```

### 3. Rate Limiting

```go
type AuthService struct {
    client  *ldap.LDAP
    limiter *rate.Limiter
}

func (s *AuthService) Authenticate(username, password string) (*ldap.User, error) {
    // Rate limit authentication attempts
    if !s.limiter.Allow() {
        return nil, errors.New("rate limit exceeded")
    }

    return s.client.CheckPasswordForSAMAccountName(username, password)
}
```

### 4. Failed Attempt Tracking

```go
type AuthTracker struct {
    client   *ldap.LDAP
    attempts sync.Map // username -> attempts
    mu       sync.Mutex
}

func (t *AuthTracker) AuthenticateWithTracking(username, password string) (*ldap.User, error) {
    // Check if account is locked
    if t.isLocked(username) {
        return nil, errors.New("account locked due to failed attempts")
    }

    user, err := t.client.CheckPasswordForSAMAccountName(username, password)
    if err != nil {
        t.recordFailedAttempt(username)
        return nil, err
    }

    // Reset on successful auth
    t.attempts.Delete(username)
    return user, nil
}

func (t *AuthTracker) isLocked(username string) bool {
    if val, ok := t.attempts.Load(username); ok {
        attempts := val.(int)
        return attempts >= 5
    }
    return false
}

func (t *AuthTracker) recordFailedAttempt(username string) {
    t.mu.Lock()
    defer t.mu.Unlock()

    val, _ := t.attempts.LoadOrStore(username, 0)
    attempts := val.(int) + 1
    t.attempts.Store(username, attempts)

    // Log security event
    log.Printf("Failed auth attempt %d for user: %s", attempts, username)
}
```

## Error Handling

### Authentication Error Types

```go
func handleAuthError(err error) {
    var ldapErr *ldap.LDAPError

    switch {
    case errors.Is(err, ldap.ErrUserNotFound):
        // User doesn't exist
        log.Println("Invalid username")

    case errors.Is(err, context.DeadlineExceeded):
        // Timeout
        log.Println("Authentication timeout")

    case errors.As(err, &ldapErr):
        // LDAP-specific error
        switch ldapErr.Code {
        case 49: // Invalid credentials
            log.Println("Invalid password")
        case 50: // Insufficient access
            log.Println("Account restricted")
        case 53: // Account disabled/locked
            log.Println("Account disabled or locked")
        default:
            log.Printf("LDAP error: %d - %v", ldapErr.Code, ldapErr)
        }

    default:
        // Generic error
        log.Printf("Authentication failed: %v", err)
    }
}
```

### Retry Logic

```go
func authenticateWithRetry(client *ldap.LDAP, username, password string, maxRetries int) (*ldap.User, error) {
    var lastErr error

    for i := 0; i < maxRetries; i++ {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        user, err := client.CheckPasswordForSAMAccountNameContext(ctx, username, password)
        cancel()

        if err == nil {
            return user, nil
        }

        // Don't retry on auth failures
        if errors.Is(err, ldap.ErrUserNotFound) {
            return nil, err
        }

        lastErr = err

        // Exponential backoff
        if i < maxRetries-1 {
            time.Sleep(time.Duration(math.Pow(2, float64(i))) * time.Second)
        }
    }

    return nil, fmt.Errorf("authentication failed after %d attempts: %w", maxRetries, lastErr)
}
```

## Advanced Patterns

### 1. Multi-Factor Authentication Flow

```go
type MFAAuthenticator struct {
    ldap     *ldap.LDAP
    mfaStore MFAStore // Your MFA backend
}

func (m *MFAAuthenticator) Authenticate(username, password, mfaCode string) (*ldap.User, error) {
    // Step 1: LDAP authentication
    user, err := m.ldap.CheckPasswordForSAMAccountName(username, password)
    if err != nil {
        return nil, fmt.Errorf("ldap auth failed: %w", err)
    }

    // Step 2: MFA verification
    if !m.mfaStore.VerifyCode(user.Mail, mfaCode) {
        return nil, errors.New("invalid MFA code")
    }

    return user, nil
}
```

### 2. Session Management

```go
type Session struct {
    User      *ldap.User
    Token     string
    ExpiresAt time.Time
}

type SessionManager struct {
    ldap     *ldap.LDAP
    sessions sync.Map
}

func (sm *SessionManager) Login(username, password string) (*Session, error) {
    // Authenticate
    user, err := sm.ldap.CheckPasswordForSAMAccountName(username, password)
    if err != nil {
        return nil, err
    }

    // Create session
    session := &Session{
        User:      user,
        Token:     generateToken(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
    }

    sm.sessions.Store(session.Token, session)
    return session, nil
}

func (sm *SessionManager) Validate(token string) (*Session, error) {
    val, ok := sm.sessions.Load(token)
    if !ok {
        return nil, errors.New("invalid session")
    }

    session := val.(*Session)
    if time.Now().After(session.ExpiresAt) {
        sm.sessions.Delete(token)
        return nil, errors.New("session expired")
    }

    return session, nil
}
```

### 3. Delegated Authentication

```go
type DelegatedAuth struct {
    serviceClient *ldap.LDAP // Admin client
}

func (d *DelegatedAuth) AuthenticateUser(username, password string) (*ldap.User, error) {
    ctx := context.Background()

    // Find user with service account
    user, err := d.serviceClient.FindUserBySAMAccountNameContext(ctx, username)
    if err != nil {
        return nil, fmt.Errorf("user lookup failed: %w", err)
    }

    // Create temporary client for auth verification
    tempConfig := ldap.Config{
        Server: d.serviceClient.config.Server,
        BaseDN: d.serviceClient.config.BaseDN,
    }

    // Attempt to bind with user credentials
    _, err = ldap.New(tempConfig, user.DN(), password)
    if err != nil {
        return nil, fmt.Errorf("authentication failed: %w", err)
    }

    return user, nil
}
```

### 4. Caching Authentication Results

```go
type CachedAuthenticator struct {
    client *ldap.LDAP
    cache  *cache.Cache
}

func (ca *CachedAuthenticator) Authenticate(username, password string) (*ldap.User, error) {
    // Generate cache key from credentials
    key := ca.generateKey(username, password)

    // Check cache
    if val, found := ca.cache.Get(key); found {
        return val.(*ldap.User), nil
    }

    // Authenticate
    user, err := ca.client.CheckPasswordForSAMAccountName(username, password)
    if err != nil {
        return nil, err
    }

    // Cache successful authentication (short TTL for security)
    ca.cache.Set(key, user, 5*time.Minute)
    return user, nil
}

func (ca *CachedAuthenticator) generateKey(username, password string) string {
    h := sha256.Sum256([]byte(username + ":" + password))
    return hex.EncodeToString(h[:])
}
```

## Troubleshooting

### Common Issues and Solutions

#### 1. "Invalid Credentials" (Error 49)

**Possible Causes:**
- Wrong username or password
- Account locked or disabled
- Password expired

**Solution:**
```go
func diagnoseAuthFailure(client *ldap.LDAP, username string) {
    // Check if user exists
    user, err := client.FindUserBySAMAccountName(username)
    if err != nil {
        log.Printf("User not found: %s", username)
        return
    }

    // Check account status (if you have admin rights)
    uac := user.UserAccountControl
    if uac&ldap.UACAccountDisable != 0 {
        log.Println("Account is disabled")
    }
    if uac&ldap.UACPasswordExpired != 0 {
        log.Println("Password has expired")
    }
    if uac&ldap.UACAccountLockout != 0 {
        log.Println("Account is locked")
    }
}
```

#### 2. Connection Timeouts

**Solution:**
```go
// Use connection pooling for better performance
pooledClient, err := ldap.NewPooledClient(config, adminDN, adminPass, 10)

// Set appropriate timeouts
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
```

#### 3. TLS/SSL Issues

**Solution:**
```go
// For self-signed certificates (development only!)
import "crypto/tls"

tlsConfig := &tls.Config{
    InsecureSkipVerify: true, // NEVER use in production
}

// Configure client with custom TLS
// Note: This requires custom transport implementation
```

#### 4. Active Directory Specific Issues

**Password Complexity:**
```go
func validateADPassword(password string) error {
    // Check AD default complexity requirements
    if len(password) < 8 {
        return errors.New("password must be at least 8 characters")
    }

    hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
    hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
    hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
    hasSpecial := regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password)

    categories := 0
    if hasUpper { categories++ }
    if hasLower { categories++ }
    if hasNumber { categories++ }
    if hasSpecial { categories++ }

    if categories < 3 {
        return errors.New("password must contain at least 3 of: uppercase, lowercase, numbers, special characters")
    }

    return nil
}
```

## Performance Considerations

### Authentication Caching

```go
// Use the high-performance client with built-in caching
client, err := ldap.NewHighPerformanceClient(config, adminDN, adminPass)
```

### Bulk Authentication

```go
func bulkAuthenticate(client *ldap.LDAP, credentials []Credential) map[string]error {
    results := make(map[string]error)
    var wg sync.WaitGroup
    var mu sync.Mutex

    // Limit concurrency
    sem := make(chan struct{}, 5)

    for _, cred := range credentials {
        wg.Add(1)
        go func(c Credential) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()

            _, err := client.CheckPasswordForSAMAccountName(c.Username, c.Password)

            mu.Lock()
            results[c.Username] = err
            mu.Unlock()
        }(cred)
    }

    wg.Wait()
    return results
}
```

## Testing Authentication

### Unit Testing

```go
func TestAuthentication(t *testing.T) {
    // Use mock LDAP for unit tests
    mock := &MockLDAP{
        users: map[string]*ldap.User{
            "testuser": {
                Object: ldap.Object{
                    DN: "cn=Test User,ou=Users,dc=example,dc=com",
                },
                SAMAccountName: "testuser",
                Mail:          "test@example.com",
            },
        },
        passwords: map[string]string{
            "testuser": "password123",
        },
    }

    // Test successful authentication
    user, err := mock.CheckPasswordForSAMAccountName("testuser", "password123")
    assert.NoError(t, err)
    assert.Equal(t, "testuser", user.SAMAccountName)

    // Test failed authentication
    _, err = mock.CheckPasswordForSAMAccountName("testuser", "wrongpassword")
    assert.Error(t, err)
}
```

### Integration Testing

```go
func TestAuthenticationIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }

    // Setup test container
    tc := ldap.SetupTestContainer(t)
    defer tc.Close(t)

    client := tc.GetLDAPClient(t)
    testData := tc.GetTestData()

    // Test with valid credentials
    user, err := client.CheckPasswordForSAMAccountName(
        testData.ValidUserUID,
        testData.ValidUserPassword,
    )
    require.NoError(t, err)
    assert.NotNil(t, user)

    // Test with invalid credentials
    _, err = client.CheckPasswordForSAMAccountName(
        testData.ValidUserUID,
        "wrongpassword",
    )
    assert.Error(t, err)
}
```

## Summary

The simple-ldap-go authentication system provides:

1. **Multiple authentication methods** - SAM account, DN, email-based
2. **Context support** - Timeouts and cancellation
3. **Security features** - Rate limiting, attempt tracking, secure connections
4. **Error handling** - Detailed error types and diagnostic capabilities
5. **Performance optimization** - Caching, pooling, bulk operations
6. **Testing support** - Mock implementations and integration testing

Always prioritize security when implementing authentication:
- Use LDAPS for encrypted connections
- Implement rate limiting and account lockout
- Log security events for auditing
- Use service accounts with minimal permissions
- Validate and sanitize all inputs
- Handle errors gracefully without leaking information

---

*Authentication Guide v1.0.0 - Last Updated: 2025-09-17*