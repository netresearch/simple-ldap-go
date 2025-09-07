# Security Guide for simple-ldap-go

This document provides comprehensive security guidance for using the simple-ldap-go library safely in production environments.

## Table of Contents

1. [Security Overview](#security-overview)
2. [Threat Model](#threat-model)
3. [Security Features](#security-features)
4. [Secure Configuration](#secure-configuration)
5. [Input Validation](#input-validation)
6. [TLS Security](#tls-security)
7. [Credential Management](#credential-management)
8. [Attack Prevention](#attack-prevention)
9. [Security Monitoring](#security-monitoring)
10. [Best Practices](#best-practices)
11. [Security Checklist](#security-checklist)

## Security Overview

The simple-ldap-go library implements defense-in-depth security with multiple layers of protection:

- **Input Validation**: Comprehensive validation of all LDAP inputs
- **Injection Prevention**: Detection and blocking of LDAP injection attacks
- **TLS Security**: Secure transport layer configuration
- **Credential Protection**: Safe credential handling and storage
- **Access Control**: Rate limiting and access control mechanisms
- **Security Auditing**: Comprehensive security event logging
- **Compliance**: OWASP security guidelines adherence

### Security Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │  simple-ldap-go │    │   LDAP Server   │
│                 │    │                 │    │                 │
│ User Input ────→│────│→ Input Validation│    │                 │
│                 │    │  Injection Detect│    │                 │
│                 │    │  Rate Limiting  │    │                 │
│                 │    │  TLS Security   │────│→ Secure Channel │
│                 │    │  Credential Mgmt│    │                 │
│                 │    │  Audit Logging  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Threat Model

### Threats Addressed

1. **LDAP Injection Attacks**
   - Filter manipulation
   - DN traversal attacks  
   - Object enumeration
   - Authentication bypass

2. **Transport Layer Attacks**
   - Man-in-the-middle attacks
   - Certificate spoofing
   - Protocol downgrade attacks
   - Eavesdropping

3. **Credential-based Attacks**
   - Credential theft
   - Password brute force
   - Credential reuse
   - Memory dumps

4. **Denial of Service**
   - Resource exhaustion
   - Connection flooding
   - Complex query attacks

5. **Data Exposure**
   - Sensitive data logging
   - Information disclosure
   - Memory leaks
   - Side-channel attacks

### Attack Vectors

- **Network**: Unencrypted connections, weak TLS configuration
- **Application**: Insufficient input validation, improper error handling
- **Authentication**: Weak credentials, credential exposure
- **Authorization**: Privilege escalation, access control bypass
- **Data**: Information disclosure, sensitive data in logs

## Security Features

### Core Security Components

```go
// Security configuration
type SecurityConfig struct {
    MaxRequestsPerSecond int           // Rate limiting
    MaxConcurrentOps     int           // Concurrency limits
    IPWhitelist         []net.IPNet    // IP-based access control
    AuditLog            bool           // Security audit logging
    StrictValidation    bool           // Enhanced validation mode
    ZeroizeCredentials  bool           // Secure credential cleanup
}

// TLS configuration
type TLSConfig struct {
    MinVersion            uint16        // Minimum TLS version
    CipherSuites          []uint16      // Allowed cipher suites
    CertificateValidation func(*x509.Certificate) error
    RequireOCSPStapling   bool         // OCSP validation
}

// Input validation configuration
type ValidationConfig struct {
    StrictMode              bool        // Strict validation mode
    BlockSuspiciousPatterns bool        // Injection detection
    ValidateUTF8           bool        // UTF-8 validation
    MaxFilterComplexity    int         // Filter complexity limits
}
```

### Security Features Matrix

| Feature | Basic Client | Secure Client | Description |
|---------|-------------|---------------|-------------|
| Input Validation | Basic | Comprehensive | LDAP filter, DN, attribute validation |
| Injection Prevention | Escaping only | Detection + Blocking | Advanced pattern detection |
| TLS Configuration | Basic | Advanced | Cipher suites, certificate validation |
| Credential Security | None | Full | Secure storage, zeroization |
| Rate Limiting | None | Yes | Request rate and concurrency limits |
| Security Auditing | None | Comprehensive | Event logging and monitoring |
| Access Control | None | IP-based | Network-level access restrictions |

## Secure Configuration

### Production Configuration

```go
// Production-ready secure configuration
config := ldap.SecureConfig{
    Config: ldap.Config{
        Server:            "ldaps://ldap.production.com:636",
        BaseDN:            "DC=production,DC=com",
        IsActiveDirectory: true,
        Logger:            slog.New(slog.NewJSONHandler(os.Stdout, nil)),
    },
    Security: &ldap.SecurityConfig{
        MaxRequestsPerSecond: 100,
        MaxConcurrentOps:     50,
        AuditLog:            true,
        SecurityEventLog:    true,
        StrictValidation:    true,
        ZeroizeCredentials:  true,
    },
    TLS: &ldap.TLSConfig{
        MinVersion:           tls.VersionTLS12,
        CipherSuites:         ldap.SecureCipherSuites,
        InsecureSkipVerify:   false,
        RequireOCSPStapling:  true,
    },
    Validation: &ldap.ValidationConfig{
        StrictMode:              true,
        BlockSuspiciousPatterns: true,
        ValidateUTF8:           true,
        MaxFilterComplexity:    10,
    },
}

// Validate configuration before use
if err := ldap.ValidateConfigSecurity(config); err != nil {
    log.Fatalf("Security configuration invalid: %v", err)
}

client, err := ldap.NewSecureLDAP(config, username, password)
if err != nil {
    log.Fatalf("Failed to create secure client: %v", err)
}
defer client.Close()
```

### Development Configuration

```go
// Development configuration with relaxed security
devConfig := ldap.SecureConfig{
    Config: ldap.Config{
        Server: "ldap://localhost:389",  // Unencrypted OK for dev
        BaseDN: "DC=dev,DC=local",
    },
    Security: &ldap.SecurityConfig{
        MaxRequestsPerSecond: 1000,      // Higher limits for testing
        StrictValidation:    false,      // Allow more flexibility
        AuditLog:           true,        // Still log for debugging
    },
    TLS: &ldap.TLSConfig{
        InsecureSkipVerify: true,        // Allow self-signed certs
        MinVersion:        tls.VersionTLS12,
    },
}
```

## Input Validation

### Validation Layers

1. **Syntax Validation**: Format and structure validation
2. **Content Validation**: Semantic and business logic validation
3. **Security Validation**: Injection and attack pattern detection
4. **Length Validation**: Prevent buffer overflow and DoS attacks

### DN Validation

```go
// Validate and normalize distinguished names
normalizedDN, err := ldap.ValidateDN("CN=John Doe, OU=Users, DC=example, DC=com")
if err != nil {
    // Handle invalid DN
}

// Validation checks:
// - Syntax: proper attribute=value format
// - Length: within reasonable limits
// - Characters: no control characters or null bytes
// - Structure: valid DN components
// - Security: no injection patterns
```

### Filter Validation

```go
// Validate LDAP search filters
err := ldap.ValidateLDAPFilter("(&(objectClass=user)(sAMAccountName=john.doe))")
if err != nil {
    // Handle invalid filter
}

// Validation checks:
// - Parentheses balance
// - Syntax correctness
// - Complexity limits
// - Injection pattern detection
// - UTF-8 validity
```

### Comprehensive Validation

```go
validator := ldap.NewValidator(ldap.DefaultValidationConfig())

// Validate multiple inputs
dnResult := validator.ValidateDNSyntax(userDN)
filterResult := validator.ValidateFilter(searchFilter)
credResult := validator.ValidateCredentials(username, password)

// Check results
if !dnResult.Valid {
    log.Printf("DN validation failed: %v", dnResult.Errors)
}

if filterResult.ThreatContext != nil {
    log.Printf("Security threat detected: %s", filterResult.ThreatContext.ThreatType)
}
```

## TLS Security

### Secure TLS Configuration

```go
tlsConfig := &ldap.TLSConfig{
    // Require TLS 1.2 minimum
    MinVersion: tls.VersionTLS12,
    
    // Use only secure cipher suites
    CipherSuites: []uint16{
        tls.TLS_AES_256_GCM_SHA384,         // TLS 1.3
        tls.TLS_AES_128_GCM_SHA256,         // TLS 1.3
        tls.TLS_CHACHA20_POLY1305_SHA256,   // TLS 1.3
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // TLS 1.2
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,   // TLS 1.2
    },
    
    // Server name for SNI
    ServerName: "ldap.example.com",
    
    // Never skip certificate verification in production
    InsecureSkipVerify: false,
    
    // Custom certificate validation
    CertificateValidation: func(cert *x509.Certificate) error {
        // Check certificate organization
        if len(cert.Subject.Organization) == 0 {
            return fmt.Errorf("certificate must have organization")
        }
        
        // Check certificate validity period
        if time.Until(cert.NotAfter) < 30*24*time.Hour {
            return fmt.Errorf("certificate expires too soon")
        }
        
        // Check key usage
        if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
            return fmt.Errorf("certificate must support digital signatures")
        }
        
        return nil
    },
}
```

### Certificate Validation

- **Chain Validation**: Verify entire certificate chain
- **Hostname Validation**: Ensure certificate matches server hostname
- **Revocation Checking**: Check OCSP/CRL status
- **Key Usage**: Validate certificate is authorized for intended use
- **Expiry Validation**: Ensure certificate is not expired or expiring soon

## Credential Management

### Secure Credential Handling

```go
// Create secure credential
password := "MySecurePassword123!"
credential := ldap.NewSecureCredential(password)

// Use credential
if !credential.IsZeroized() {
    username := credential.String()
    // Use for authentication
}

// Always zeroize when done
defer credential.Zeroize()

// Credential is now safely erased from memory
fmt.Printf("Zeroized: %v", credential.IsZeroized()) // true
fmt.Printf("Value: %q", credential.String())        // ""
```

### Credential Providers

```go
// Custom credential provider
type vaultCredentialProvider struct {
    vaultPath string
}

func (p *vaultCredentialProvider) GetCredentials(ctx context.Context) (string, string, error) {
    // Retrieve from secure vault (HashiCorp Vault, Azure Key Vault, etc.)
    return p.retrieveFromVault(ctx)
}

func (p *vaultCredentialProvider) RefreshCredentials(ctx context.Context) error {
    // Refresh credentials from vault
    return p.refreshVaultCredentials(ctx)
}

// Use with secure client
config.CredentialProvider = &vaultCredentialProvider{
    vaultPath: "/secret/ldap/credentials",
}
```

### Anti-Timing Attack Protection

```go
// Use timing-safe comparison for sensitive data
func validatePassword(provided, stored string) bool {
    // WRONG: Vulnerable to timing attacks
    // return provided == stored
    
    // RIGHT: Timing-safe comparison
    return ldap.TimingSafeEqual(provided, stored)
}
```

## Attack Prevention

### LDAP Injection Prevention

#### Common Injection Patterns Detected

```go
injectionPatterns := []string{
    "*)(objectClass=*",          // Wildcard injection
    "*)(&(objectClass=*",        // Complex filter manipulation
    "*))%00",                    // Null byte injection
    ")(userPassword=*",          // Password enumeration
    "|(userAccountControl=*",    // Account control bypass
}

for _, pattern := range injectionPatterns {
    threat := ldap.DetectInjectionAttempt(pattern)
    if threat != nil {
        log.Printf("Injection detected: %s (Risk: %.2f)", 
            threat.ThreatType, threat.RiskScore)
    }
}
```

#### Safe Filter Construction

```go
// WRONG: String concatenation vulnerable to injection
userInput := "test*)(objectClass=*"
unsafeFilter := fmt.Sprintf("(sAMAccountName=%s)", userInput)

// RIGHT: Proper escaping prevents injection
safeFilter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilterValue(userInput))

// BEST: Use validation in addition to escaping
if err := ldap.ValidateLDAPFilter(safeFilter); err != nil {
    return fmt.Errorf("filter validation failed: %w", err)
}
```

### Rate Limiting and DoS Prevention

```go
// Configure rate limiting
rateLimiter := ldap.NewRateLimiter(100, time.Second) // 100 req/sec

// Check before processing request
if !rateLimiter.Allow(clientID) {
    return errors.New("rate limit exceeded")
}

// Process request...
```

### Access Control

```go
// IP-based access control
allowedNetworks := []net.IPNet{
    // Internal networks only
    {IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
    {IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
}

securityConfig := &ldap.SecurityConfig{
    IPWhitelist: allowedNetworks,
}
```

## Security Monitoring

### Security Event Logging

```go
// Create security auditor
auditor := ldap.NewSecurityAuditor(securityConfig)
defer auditor.Close()

// Log security events
auditor.LogSecurityEvent("authentication_success", ldap.SecurityInfo, 
    "Authentication", username, map[string]interface{}{
        "source_ip": clientIP,
        "method":   "bind",
    })

auditor.LogSecurityEvent("injection_attempt", ldap.SecurityCritical,
    "Search", username, map[string]interface{}{
        "filter":    suspiciousFilter,
        "source_ip": clientIP,
        "blocked":   true,
    })
```

### Security Metrics

```go
// Get security metrics from secure client
metrics := client.GetSecurityMetrics()

// Monitor key security indicators
log.Printf("Security metrics: %+v", map[string]interface{}{
    "rate_limits_active":     metrics["active_rate_limits"],
    "credentials_secure":     !metrics["credentials_zeroized"].(bool),
    "strict_validation":      metrics["strict_validation"],
    "tls_enabled":           metrics["tls_enabled"],
    "audit_enabled":         metrics["audit_enabled"],
})
```

### Threat Intelligence Integration

```go
// Custom threat detection
func analyzeSecurityEvents(events []ldap.SecurityAuditEvent) {
    for _, event := range events {
        if event.Severity == ldap.SecurityCritical {
            // Alert security team
            alertSecurityTeam(event)
        }
        
        if event.Threat != nil && event.Threat.RequiresAction {
            // Take automated action
            blockIPAddress(event.RemoteIP)
        }
    }
}
```

## Best Practices

### Production Deployment

1. **Always Use LDAPS**: Never use unencrypted LDAP in production
2. **Certificate Validation**: Always validate server certificates
3. **Strong Authentication**: Use complex passwords and consider certificate-based auth
4. **Input Validation**: Enable strict validation mode
5. **Rate Limiting**: Implement appropriate rate limits
6. **Security Monitoring**: Enable comprehensive audit logging
7. **Credential Management**: Use secure credential storage and rotation
8. **Network Security**: Restrict network access to LDAP servers

### Development Guidelines

1. **Security by Default**: Use secure defaults in all configurations
2. **Validate All Inputs**: Never trust user input
3. **Escape LDAP Values**: Always escape filter values properly
4. **Handle Errors Securely**: Don't leak sensitive information in errors
5. **Test Security Features**: Include security tests in your test suite
6. **Regular Updates**: Keep the library updated for security fixes

### Code Examples

#### Secure Authentication

```go
func authenticateUser(client *ldap.SecureLDAP, username, password string) error {
    // Use secure bind with validation
    err := client.SecureBindContext(ctx, username, password)
    if err != nil {
        if ldap.IsAuthenticationError(err) {
            // Handle authentication failure securely
            log.Printf("Authentication failed for user: %s", username)
            return errors.New("invalid credentials")
        }
        return fmt.Errorf("authentication error: %w", err)
    }
    
    return nil
}
```

#### Secure Search

```go
func searchUsers(client *ldap.SecureLDAP, searchTerm string) ([]*ldap.User, error) {
    // Properly escape search term
    escapedTerm := ldap.EscapeFilterValue(searchTerm)
    
    // Create secure search request
    searchRequest := &ldap.SearchRequest{
        BaseDN: "OU=Users,DC=example,DC=com",
        Filter: fmt.Sprintf("(&(objectClass=user)(cn=*%s*))", escapedTerm),
        Attributes: []string{"cn", "mail", "sAMAccountName"},
    }
    
    // Perform secure search with validation
    result, err := client.SecureSearchContext(ctx, searchRequest)
    if err != nil {
        return nil, fmt.Errorf("search failed: %w", err)
    }
    
    // Process results...
    return processSearchResults(result), nil
}
```

#### Error Handling

```go
func handleLDAPError(err error) {
    if ldap.IsAuthenticationError(err) {
        // Don't leak authentication details
        log.Info("authentication failed")
        return
    }
    
    if ldap.IsConnectionError(err) {
        // Log connection issues for ops team
        log.Error("LDAP connection failed", "error", err)
        return
    }
    
    if ldap.IsValidationError(err) {
        // Log validation failures for security team
        log.Warn("input validation failed", "error", err)
        return
    }
    
    // Generic error handling
    log.Error("LDAP operation failed", "error", err)
}
```

## Security Checklist

### Configuration Security

- [ ] Use LDAPS (port 636) in production
- [ ] Configure minimum TLS version (1.2 or higher)
- [ ] Use secure cipher suites only
- [ ] Enable certificate validation
- [ ] Configure proper certificate validation logic
- [ ] Set appropriate connection timeouts
- [ ] Enable strict input validation
- [ ] Configure rate limiting
- [ ] Set up IP-based access control
- [ ] Enable comprehensive audit logging

### Code Security

- [ ] Always escape LDAP filter values
- [ ] Validate all user inputs
- [ ] Use secure credential handling
- [ ] Implement proper error handling
- [ ] Never log sensitive information
- [ ] Use timing-safe comparisons for sensitive data
- [ ] Zeroize credentials after use
- [ ] Handle context cancellation properly
- [ ] Implement proper retry logic with backoff
- [ ] Use structured logging for security events

### Deployment Security

- [ ] Use secure credential storage (vaults, environment variables)
- [ ] Implement credential rotation
- [ ] Monitor security events and alerts
- [ ] Set up intrusion detection
- [ ] Configure network segmentation
- [ ] Implement defense in depth
- [ ] Regular security assessments
- [ ] Keep library updated
- [ ] Monitor for CVEs
- [ ] Test disaster recovery procedures

### Monitoring and Alerting

- [ ] Monitor authentication failures
- [ ] Alert on injection attempts
- [ ] Track rate limit violations
- [ ] Monitor certificate expiry
- [ ] Log all security events
- [ ] Set up SIEM integration
- [ ] Regular security reviews
- [ ] Incident response procedures
- [ ] Security metrics dashboard
- [ ] Automated threat response

## Conclusion

The simple-ldap-go library provides comprehensive security features that, when properly configured and used, offer strong protection against common LDAP security threats. By following this security guide and implementing the recommended practices, you can ensure your LDAP operations are secure and compliant with industry standards.

For additional security concerns or to report security issues, please contact the maintainers through the project's security channels.