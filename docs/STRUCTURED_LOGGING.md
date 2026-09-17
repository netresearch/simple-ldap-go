# Structured Logging with Go 1.21+ log/slog

This document describes the structured logging implementation in the simple-ldap-go library using Go 1.21+ `log/slog` package.

## Overview

The library now provides comprehensive structured logging for all LDAP operations including:
- Connection establishment and teardown
- Authentication attempts (success/failure) 
- Search operations (DN, filter, results count)
- CRUD operations (create, update, delete with DN)
- Error conditions with context
- Performance metrics (operation duration)

## Configuration

### Basic Setup

```go
import (
    "log/slog"
    "os"
    ldap "github.com/netresearch/simple-ldap-go"
)

// Create a JSON logger
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

config := ldap.Config{
    Server:            "ldaps://ad.example.com:636",
    BaseDN:            "DC=example,DC=com", 
    IsActiveDirectory: true,
    Logger:            logger, // Add structured logging
}

client, err := ldap.New(config, "CN=admin,CN=Users,DC=example,DC=com", "password")
```

### Default Logger

A nil `Logger` does not mean silence. The client falls back to `slog.Default()`
(`client.go`), so the process-wide handler receives the library's output -
including `ldap_client_initializing` at INFO before anything else happens.

```go
config := ldap.Config{
    Server: "ldaps://ad.example.com:636",
    BaseDN: "DC=example,DC=com",
    // Logger is nil - output goes to slog.Default()
}
```

To discard everything, pass a handler that drops records:

```go
config.Logger = slog.New(slog.DiscardHandler)
```

A logger can also be supplied as an option to `New`, which overrides
`Config.Logger`:

```go
client, err := ldap.New(config, bindDN, password, ldap.WithLogger(logger))
```

### Different Log Levels

```go
// Debug level - logs everything including detailed operation traces
debugLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

// Info level - logs successful operations and errors (recommended for production)
infoLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

// Error level - only logs error conditions
errorLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelError,
}))
```

### Text vs JSON Output

```go
// JSON output (structured, machine-readable)
jsonLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

// Text output (human-readable)
textLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))
```

### File Logging

```go
logFile, err := os.OpenFile("ldap.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
if err != nil {
    panic(err)
}
defer logFile.Close()

fileLogger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))
```

## Log Entry Examples

### Connection Establishment

```json
{
  "time": "2024-01-15T10:30:00.123456Z",
  "level": "DEBUG",
  "msg": "ldap_connection_establishing",
  "server": "ldaps://ad.example.com:636"
}

{
  "time": "2024-01-15T10:30:00.156789Z", 
  "level": "DEBUG",
  "msg": "ldap_connection_established",
  "server": "ldaps://ad.example.com:636",
  "duration": "33.333ms"
}
```

### Authentication

```json
{
  "time": "2024-01-15T10:30:01.123456Z",
  "level": "INFO", 
  "msg": "authentication_successful",
  "operation": "CheckPasswordForSAMAccountName",
  "username_masked": "jd**e",
  "client_ip_masked": "19*****10",
  "duration": "245.678ms"
}

{
  "time": "2024-01-15T10:30:02.123456Z",
  "level": "WARN",
  "msg": "authentication_failed", 
  "operation": "CheckPasswordForSAMAccountName",
  "username_masked": "jd**e",
  "client_ip_masked": "19*****10",
  "error_type": "bind_failed",
  "error": "LDAP Result Code 49 \"Invalid Credentials\"",
  "duration": "156.789ms"
}
```

The identifiers are masked, and the attribute names say so: `username_masked`,
`dn_masked`, `client_ip_masked` (`auth.go`). `CheckPasswordForDN` logs
`dn_masked` in place of `username_masked`.

`error_type` takes one of two values on this message: `bind_failed` when the
user's bind is refused, and `user_lookup_failed` when the account could not be
found at all.

### Search Operations

```json
{
  "time": "2024-01-15T10:30:03.123456Z",
  "level": "DEBUG",
  "msg": "user_found_by_sam_account",
  "operation": "FindUserBySAMAccountName", 
  "username_masked": "jd**e",
  "dn_masked": "CN**************************om",
  "duration": "89.123ms"
}

{
  "time": "2024-01-15T10:30:04.123456Z",
  "level": "INFO",
  "msg": "user_list_search_completed",
  "operation": "FindUsers",
  "total_found": 1542,
  "processed": 1542,
  "skipped": 0,
  "duration": "2.345s"
}
```

### Group Operations

```json
{
  "time": "2024-01-15T10:30:05.123456Z",
  "level": "INFO",
  "msg": "user_group_add_successful", 
  "operation": "AddUserToGroup",
  "user_dn": "CN=John Doe,CN=Users,DC=example,DC=com",
  "group_dn": "CN=IT Department,CN=Groups,DC=example,DC=com",
  "duration": "123.456ms"
}
```

### Password Changes

```json
{
  "time": "2024-01-15T10:30:06.123456Z",
  "level": "INFO",
  "msg": "password_change_successful",
  "operation": "ChangePasswordForSAMAccountName",
  "username_masked": "jd**e", 
  "dn": "CN=John Doe,CN=Users,DC=example,DC=com",
  "duration": "456.789ms"
}
```

Masking is not applied everywhere. This record carries `dn` in full next to a
masked username (`auth.go`), and the group operations below log `user_dn` and
`group_dn` unmasked. Treat the output as containing directory identifiers and
size the log retention accordingly.

### Error Conditions

```json
{
  "time": "2024-01-15T10:30:07.123456Z",
  "level": "DEBUG",
  "msg": "user_not_found_by_sam_account",
  "operation": "FindUserBySAMAccountName",
  "username_masked": "no*********nt",
  "duration": "78.901ms"
}
```

## Security Considerations

### Password Protection

**Passwords are NEVER logged** - The library carefully avoids logging any password values:

```go
// This is safe - password won't appear in logs
user, err := client.CheckPasswordForSAMAccountName("jdoe", "secret123")
```

### Username Masking

Masking does not depend on the level. Where an attribute name ends in `_masked`,
the value went through `maskSensitiveData` (`security.go`): it keeps the
first and last two runes and replaces the middle with asterisks, or returns
`***` for anything up to four runes. It works on runes, so multi-byte
identifiers are not split into invalid UTF-8, and it has no exemption for
`example.com` or `test.com` - a control that returned test-looking values
verbatim would leak real identifiers at those domains (#215).

Attributes without the suffix are not masked. `password_change_successful`
logs `dn` in full, and the group operations log `user_dn` and `group_dn` in
full.

## Performance Impact

### Overhead

A nil `Logger` is not free: the library logs to `slog.Default()` instead. Raise
the level on the handler, or set `slog.New(slog.DiscardHandler)`, to get the
no-cost path.

### Efficient Structured Logging

The slog package provides efficient structured logging with minimal allocations:
- Field values are only processed if the log level allows the message
- Duration measurements use high-precision timers
- JSON marshalling is optimized for common field types

### Performance Monitoring

All operations include duration measurements:

```json
{
  "msg": "authentication_successful",
  "duration": "245.678ms"  // Precise timing for performance monitoring
}
```

## Integration with Observability Tools

### Prometheus/Grafana

Parse JSON logs to extract duration metrics:

```bash
# Extract authentication times
jq -r 'select(.msg == "authentication_successful") | .duration' ldap.log

# Count failed authentications per hour
jq -r 'select(.msg == "authentication_failed") | .time[0:13]' ldap.log | sort | uniq -c
```

### ELK Stack

Use structured JSON logs directly in Elasticsearch:

```json
{
  "index": "ldap-logs-*",
  "mappings": {
    "properties": {
      "time": { "type": "date" },
      "level": { "type": "keyword" },
      "msg": { "type": "keyword" },
      "operation": { "type": "keyword" },
      "username": { "type": "keyword" },
      "duration": { "type": "keyword" }
    }
  }
}
```

### Custom Handlers

Create custom slog handlers for integration with other systems:

```go
// Custom handler that sends logs to a monitoring system
type MetricsHandler struct {
    base slog.Handler
    metrics MetricsCollector
}

func (h *MetricsHandler) Handle(ctx context.Context, r slog.Record) error {
    // Send metrics to monitoring system
    if r.Message == "authentication_successful" {
        h.metrics.IncrementCounter("ldap_auth_success")
    }
    return h.base.Handle(ctx, r)
}
```

## Best Practices

### Production Configuration

```go
// Recommended production setup
logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
    Level: slog.LevelInfo,        // Info and above
    AddSource: false,             // Don't include source locations
    ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
        // Add environment context
        if a.Key == slog.TimeKey {
            return slog.Attr{Key: "timestamp", Value: a.Value}
        }
        return a
    },
}))

// Add application context
contextLogger := logger.With(
    slog.String("service", "user-management"),
    slog.String("version", "1.2.3"),
    slog.String("environment", "production"),
)

config.Logger = contextLogger
```

### Log Rotation

Use log rotation for production deployments:

```go
import "gopkg.in/natefinch/lumberjack.v2"

logWriter := &lumberjack.Logger{
    Filename:   "ldap.log",
    MaxSize:    100, // MB
    MaxBackups: 3,
    MaxAge:     28, // days
    Compress:   true,
}

logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))
```

### Error Correlation

Use context to correlate related operations:

```go
ctx := context.WithValue(context.Background(), "request_id", "req-123")

// All operations in this context will be traceable
user, err := client.FindUserBySAMAccountNameContext(ctx, "jdoe")
err = client.AddUserToGroupContext(ctx, user.DN(), groupDN)
```

## Migration Guide

### From No Logging

```go
// Before
client, err := ldap.New(config, user, password)

// After  
config.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
client, err := ldap.New(config, user, password)
```

### From Custom Logging

```go
// Before - custom logging in application code
user, err := client.CheckPasswordForSAMAccountName(username, password)
if err != nil {
    log.Printf("Auth failed for %s: %v", username, err)
} else {
    log.Printf("Auth success for %s", username) 
}

// After - structured logging built-in
user, err := client.CheckPasswordForSAMAccountName(username, password)
// Logging is automatic and structured
```

## Troubleshooting

### No Log Output

If you're not seeing logs:

1. Check logger is configured: `config.Logger != nil`
2. Check log level: ensure your operations exceed the configured level
3. Check output destination: stdout, file, etc.

### Too Much Logging

To reduce log volume:

1. Increase log level to `slog.LevelWarn` or `slog.LevelError`
2. Use custom handler to filter specific operations
3. Configure log rotation

### Performance Issues

If logging impacts performance:

1. Use async handlers for high-volume operations
2. Set log level to `slog.LevelError` for minimal logging
3. Consider sampling high-frequency operations

## Complete Example

```go
package main

import (
    "context"
    "log/slog"
    "os"
    "time"
    
    ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
    // Setup structured logging
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    })).With(
        slog.String("service", "auth-service"),
        slog.String("version", "1.0.0"),
    )
    
    // Configure LDAP client with logging
    config := ldap.Config{
        Server:            "ldaps://ad.company.com:636",
        BaseDN:            "DC=company,DC=com",
        IsActiveDirectory: true,
        Logger:            logger,
    }
    
    client, err := ldap.New(config, "CN=service,CN=Users,DC=company,DC=com", "password")
    if err != nil {
        logger.Error("Failed to create LDAP client", slog.String("error", err.Error()))
        return
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // All operations will now be logged with structured data
    user, err := client.CheckPasswordForSAMAccountNameContext(ctx, "jdoe", "userpass")
    if err != nil {
        logger.Error("Authentication failed", 
            slog.String("username", "jdoe"),
            slog.String("error", err.Error()))
        return
    }
    
    logger.Info("User authenticated successfully",
        slog.String("username", user.SAMAccountName),
        slog.String("dn", user.DN()))
    
    // Search operations
    users, err := client.FindUsersContext(ctx)
    if err != nil {
        logger.Error("User search failed", slog.String("error", err.Error()))
        return
    }
    
    logger.Info("User search completed", slog.Int("count", len(users)))
}
```

This produces structured log output like:

```json
{"time":"2024-01-15T10:30:00.123456Z","level":"INFO","msg":"ldap_client_initialized_successfully","server":"ldaps://ad.company.com:636","duration":"45.678ms","service":"auth-service","version":"1.0.0"}
{"time":"2024-01-15T10:30:01.234567Z","level":"INFO","msg":"authentication_successful","operation":"CheckPasswordForSAMAccountName","username_masked":"jd**e","client_ip_masked":"19*****10","duration":"156.789ms","service":"auth-service","version":"1.0.0"}
{"time":"2024-01-15T10:30:02.345678Z","level":"INFO","msg":"user_list_search_completed","operation":"FindUsers","total_found":1542,"processed":1542,"skipped":0,"duration":"2.345s","service":"auth-service","version":"1.0.0"}
```