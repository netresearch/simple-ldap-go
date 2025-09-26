# LDAP Resilience Guide

This guide explains the resilience features available in the simple-ldap-go library, focusing on the circuit breaker pattern that protects your application from failing LDAP servers.

## Table of Contents

- [Overview](#overview)
- [Circuit Breaker Pattern](#circuit-breaker-pattern)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Monitoring](#monitoring)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

The simple-ldap-go library provides built-in resilience features to protect your application from cascading failures when LDAP servers become unavailable. The primary mechanism is the **Circuit Breaker** pattern, which prevents your application from repeatedly trying to connect to a failing service.

### Benefits

- **Fast Failure**: Returns errors immediately when LDAP is down (milliseconds vs 30+ second timeouts)
- **Resource Protection**: Prevents connection attempt storms during outages
- **Automatic Recovery**: Periodically tests if the service has recovered
- **Better User Experience**: Provides clear error messages when service is unavailable
- **Production Resilience**: Protects against cascading failures in microservice architectures

## Circuit Breaker Pattern

The circuit breaker works like an electrical circuit breaker - it "trips" (opens) when too many failures occur, preventing further damage.

### States

1. **CLOSED** (Normal Operation)
   - All requests pass through to LDAP
   - Failures are counted
   - Transitions to OPEN after threshold is reached

2. **OPEN** (Fast Failing)
   - All requests fail immediately with `CircuitBreakerError`
   - No connection attempts are made
   - After timeout, transitions to HALF_OPEN

3. **HALF_OPEN** (Testing Recovery)
   - Limited requests are allowed through
   - If successful, transitions to CLOSED
   - If any fail, transitions back to OPEN

```
Normal Operation          Service Down              Testing Recovery
    [CLOSED] ──────────> [OPEN] ──────────> [HALF_OPEN]
        ^                    ^                    │
        │                    │                    │
        └────────────────────┴────────────────────┘
         Success             Failure
```

## Configuration

### Basic Configuration

Circuit breaker is **disabled by default** for backward compatibility. Enable it explicitly:

```go
import (
    ldap "github.com/netresearch/simple-ldap-go"
)

// Method 1: Via Config struct
config := &ldap.Config{
    Server: "ldap://ldap.example.com",
    Port:   389,
    BaseDN: "dc=example,dc=com",
    Resilience: &ldap.ResilienceConfig{
        EnableCircuitBreaker: true,
        CircuitBreaker: &ldap.CircuitBreakerConfig{
            MaxFailures:         5,                    // Open after 5 consecutive failures
            Timeout:             30 * time.Second,     // Wait 30s before trying again
            HalfOpenMaxRequests: 3,                    // Allow 3 test requests in half-open
        },
    },
}

client, err := ldap.New(config, "username", "password")
```

### Using Functional Options

```go
// Method 2: Using WithCircuitBreaker option
config := &ldap.Config{
    Server: "ldap://ldap.example.com",
    Port:   389,
    BaseDN: "dc=example,dc=com",
}

client, err := ldap.New(config, "username", "password",
    ldap.WithCircuitBreaker(&ldap.CircuitBreakerConfig{
        MaxFailures: 3,
        Timeout:     1 * time.Minute,
    }),
)
```

### Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MaxFailures` | 5 | Number of consecutive failures before opening circuit |
| `Timeout` | 30s | How long to wait in OPEN state before testing recovery |
| `HalfOpenMaxRequests` | 3 | Maximum requests allowed in HALF_OPEN state |

### Default Configuration

Use the provided defaults for most applications:

```go
config.Resilience = &ldap.ResilienceConfig{
    EnableCircuitBreaker: true,
    CircuitBreaker: ldap.DefaultCircuitBreakerConfig(), // 5 failures, 30s timeout, 3 half-open requests
}
```

## Usage Examples

### Basic Usage with Iterators

All iterators automatically benefit from circuit breaker protection:

```go
// SearchIter with circuit breaker
searchRequest := ldap.NewSearchRequest(
    "dc=example,dc=com",
    ldap.ScopeWholeSubtree,
    ldap.NeverDerefAliases, 0, 0, false,
    "(objectClass=person)",
    []string{"cn", "mail"},
    nil,
)

for entry, err := range client.SearchIter(ctx, searchRequest) {
    if err != nil {
        // Could be a CircuitBreakerError if LDAP is down
        if strings.Contains(err.Error(), "circuit breaker") {
            log.Printf("LDAP service is currently unavailable")
            return
        }
        log.Printf("Search error: %v", err)
        break
    }

    // Process entry
    fmt.Printf("User: %s\n", entry.GetAttributeValue("cn"))
}
```

### Handling Circuit Breaker Errors

```go
// Check for specific circuit breaker error
conn, err := client.GetConnectionProtected()
if err != nil {
    var cbErr *ldap.CircuitBreakerError
    if errors.As(err, &cbErr) {
        log.Printf("Circuit breaker is %s", cbErr.State)
        log.Printf("Failed %d times", cbErr.Failures)
        log.Printf("Will retry at %v", cbErr.NextRetry)

        // Implement fallback logic
        return handleLDAPUnavailable()
    }
    return err
}
defer conn.Close()
```

### Monitoring Circuit Breaker State

```go
// Get circuit breaker statistics
stats := client.GetCircuitBreakerStats()
if stats != nil {
    fmt.Printf("Circuit Breaker Status:\n")
    fmt.Printf("  State: %s\n", stats["state"])
    fmt.Printf("  Failures: %d\n", stats["failures"])
    fmt.Printf("  Total Requests: %d\n", stats["requests"])
    fmt.Printf("  Success Rate: %.2f%%\n", stats["success_rate"].(float64) * 100)

    if stats["state"] == "OPEN" {
        fmt.Printf("  Next Retry: %v\n", stats["next_retry"])
    }
}
```

### High-Traffic Application Example

```go
// Configure for high-traffic scenarios
config := &ldap.Config{
    Server: "ldap://ldap.example.com",
    Port:   389,
    BaseDN: "dc=example,dc=com",
    Resilience: &ldap.ResilienceConfig{
        EnableCircuitBreaker: true,
        CircuitBreaker: &ldap.CircuitBreakerConfig{
            MaxFailures:         10,                   // More tolerance for transient issues
            Timeout:             10 * time.Second,     // Faster recovery checks
            HalfOpenMaxRequests: 5,                    // More test requests
        },
    },
}

// Authentication endpoint with circuit breaker
func authenticateUser(username, password string) error {
    user, err := ldapClient.AuthenticateUser(username, password)
    if err != nil {
        // Fast failure if LDAP is down
        if strings.Contains(err.Error(), "circuit breaker") {
            // Return cached result or degraded service
            return handleDegradedAuth(username)
        }
        return err
    }
    return nil
}
```

## Monitoring

### Metrics to Track

1. **Circuit State Changes**
   - Log when circuit opens/closes
   - Alert on extended OPEN states

2. **Failure Rates**
   - Track failure count over time
   - Set thresholds for alerts

3. **Recovery Time**
   - Monitor how long circuit stays open
   - Track successful recovery patterns

### Example Monitoring Integration

```go
// Prometheus metrics example
var (
    circuitBreakerState = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ldap_circuit_breaker_state",
            Help: "Circuit breaker state (0=closed, 1=open, 2=half-open)",
        },
        []string{"server"},
    )

    ldapFailures = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ldap_connection_failures_total",
            Help: "Total LDAP connection failures",
        },
        []string{"server"},
    )
)

// Update metrics periodically
go func() {
    ticker := time.NewTicker(10 * time.Second)
    for range ticker.C {
        stats := client.GetCircuitBreakerStats()
        if stats != nil {
            state := 0
            switch stats["state"] {
            case "OPEN":
                state = 1
            case "HALF_OPEN":
                state = 2
            }
            circuitBreakerState.WithLabelValues(config.Server).Set(float64(state))
            ldapFailures.WithLabelValues(config.Server).Set(float64(stats["failures"].(int64)))
        }
    }
}()
```

## Best Practices

### 1. Configure Appropriately for Your Environment

- **Development**: May want to disable or use high thresholds
- **Staging**: Use production-like settings for testing
- **Production**: Balance between stability and recovery speed

### 2. Implement Fallback Strategies

```go
func getUserGroups(userDN string) ([]string, error) {
    groups, err := ldapClient.GetUserGroups(userDN)
    if err != nil {
        if strings.Contains(err.Error(), "circuit breaker") {
            // Fall back to cached groups
            return cache.GetUserGroups(userDN)
        }
        return nil, err
    }

    // Update cache for future fallback
    cache.SetUserGroups(userDN, groups)
    return groups, nil
}
```

### 3. Log Circuit Breaker Events

```go
// Configure logger to capture circuit breaker events
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug, // Capture circuit breaker debug logs
}))

config.Logger = logger
```

### 4. Test Circuit Breaker Behavior

```go
func TestCircuitBreakerIntegration(t *testing.T) {
    // Simulate LDAP failures
    mockLDAP := startMockLDAPServer()
    defer mockLDAP.Stop()

    config := createConfigWithCircuitBreaker()
    client := createClient(config)

    // Trigger failures
    mockLDAP.SetFailureMode(true)

    // Verify fast failure after threshold
    start := time.Now()
    _, err := client.SearchIter(ctx, searchRequest)
    elapsed := time.Since(start)

    assert.Error(t, err)
    assert.Contains(t, err.Error(), "circuit breaker")
    assert.Less(t, elapsed, 100*time.Millisecond) // Fast failure
}
```

## Troubleshooting

### Circuit Breaker Opens Too Frequently

**Symptoms**: Circuit breaker opens even with occasional failures

**Solutions**:
- Increase `MaxFailures` threshold
- Check for transient network issues
- Verify LDAP server health

```go
// More tolerant configuration
CircuitBreaker: &ldap.CircuitBreakerConfig{
    MaxFailures: 10,  // Increased from 5
    Timeout:     30 * time.Second,
}
```

### Circuit Breaker Never Recovers

**Symptoms**: Circuit stays open even after LDAP recovers

**Solutions**:
- Decrease `Timeout` for faster recovery attempts
- Check network connectivity
- Verify LDAP credentials haven't expired

```go
// Faster recovery configuration
CircuitBreaker: &ldap.CircuitBreakerConfig{
    MaxFailures: 5,
    Timeout:     10 * time.Second,  // Reduced from 30s
    HalfOpenMaxRequests: 5,          // More test attempts
}
```

### Performance Impact

**Symptoms**: Slight overhead even when circuit is closed

**Solutions**:
- Circuit breaker overhead is minimal (~1-2ns per check)
- For ultra-low-latency requirements, disable circuit breaker
- Use connection pooling to offset any overhead

### Debugging Circuit Breaker State

```go
// Enable debug logging
config.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

// Check state programmatically
stats := client.GetCircuitBreakerStats()
fmt.Printf("Debug: Circuit breaker state = %+v\n", stats)

// Force reset if needed (use with caution)
if client.circuitBreaker != nil {
    client.circuitBreaker.Reset()
}
```

## Advanced Scenarios

### Multiple LDAP Servers with Independent Circuit Breakers

```go
// Create clients for each LDAP server with independent circuit breakers
primary := createClientWithCircuitBreaker("ldap://primary.example.com")
secondary := createClientWithCircuitBreaker("ldap://secondary.example.com")

func searchWithFailover(ctx context.Context, filter string) ([]*ldap.Entry, error) {
    // Try primary first
    entries, err := searchWithClient(ctx, primary, filter)
    if err == nil {
        return entries, nil
    }

    // If primary fails with circuit breaker, try secondary
    if strings.Contains(err.Error(), "circuit breaker") {
        log.Printf("Primary LDAP unavailable, trying secondary")
        return searchWithClient(ctx, secondary, filter)
    }

    return nil, err
}
```

### Gradual Recovery Testing

```go
// Custom configuration for gradual recovery
config.Resilience = &ldap.ResilienceConfig{
    EnableCircuitBreaker: true,
    CircuitBreaker: &ldap.CircuitBreakerConfig{
        MaxFailures:         5,
        Timeout:             5 * time.Second,  // Quick initial retry
        HalfOpenMaxRequests: 1,                // Single test request
    },
}

// Implement exponential backoff on circuit breaker resets
go func() {
    backoff := 5 * time.Second
    for {
        time.Sleep(1 * time.Minute)
        stats := client.GetCircuitBreakerStats()

        if stats != nil && stats["state"] == "OPEN" {
            failures := stats["failures"].(int64)
            if failures > 10 {
                // Increase timeout for persistent failures
                backoff = backoff * 2
                if backoff > 5*time.Minute {
                    backoff = 5 * time.Minute
                }
                log.Printf("Adjusting circuit breaker timeout to %v", backoff)
            }
        }
    }
}()
```

## Conclusion

The circuit breaker pattern in simple-ldap-go provides essential protection for production applications. By failing fast when LDAP is unavailable, it prevents cascading failures and improves user experience. Configure it appropriately for your environment and implement proper fallback strategies for maximum resilience.