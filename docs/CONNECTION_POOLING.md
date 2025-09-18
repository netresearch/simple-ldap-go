# Connection Pooling Guide

## Overview

Connection pooling is a critical performance optimization technique that maintains a pool of reusable LDAP connections, reducing the overhead of establishing new connections for each operation. The simple-ldap-go library provides a robust connection pooling implementation with health monitoring, automatic recovery, and configurable parameters.

## Table of Contents

- [Why Connection Pooling](#why-connection-pooling)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Pool Management](#pool-management)
- [Health Monitoring](#health-monitoring)
- [Performance Optimization](#performance-optimization)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Why Connection Pooling

### Benefits

1. **Reduced Latency**: Eliminates connection establishment overhead
2. **Resource Efficiency**: Reuses existing connections
3. **Improved Throughput**: Handles more requests with fewer resources
4. **Connection Management**: Automatic lifecycle management
5. **Fault Tolerance**: Health checks and automatic recovery

### When to Use

- High-volume applications
- Microservices with frequent LDAP queries
- API servers with concurrent requests
- Batch processing systems
- Any production environment

## Quick Start

### Basic Pool Setup

```go
package main

import (
    "log"
    "time"

    ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
    config := ldap.Config{
        Server: "ldaps://ldap.example.com:636",
        BaseDN: "dc=example,dc=com",
    }

    // Create client with connection pool (10 connections)
    client, err := ldap.NewPooledClient(
        config,
        "admin@example.com",
        "password",
        10, // Max connections
    )
    if err != nil {
        log.Fatal(err)
    }

    // Use client normally - pooling is transparent
    user, err := client.FindUserBySAMAccountName("jdoe")
    if err != nil {
        log.Printf("Error: %v", err)
    }
}
```

### Advanced Configuration

```go
// Create custom pool configuration
poolConfig := &ldap.PoolConfig{
    MaxConnections:      20,
    MinIdleConnections:  5,
    MaxIdleTime:        5 * time.Minute,
    MaxLifetime:        30 * time.Minute,
    HealthCheckInterval: 1 * time.Minute,
}

// Create connection pool
pool, err := ldap.NewConnectionPool(
    poolConfig,
    config,
    "admin@example.com",
    "password",
    slog.Default(),
)
if err != nil {
    log.Fatal(err)
}

// Create client with custom pool
client := &ldap.LDAP{
    // ... configuration
    pool: pool,
}
```

## Configuration

### Pool Configuration Parameters

```go
type PoolConfig struct {
    // Maximum number of connections in the pool
    MaxConnections int

    // Minimum number of idle connections to maintain
    MinIdleConnections int

    // Maximum time a connection can be idle before closing
    MaxIdleTime time.Duration

    // Maximum lifetime of a connection
    MaxLifetime time.Duration

    // Interval between health checks
    HealthCheckInterval time.Duration

    // Connection timeout for new connections
    ConnectionTimeout time.Duration

    // Enable connection validation before use
    TestOnBorrow bool

    // Enable connection validation on return
    TestOnReturn bool
}
```

### Recommended Configurations

#### High-Traffic API Server

```go
poolConfig := &ldap.PoolConfig{
    MaxConnections:      50,
    MinIdleConnections:  10,
    MaxIdleTime:        10 * time.Minute,
    MaxLifetime:        1 * time.Hour,
    HealthCheckInterval: 30 * time.Second,
    ConnectionTimeout:   5 * time.Second,
    TestOnBorrow:       true,
}
```

#### Batch Processing System

```go
poolConfig := &ldap.PoolConfig{
    MaxConnections:      100,
    MinIdleConnections:  20,
    MaxIdleTime:        5 * time.Minute,
    MaxLifetime:        30 * time.Minute,
    HealthCheckInterval: 1 * time.Minute,
    ConnectionTimeout:   10 * time.Second,
    TestOnBorrow:       false, // Performance over reliability
}
```

#### Microservice

```go
poolConfig := &ldap.PoolConfig{
    MaxConnections:      10,
    MinIdleConnections:  2,
    MaxIdleTime:        15 * time.Minute,
    MaxLifetime:        2 * time.Hour,
    HealthCheckInterval: 2 * time.Minute,
    ConnectionTimeout:   3 * time.Second,
    TestOnBorrow:       true,
}
```

## Pool Management

### Connection Lifecycle

```go
// Internal connection lifecycle management
type pooledConnection struct {
    conn       *ldap.Conn
    createdAt  time.Time
    lastUsedAt time.Time
    inUse      bool
    healthy    bool
}

// Connection states
const (
    StateIdle     = "idle"
    StateInUse    = "in_use"
    StateStale    = "stale"
    StateUnhealthy = "unhealthy"
)
```

### Manual Pool Management

```go
type PoolManager struct {
    pool *ldap.ConnectionPool
}

// Get pool statistics
func (pm *PoolManager) GetStats() PoolStats {
    return pm.pool.Stats()
}

// Force connection refresh
func (pm *PoolManager) RefreshConnections() error {
    stats := pm.pool.Stats()

    // Close idle connections
    for i := 0; i < stats.IdleConnections; i++ {
        conn := pm.pool.getIdleConnection()
        if conn != nil {
            conn.Close()
        }
    }

    // Pre-warm new connections
    return pm.pool.warmUp()
}

// Graceful shutdown
func (pm *PoolManager) Shutdown(ctx context.Context) error {
    // Wait for active connections to complete
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            stats := pm.pool.Stats()
            if stats.ActiveConnections == 0 {
                return pm.pool.Close()
            }
        }
    }
}
```

### Dynamic Pool Sizing

```go
type DynamicPool struct {
    pool      *ldap.ConnectionPool
    metrics   *PerformanceMonitor
    mu        sync.RWMutex
    minSize   int
    maxSize   int
}

func (dp *DynamicPool) AutoScale() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        dp.adjustPoolSize()
    }
}

func (dp *DynamicPool) adjustPoolSize() {
    stats := dp.pool.Stats()
    utilization := float64(stats.ActiveConnections) / float64(stats.TotalConnections)

    dp.mu.Lock()
    defer dp.mu.Unlock()

    switch {
    case utilization > 0.8 && stats.TotalConnections < dp.maxSize:
        // Scale up
        newSize := min(stats.TotalConnections+5, dp.maxSize)
        dp.pool.Resize(newSize)
        log.Printf("Scaled up pool to %d connections", newSize)

    case utilization < 0.2 && stats.TotalConnections > dp.minSize:
        // Scale down
        newSize := max(stats.TotalConnections-5, dp.minSize)
        dp.pool.Resize(newSize)
        log.Printf("Scaled down pool to %d connections", newSize)
    }
}
```

## Health Monitoring

### Health Check Implementation

```go
type HealthChecker struct {
    pool   *ldap.ConnectionPool
    logger *slog.Logger
}

func (hc *HealthChecker) RunHealthChecks(ctx context.Context) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            hc.checkPoolHealth()
        }
    }
}

func (hc *HealthChecker) checkPoolHealth() {
    stats := hc.pool.Stats()

    // Check pool health metrics
    if stats.FailedConnections > 0 {
        hc.logger.Warn("Pool has failed connections",
            "failed", stats.FailedConnections,
            "total", stats.TotalConnections)
    }

    if float64(stats.ActiveConnections)/float64(stats.TotalConnections) > 0.9 {
        hc.logger.Warn("Pool near capacity",
            "active", stats.ActiveConnections,
            "total", stats.TotalConnections)
    }

    // Validate idle connections
    hc.validateIdleConnections()
}

func (hc *HealthChecker) validateIdleConnections() {
    // Test each idle connection
    for _, conn := range hc.pool.getIdleConnections() {
        if err := hc.testConnection(conn); err != nil {
            hc.logger.Error("Unhealthy connection detected",
                "error", err)
            conn.markUnhealthy()
        }
    }
}

func (hc *HealthChecker) testConnection(conn *ldap.Conn) error {
    // Simple search to test connection
    searchRequest := ldap.NewSearchRequest(
        "", // Empty base DN
        ldap.ScopeBaseObject,
        ldap.NeverDerefAliases,
        0, 1, false,
        "(objectClass=*)",
        []string{"1.1"}, // No attributes
        nil,
    )

    _, err := conn.Search(searchRequest)
    return err
}
```

### Monitoring Metrics

```go
type PoolMetrics struct {
    // Connection metrics
    TotalConnections   int
    ActiveConnections  int
    IdleConnections   int
    FailedConnections int

    // Performance metrics
    AverageWaitTime   time.Duration
    ConnectionsCreated int64
    ConnectionsClosed  int64

    // Health metrics
    HealthChecksPassed int64
    HealthChecksFailed int64

    // Usage metrics
    RequestsServed    int64
    ConnectionReuse   float64
}

func (p *ConnectionPool) CollectMetrics() *PoolMetrics {
    p.mu.RLock()
    defer p.mu.RUnlock()

    metrics := &PoolMetrics{
        TotalConnections:  len(p.connections),
        ActiveConnections: p.activeCount,
        IdleConnections:  len(p.idle),
        // ... collect other metrics
    }

    return metrics
}
```

## Performance Optimization

### Connection Warm-up

```go
func WarmUpPool(pool *ldap.ConnectionPool) error {
    // Pre-create minimum connections
    for i := 0; i < pool.config.MinIdleConnections; i++ {
        conn, err := pool.createConnection()
        if err != nil {
            return fmt.Errorf("warm-up failed: %w", err)
        }
        pool.returnConnection(conn)
    }

    log.Printf("Pool warmed up with %d connections", pool.config.MinIdleConnections)
    return nil
}
```

### Connection Reuse Strategies

```go
// LIFO Strategy - Better for connection keep-alive
type LIFOPool struct {
    connections []* ldap.Conn
    mu         sync.Mutex
}

func (p *LIFOPool) Get() (*ldap.Conn, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    if len(p.connections) > 0 {
        // Take from end (most recently used)
        conn := p.connections[len(p.connections)-1]
        p.connections = p.connections[:len(p.connections)-1]
        return conn, nil
    }

    return p.createNew()
}

// FIFO Strategy - Better for load distribution
type FIFOPool struct {
    connections chan *ldap.Conn
}

func (p *FIFOPool) Get() (*ldap.Conn, error) {
    select {
    case conn := <-p.connections:
        return conn, nil
    default:
        return p.createNew()
    }
}
```

### Batch Operations with Pooling

```go
func BulkOperationWithPool(pool *ldap.ConnectionPool, operations []Operation) []Result {
    results := make([]Result, len(operations))
    var wg sync.WaitGroup

    // Create worker pool
    workers := min(10, pool.config.MaxConnections/2)
    jobChan := make(chan int, len(operations))

    // Start workers
    for w := 0; w < workers; w++ {
        wg.Add(1)
        go func() {
            defer wg.Done()

            // Get connection for this worker
            conn, err := pool.Get()
            if err != nil {
                return
            }
            defer pool.Return(conn)

            // Process jobs
            for idx := range jobChan {
                results[idx] = operations[idx].Execute(conn)
            }
        }()
    }

    // Queue jobs
    for i := range operations {
        jobChan <- i
    }
    close(jobChan)

    wg.Wait()
    return results
}
```

## Troubleshooting

### Common Issues

#### 1. Connection Pool Exhaustion

**Symptoms:**
- Timeouts waiting for connections
- "No available connections" errors

**Diagnosis:**
```go
func diagnosePoolExhaustion(pool *ldap.ConnectionPool) {
    stats := pool.Stats()

    fmt.Printf("Pool Status:\n")
    fmt.Printf("  Total: %d\n", stats.TotalConnections)
    fmt.Printf("  Active: %d\n", stats.ActiveConnections)
    fmt.Printf("  Idle: %d\n", stats.IdleConnections)
    fmt.Printf("  Wait Queue: %d\n", stats.WaitingRequests)

    if stats.ActiveConnections == stats.TotalConnections {
        fmt.Println("WARNING: Pool is exhausted!")

        // Check for connection leaks
        if stats.ConnectionsNotReturned > 0 {
            fmt.Printf("LEAK DETECTED: %d connections not returned\n",
                stats.ConnectionsNotReturned)
        }
    }
}
```

**Solutions:**
```go
// Increase pool size
pool.Resize(pool.config.MaxConnections * 2)

// Implement connection timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
conn, err := pool.GetContext(ctx)
cancel()

// Always return connections
defer pool.Return(conn)
```

#### 2. Connection Leaks

**Detection:**
```go
type LeakDetector struct {
    pool        *ldap.ConnectionPool
    checkouts   map[*ldap.Conn]stackTrace
    mu          sync.Mutex
}

func (ld *LeakDetector) TrackCheckout(conn *ldap.Conn) {
    ld.mu.Lock()
    defer ld.mu.Unlock()

    ld.checkouts[conn] = captureStackTrace()
}

func (ld *LeakDetector) TrackReturn(conn *ldap.Conn) {
    ld.mu.Lock()
    defer ld.mu.Unlock()

    delete(ld.checkouts, conn)
}

func (ld *LeakDetector) DetectLeaks() []LeakInfo {
    ld.mu.Lock()
    defer ld.mu.Unlock()

    var leaks []LeakInfo
    for conn, stack := range ld.checkouts {
        if time.Since(conn.CheckoutTime) > 5*time.Minute {
            leaks = append(leaks, LeakInfo{
                Connection: conn,
                Stack:     stack,
                Duration:  time.Since(conn.CheckoutTime),
            })
        }
    }

    return leaks
}
```

#### 3. Stale Connections

**Prevention:**
```go
// Configure appropriate timeouts
poolConfig := &ldap.PoolConfig{
    MaxIdleTime: 5 * time.Minute,  // Close idle connections
    MaxLifetime: 30 * time.Minute, // Rotate connections
    TestOnBorrow: true,             // Validate before use
}

// Implement connection refresh
func refreshStaleConnections(pool *ldap.ConnectionPool) {
    for _, conn := range pool.GetConnections() {
        if conn.IsStale() {
            pool.Remove(conn)
            newConn, _ := pool.CreateConnection()
            pool.Add(newConn)
        }
    }
}
```

### Debug Logging

```go
// Enable detailed pool logging
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

pool, _ := ldap.NewConnectionPool(config, ldapConfig, user, pass, logger)

// Pool will log:
// - Connection creation/destruction
// - Health check results
// - Pool statistics
// - Error conditions
```

## Best Practices

### 1. Right-Size Your Pool

```go
// Calculate optimal pool size
func calculatePoolSize(expectedQPS int, avgResponseTime time.Duration) int {
    // Little's Law: L = λW
    // L = number of connections needed
    // λ = arrival rate (QPS)
    // W = average response time

    connections := float64(expectedQPS) * avgResponseTime.Seconds()

    // Add 20% buffer
    optimalSize := int(connections * 1.2)

    // Apply bounds
    minSize := 5
    maxSize := 100

    if optimalSize < minSize {
        return minSize
    }
    if optimalSize > maxSize {
        return maxSize
    }

    return optimalSize
}
```

### 2. Implement Circuit Breaker

```go
type CircuitBreaker struct {
    pool           *ldap.ConnectionPool
    failureCount   int
    lastFailTime   time.Time
    state          string
    mu             sync.Mutex
}

func (cb *CircuitBreaker) Get() (*ldap.Conn, error) {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    // Check circuit state
    switch cb.state {
    case "open":
        if time.Since(cb.lastFailTime) > 30*time.Second {
            cb.state = "half-open"
        } else {
            return nil, errors.New("circuit breaker open")
        }
    }

    // Try to get connection
    conn, err := cb.pool.Get()
    if err != nil {
        cb.recordFailure()
        return nil, err
    }

    // Reset on success
    if cb.state == "half-open" {
        cb.state = "closed"
        cb.failureCount = 0
    }

    return conn, nil
}

func (cb *CircuitBreaker) recordFailure() {
    cb.failureCount++
    cb.lastFailTime = time.Now()

    if cb.failureCount >= 5 {
        cb.state = "open"
        log.Println("Circuit breaker opened")
    }
}
```

### 3. Monitor Pool Health

```go
// Expose metrics endpoint
func (p *ConnectionPool) MetricsHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        stats := p.Stats()

        // Prometheus format
        fmt.Fprintf(w, "# HELP ldap_pool_connections_total Total connections in pool\n")
        fmt.Fprintf(w, "ldap_pool_connections_total %d\n", stats.TotalConnections)

        fmt.Fprintf(w, "# HELP ldap_pool_connections_active Active connections\n")
        fmt.Fprintf(w, "ldap_pool_connections_active %d\n", stats.ActiveConnections)

        fmt.Fprintf(w, "# HELP ldap_pool_connections_idle Idle connections\n")
        fmt.Fprintf(w, "ldap_pool_connections_idle %d\n", stats.IdleConnections)

        fmt.Fprintf(w, "# HELP ldap_pool_wait_duration_seconds Average wait time\n")
        fmt.Fprintf(w, "ldap_pool_wait_duration_seconds %f\n", stats.AvgWaitTime.Seconds())
    })
}
```

### 4. Graceful Degradation

```go
type ResilientClient struct {
    primary   *ldap.LDAP  // With pool
    fallback  *ldap.LDAP  // Without pool
}

func (rc *ResilientClient) FindUser(username string) (*ldap.User, error) {
    // Try primary (pooled)
    user, err := rc.primary.FindUserBySAMAccountName(username)
    if err == nil {
        return user, nil
    }

    // Check if pool-related error
    if isPoolError(err) {
        log.Println("Falling back to non-pooled connection")
        return rc.fallback.FindUserBySAMAccountName(username)
    }

    return nil, err
}
```

### 5. Connection Lifecycle Events

```go
type PoolEventHandler interface {
    OnConnectionCreate(conn *ldap.Conn)
    OnConnectionDestroy(conn *ldap.Conn)
    OnConnectionCheckout(conn *ldap.Conn)
    OnConnectionReturn(conn *ldap.Conn)
    OnHealthCheckFail(conn *ldap.Conn, err error)
}

type LoggingEventHandler struct {
    logger *slog.Logger
}

func (h *LoggingEventHandler) OnConnectionCreate(conn *ldap.Conn) {
    h.logger.Info("Connection created",
        "conn_id", conn.ID,
        "pool_size", conn.Pool.Size())
}

func (h *LoggingEventHandler) OnHealthCheckFail(conn *ldap.Conn, err error) {
    h.logger.Error("Health check failed",
        "conn_id", conn.ID,
        "error", err)
}
```

## Summary

Connection pooling is essential for production LDAP applications. Key takeaways:

1. **Right-size your pool** based on application load
2. **Monitor pool health** with metrics and logging
3. **Handle connection lifecycle** properly (always return connections)
4. **Implement health checks** to detect stale connections
5. **Use circuit breakers** for resilience
6. **Plan for graceful degradation** when pool is exhausted

The simple-ldap-go connection pool provides:
- Automatic connection management
- Health monitoring and recovery
- Configurable sizing and timeouts
- Performance optimization
- Production-ready reliability

---

*Connection Pooling Guide v1.0.0 - Last Updated: 2025-09-17*