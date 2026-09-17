# Performance Tuning Guide

## Table of Contents

1. [Overview](#overview)
2. [Performance Metrics](#performance-metrics)
3. [Connection Pool Optimization](#connection-pool-optimization)
4. [Cache Tuning](#cache-tuning)
5. [Query Optimization](#query-optimization)
6. [Concurrency and Parallelism](#concurrency-and-parallelism)
7. [Memory Management](#memory-management)
8. [Benchmarking](#benchmarking)
9. [Profiling](#profiling)
10. [Production Optimizations](#production-optimizations)

## Overview

This guide provides comprehensive strategies for optimizing simple-ldap-go performance in production environments. The library is designed for high-throughput LDAP operations with built-in optimizations including connection pooling, caching, and parallel processing capabilities.

### Performance Goals

- **Latency**: Sub-millisecond cache hits, <100ms LDAP queries
- **Throughput**: 10,000+ operations/second for cached data
- **Concurrency**: Support 1000+ concurrent operations
- **Memory**: Efficient memory usage with automatic cleanup
- **Scalability**: Linear scaling with hardware resources

## Performance Metrics

### Key Performance Indicators

```go
// performance.go - what GetPerformanceStats returns.
// PerformanceStats is an alias of PerformanceMetrics; times are durations,
// not float milliseconds, and rates are not precomputed.
type PerformanceMetrics struct {
    OperationsTotal int64
    ErrorCount      int64
    TimeoutCount    int64
    SlowQueries     int64
    CacheHits       int64
    CacheMisses     int64

    AvgResponseTime time.Duration
    MinResponseTime time.Duration
    MaxResponseTime time.Duration
    P50ResponseTime time.Duration
    P95ResponseTime time.Duration
    P99ResponseTime time.Duration

    MemoryUsageMB  float64
    GoroutineCount int

    OperationsByType  map[string]int64
    ErrorsByType      map[string]int64
    SlowQueriesByType map[string]int64

    // Nil unless a pool is configured.
    PoolStats *ConnectionPoolStats
    // ... time series and cache fields omitted
}
```

### Performance Monitoring

```go
// Continuous performance monitoring
type PerformanceMonitor struct {
    client   *LDAP
    interval time.Duration
    logger   *slog.Logger
    alerts   chan *PerformanceAlert
}

func (pm *PerformanceMonitor) Start(ctx context.Context) {
    ticker := time.NewTicker(pm.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            metrics := pm.client.GetPerformanceStats()
            pm.analyzeMetrics(metrics)
        }
    }
}

func (pm *PerformanceMonitor) analyzeMetrics(metrics ldap.PerformanceStats) {
    if metrics.P95ResponseTime > 500*time.Millisecond {
        pm.alerts <- &PerformanceAlert{
            Type:     "high_latency",
            Message:  fmt.Sprintf("P95 response time is %v", metrics.P95ResponseTime),
            Severity: "warning",
        }
    }

    // Hit rate is derived, not reported.
    if lookups := metrics.CacheHits + metrics.CacheMisses; lookups > 0 {
        hitRate := float64(metrics.CacheHits) / float64(lookups) * 100
        if hitRate < 70 {
            pm.alerts <- &PerformanceAlert{
                Type:     "low_cache_hit_rate",
                Message:  fmt.Sprintf("Cache hit rate is %0.2f%%", hitRate),
                Severity: "info",
            }
        }
    }

    // PoolStats is nil when the client runs without a pool.
    if pool := metrics.PoolStats; pool != nil && pool.MaxConnections > 0 {
        utilization := float64(pool.ActiveConnections) / float64(pool.MaxConnections) * 100
        if utilization > 80 {
            pm.alerts <- &PerformanceAlert{
                Type:     "high_pool_utilization",
                Message:  fmt.Sprintf("Pool utilization is %0.2f%%", utilization),
                Severity: "warning",
            }
        }
    }
}
```

## Connection Pool Optimization

Warm-up, health checking and leak recovery are the pool's own background work,
not something a caller wires up: `NewConnectionPool` calls `warmPool` to open
`MinConnections` before returning (`pool.go:184`), and `startBackgroundTasks`
runs `performHealthChecks`, `cleanupIdleConnections` and `monitorLeaks` until
`Close` (`pool.go:861`). Tuning it means choosing the `PoolConfig` values below;
there is no runtime resize.

### Pool Sizing

Pick the numbers, then measure `PoolHits` against `PoolMisses` under real load -
a low hit rate means `MinConnections` is too low for the arrival rate.

```go
config := ldap.Config{
    Server: "ldaps://ldap.example.com:636",
    BaseDN: "dc=example,dc=com",
    Pool: &ldap.PoolConfig{
        // Ceiling on concurrent connections. Reached means Get blocks up to
        // GetTimeout, so size it to peak concurrency, not to average load.
        MaxConnections: calculateOptimalPoolSize(),
        // Opened eagerly at startup and kept idle.
        MinConnections: runtime.NumCPU(),

        MaxIdleTime:         5 * time.Minute,
        HealthCheckInterval: 30 * time.Second,
        ConnectionTimeout:   30 * time.Second,
        GetTimeout:          10 * time.Second,
    },
}
```

The sizing calculation itself is caller-side code; this is one workable shape:

```go
func calculateOptimalPoolSize() int {
    // Base calculation on CPU cores
    numCPU := runtime.NumCPU()

    // Factor in expected concurrency
    expectedConcurrency := getEnvInt("LDAP_EXPECTED_CONCURRENCY", 100)

    // Connection overhead factor
    connectionOverhead := 0.1 // 10% overhead

    // Calculate optimal size
    optimalSize := int(math.Ceil(float64(expectedConcurrency) * (1 + connectionOverhead)))

    // Apply bounds
    minSize := numCPU * 2
    maxSize := numCPU * 25

    if optimalSize < minSize {
        return minSize
    }
    if optimalSize > maxSize {
        return maxSize
    }

    return optimalSize
}
```

### Health Monitoring

The health check runs inside the pool on the `HealthCheckInterval` ticker
(`pool.go:861`); `isConnectionHealthy` decides per connection and unhealthy ones
are closed rather than replaced in place. What a caller does is read the result:

```go
stats := pool.Stats()

// Rising failures point at the server or the network, not at the pool.
log.Printf("health checks: %d passed, %d failed",
    stats.HealthChecksPassed, stats.HealthChecksFailed)

// Churn: a connection count far above MinConnections that keeps climbing
// means connections are being closed as fast as they are created.
log.Printf("connections: %d created, %d closed, %d idle",
    stats.ConnectionsCreated, stats.ConnectionsClosed, stats.IdleConnections)
```

## Cache Tuning

### Cache Sizing Strategy

```go
// Intelligent cache sizing
func DetermineCacheSize(availableMemoryMB int, avgEntrySize int) int {
    // Reserve memory for application
    appOverheadMB := 256

    // Calculate available for cache
    cacheMemoryMB := availableMemoryMB - appOverheadMB
    if cacheMemoryMB < 64 {
        cacheMemoryMB = 64 // Minimum cache size
    }

    // Convert to number of entries
    avgEntrySizeKB := avgEntrySize / 1024
    if avgEntrySizeKB < 1 {
        avgEntrySizeKB = 1
    }

    maxEntries := (cacheMemoryMB * 1024) / avgEntrySizeKB

    // Apply reasonable bounds
    if maxEntries < 1000 {
        return 1000
    }
    if maxEntries > 1000000 {
        return 1000000
    }

    return maxEntries
}
```

### TTL Optimization

```go
// Dynamic TTL based on access patterns
type AdaptiveTTL struct {
    baseT TL      time.Duration
    minTTL       time.Duration
    maxTTL       time.Duration
    accessCounts map[string]int64
    mu           sync.RWMutex
}

func (a *AdaptiveTTL) GetTTL(key string) time.Duration {
    a.mu.RLock()
    count := a.accessCounts[key]
    a.mu.RUnlock()

    // High-frequency items get longer TTL
    if count > 100 {
        return a.maxTTL
    } else if count > 10 {
        return a.baseTTL * 2
    } else if count > 1 {
        return a.baseTTL
    }

    return a.minTTL
}

func (a *AdaptiveTTL) RecordAccess(key string) {
    a.mu.Lock()
    a.accessCounts[key]++
    a.mu.Unlock()
}
```

### Cache Preloading

```go
// Strategic cache preloading
func (l *LDAP) PreloadCriticalData(ctx context.Context) error {
    start := time.Now()

    // Define critical data sets
    criticalUsers := []string{"admin", "service-account", "monitor"}
    criticalGroups := []string{"administrators", "operators", "users"}

    g, gCtx := errgroup.WithContext(ctx)

    // Preload users
    g.Go(func() error {
        for _, username := range criticalUsers {
            // The context-taking variant is the one that accepts a ctx;
            // FindUserBySAMAccountName itself takes only the identifier.
            user, err := l.FindUserBySAMAccountNameContext(gCtx, username)
            if err != nil {
                l.logger.Warn("failed to preload user",
                    slog.String("user", username),
                    slog.String("error", err.Error()))
                continue
            }

            key := fmt.Sprintf("user:sam:%s", username)
            l.cache.Set(key, user, 1*time.Hour)
        }
        return nil
    })

    // Preload groups
    g.Go(func() error {
        for _, groupName := range criticalGroups {
            // Groups are addressed by DN; there is no lookup by CN alone.
            groupDN := fmt.Sprintf("cn=%s,ou=groups,%s", groupName, l.config.BaseDN)
            group, err := l.FindGroupByDNContext(gCtx, groupDN)
            if err != nil {
                continue
            }

            key := fmt.Sprintf("group:dn:%s", groupDN)
            l.cache.Set(key, group, 1*time.Hour)
        }
        return nil
    })

    if err := g.Wait(); err != nil {
        return fmt.Errorf("preload failed: %w", err)
    }

    l.logger.Info("cache preload completed",
        slog.Duration("duration", time.Since(start)),
        slog.Int("entries", len(criticalUsers)+len(criticalGroups)))

    return nil
}
```

## Query Optimization

### Filter Optimization

```go
// Optimize LDAP filters
func OptimizeFilter(filter string) string {
    // Use indexed attributes first
    indexedAttrs := []string{"objectGUID", "objectSid", "sAMAccountName", "mail"}

    // Reorder filter components for better performance
    parts := parseFilter(filter)

    // Sort by selectivity (most selective first)
    sort.Slice(parts, func(i, j int) bool {
        return getSelectivity(parts[i]) > getSelectivity(parts[j])
    })

    // Place indexed attributes at the beginning
    var optimized []string
    var nonIndexed []string

    for _, part := range parts {
        if containsIndexedAttr(part, indexedAttrs) {
            optimized = append(optimized, part)
        } else {
            nonIndexed = append(nonIndexed, part)
        }
    }

    optimized = append(optimized, nonIndexed...)

    return "(&" + strings.Join(optimized, "") + ")"
}

// Use paged searches for large results
func (l *LDAP) SearchPaged(filter string, pageSize int) ([]*ldap.Entry, error) {
    var allEntries []*ldap.Entry

    pagingControl := ldap.NewControlPaging(uint32(pageSize))

    for {
        searchRequest := &ldap.SearchRequest{
            BaseDN:       l.config.BaseDN,
            Scope:        ldap.ScopeWholeSubtree,
            DerefAliases: ldap.NeverDerefAliases,
            Filter:       filter,
            Attributes:   []string{"*"},
            Controls:     []ldap.Control{pagingControl},
        }

        result, err := l.conn.Search(searchRequest)
        if err != nil {
            return nil, fmt.Errorf("paged search failed: %w", err)
        }

        allEntries = append(allEntries, result.Entries...)

        // Check for more pages
        pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
        if pagingResult == nil {
            break
        }

        pagingControl = pagingResult.(*ldap.ControlPaging)
        if len(pagingControl.Cookie) == 0 {
            break // No more pages
        }
    }

    return allEntries, nil
}
```

### Attribute Selection

```go
// Request only needed attributes
func (l *LDAP) SearchWithAttributes(filter string, attributes []string) ([]*ldap.Entry, error) {
    // Only request attributes we need
    searchRequest := &ldap.SearchRequest{
        BaseDN:     l.config.BaseDN,
        Filter:     filter,
        Attributes: attributes, // Specific attributes instead of "*"
    }

    result, err := l.conn.Search(searchRequest)
    if err != nil {
        return nil, err
    }

    return result.Entries, nil
}

// Example: Optimized user lookup
func (l *LDAP) GetUserBasicInfo(ctx context.Context, username string) (*BasicUser, error) {
    // Only request essential attributes
    attributes := []string{
        "cn",
        "sAMAccountName",
        "mail",
        "displayName",
        "distinguishedName",
    }

    filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))",
        ldap.EscapeFilter(username))

    // Requesting only the attributes you need is done on the SearchRequest;
    // there is no SearchWithAttributes helper.
    req := ldap.NewSearchRequest(
        l.config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
        filter, attributes, nil,
    )

    var entries []*ldap.Entry
    for entry, err := range l.SearchIter(ctx, req) {
        if err != nil {
            return nil, err
        }
        entries = append(entries, entry)
    }
    if len(entries) == 0 {
        return nil, ErrUserNotFound
    }

    // Reduced data transfer and parsing
    return parseBasicUser(entries[0]), nil
}
```

### Batch Operations

```go
// Efficient batch processing
func (l *LDAP) BatchGetUsers(usernames []string, batchSize int) ([]*User, error) {
    var allUsers []*User
    var mu sync.Mutex

    // Process in batches
    batches := chunkSlice(usernames, batchSize)

    g := new(errgroup.Group)
    g.SetLimit(10) // Limit concurrent batches

    for _, batch := range batches {
        batch := batch // Capture loop variable

        g.Go(func() error {
            // Build optimized filter for batch
            var filters []string
            for _, username := range batch {
                filters = append(filters,
                    fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(username)))
            }

            batchFilter := fmt.Sprintf("(&(objectClass=user)(|%s))",
                strings.Join(filters, ""))

            users, err := l.searchUsers(batchFilter)
            if err != nil {
                return err
            }

            mu.Lock()
            allUsers = append(allUsers, users...)
            mu.Unlock()

            return nil
        })
    }

    if err := g.Wait(); err != nil {
        return nil, fmt.Errorf("batch operation failed: %w", err)
    }

    return allUsers, nil
}
```

## Concurrency and Parallelism

### Worker Pool Pattern

```go
// Efficient worker pool implementation
type WorkerPool struct {
    workers    int
    jobQueue   chan Job
    results    chan Result
    wg         sync.WaitGroup
}

func NewWorkerPool(workers int) *WorkerPool {
    return &WorkerPool{
        workers:  workers,
        jobQueue: make(chan Job, workers*2),
        results:  make(chan Result, workers*2),
    }
}

func (wp *WorkerPool) Start(ctx context.Context) {
    for i := 0; i < wp.workers; i++ {
        wp.wg.Add(1)
        go wp.worker(ctx, i)
    }
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
    defer wp.wg.Done()

    for {
        select {
        case <-ctx.Done():
            return
        case job, ok := <-wp.jobQueue:
            if !ok {
                return
            }

            result := wp.processJob(job)

            select {
            case wp.results <- result:
            case <-ctx.Done():
                return
            }
        }
    }
}

// Usage for LDAP operations
func (l *LDAP) ParallelUserLookup(usernames []string) ([]*User, error) {
    wp := NewWorkerPool(runtime.NumCPU() * 2)
    ctx := context.Background()

    wp.Start(ctx)
    defer wp.Stop()

    // Submit jobs
    go func() {
        for _, username := range usernames {
            wp.jobQueue <- Job{
                Type: "user_lookup",
                Data: username,
            }
        }
        close(wp.jobQueue)
    }()

    // Collect results
    var users []*User
    for range usernames {
        result := <-wp.results
        if result.Error != nil {
            continue // Or handle error
        }
        users = append(users, result.Data.(*User))
    }

    return users, nil
}
```

### Pipeline Pattern

```go
// Stream processing for large datasets
func (l *LDAP) StreamUsers(ctx context.Context) (<-chan *User, <-chan error) {
    userChan := make(chan *User, 100)
    errChan := make(chan error, 1)

    go func() {
        defer close(userChan)
        defer close(errChan)

        // Use paged search for memory efficiency
        pageSize := 500
        cookie := []byte{}

        for {
            users, newCookie, err := l.searchPagedUsers(cookie, pageSize)
            if err != nil {
                errChan <- err
                return
            }

            // Stream results
            for _, user := range users {
                select {
                case userChan <- user:
                case <-ctx.Done():
                    return
                }
            }

            if len(newCookie) == 0 {
                break // No more pages
            }
            cookie = newCookie
        }
    }()

    return userChan, errChan
}

// Usage with pipeline
func ProcessUsersInPipeline(ctx context.Context, l *LDAP) error {
    userChan, errChan := l.StreamUsers(ctx)

    // Stage 1: Filter
    filtered := filterUsers(ctx, userChan)

    // Stage 2: Enrich
    enriched := enrichUsers(ctx, l, filtered)

    // Stage 3: Process
    for user := range enriched {
        if err := processUser(user); err != nil {
            return err
        }
    }

    select {
    case err := <-errChan:
        return err
    default:
        return nil
    }
}
```

### Semaphore Pattern

```go
// Control concurrency with semaphores
type Semaphore struct {
    sem chan struct{}
}

func NewSemaphore(limit int) *Semaphore {
    return &Semaphore{
        sem: make(chan struct{}, limit),
    }
}

func (s *Semaphore) Acquire() {
    s.sem <- struct{}{}
}

func (s *Semaphore) Release() {
    <-s.sem
}

// Usage for rate limiting
func (l *LDAP) RateLimitedOperations(operations []Operation) error {
    sem := NewSemaphore(50) // Max 50 concurrent operations
    g := new(errgroup.Group)

    for _, op := range operations {
        op := op // Capture loop variable

        g.Go(func() error {
            sem.Acquire()
            defer sem.Release()

            return l.executeOperation(op)
        })
    }

    return g.Wait()
}
```

## Memory Management

### Object Pooling

```go
// Reuse objects to reduce GC pressure
var userPool = sync.Pool{
    New: func() interface{} {
        return &User{
            Attributes: make(map[string][]string),
        }
    },
}

func GetUser() *User {
    return userPool.Get().(*User)
}

func PutUser(u *User) {
    // Reset user
    u.DN = ""
    u.CN = ""
    u.SAMAccountName = ""
    u.Mail = ""

    // Clear map without allocating new one
    for k := range u.Attributes {
        delete(u.Attributes, k)
    }

    userPool.Put(u)
}

// Usage in parsing
func (l *LDAP) parseUserOptimized(entry *ldap.Entry) *User {
    user := GetUser() // Reuse from pool

    user.DN() = entry.DN
    user.CN() = entry.GetAttributeValue("cn")
    user.SAMAccountName = entry.GetAttributeValue("sAMAccountName")
    user.Mail = entry.GetAttributeValue("mail")

    // Note: Caller is responsible for returning to pool
    return user
}
```

### String Interning

```go
// Reduce memory for repeated strings
type StringInterner struct {
    mu    sync.RWMutex
    cache map[string]string
}

func NewStringInterner() *StringInterner {
    return &StringInterner{
        cache: make(map[string]string),
    }
}

func (si *StringInterner) Intern(s string) string {
    if s == "" {
        return ""
    }

    si.mu.RLock()
    if interned, ok := si.cache[s]; ok {
        si.mu.RUnlock()
        return interned
    }
    si.mu.RUnlock()

    si.mu.Lock()
    defer si.mu.Unlock()

    // Double-check after acquiring write lock
    if interned, ok := si.cache[s]; ok {
        return interned
    }

    si.cache[s] = s
    return s
}

// Usage for attribute values
func (l *LDAP) internAttributes(attrs map[string][]string) {
    for key, values := range attrs {
        for i, value := range values {
            values[i] = l.interner.Intern(value)
        }
        attrs[key] = values
    }
}
```

### Memory Monitoring

```go
// Track and manage memory usage
func MonitorMemory(ctx context.Context, threshold uint64) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            var m runtime.MemStats
            runtime.ReadMemStats(&m)

            if m.Alloc > threshold {
                slog.Warn("high memory usage",
                    slog.Uint64("alloc_mb", m.Alloc/1024/1024),
                    slog.Uint64("threshold_mb", threshold/1024/1024))

                // Trigger GC
                runtime.GC()

                // Clear caches if needed
                if m.Alloc > threshold*2 {
                    clearNonEssentialCaches()
                }
            }
        }
    }
}
```

## Benchmarking

### Micro-benchmarks

```go
// Benchmark individual operations
func BenchmarkUserLookup(b *testing.B) {
    client := setupTestClient(b)

    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, err := client.FindUserBySAMAccountName("testuser")
            if err != nil {
                b.Fatal(err)
            }
        }
    })

    b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "ops/sec")
}

func BenchmarkCachedVsUncached(b *testing.B) {
    client := setupTestClient(b)

    b.Run("Uncached", func(b *testing.B) {
        client.cache.Clear()
        for i := 0; i < b.N; i++ {
            client.FindUserByDN("cn=user,dc=example,dc=com")
        }
    })

    b.Run("Cached", func(b *testing.B) {
        // Warm cache
        client.FindUserByDN("cn=user,dc=example,dc=com")

        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            client.FindUserByDN("cn=user,dc=example,dc=com")
        }
    })
}
```

### Load Testing

```go
// Simulate production load
func TestLoadScenario(t *testing.T) {
    client := setupTestClient(t)

    // Define load scenario
    scenario := &LoadScenario{
        Duration:       1 * time.Minute,
        Concurrency:    100,
        TargetRPS:      1000,
        Operations: []Operation{
            {Type: "user_lookup", Weight: 0.5},
            {Type: "group_lookup", Weight: 0.3},
            {Type: "auth", Weight: 0.2},
        },
    }

    results := runLoadTest(client, scenario)

    // Assert performance requirements
    assert.Less(t, results.P95Latency, 100*time.Millisecond)
    assert.Greater(t, results.SuccessRate, 0.99)
    assert.Less(t, results.ErrorRate, 0.01)
}
```

## Profiling

### CPU Profiling

```go
// CPU profiling integration
func EnableCPUProfiling(profilePath string) func() {
    f, err := os.Create(profilePath)
    if err != nil {
        log.Fatal(err)
    }

    pprof.StartCPUProfile(f)

    return func() {
        pprof.StopCPUProfile()
        f.Close()
    }
}

// Usage
func main() {
    if *cpuprofile != "" {
        defer EnableCPUProfiling(*cpuprofile)()
    }

    // Run application
}
```

### Memory Profiling

```go
// Memory profiling
func WriteMemProfile(profilePath string) error {
    f, err := os.Create(profilePath)
    if err != nil {
        return err
    }
    defer f.Close()

    runtime.GC() // Get up-to-date statistics

    if err := pprof.WriteHeapProfile(f); err != nil {
        return err
    }

    return nil
}

// Periodic memory profiling
func PeriodicMemoryProfile(interval time.Duration, dir string) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for range ticker.C {
        filename := fmt.Sprintf("%s/mem_%d.prof",
            dir, time.Now().Unix())

        if err := WriteMemProfile(filename); err != nil {
            slog.Error("failed to write memory profile",
                slog.String("error", err.Error()))
        }
    }
}
```

### Trace Analysis

```go
// Execution tracing
func EnableTracing(tracePath string) (func(), error) {
    f, err := os.Create(tracePath)
    if err != nil {
        return nil, err
    }

    if err := trace.Start(f); err != nil {
        f.Close()
        return nil, err
    }

    return func() {
        trace.Stop()
        f.Close()
    }, nil
}

// Analyze with: go tool trace trace.out
```

## Production Optimizations

### Configuration Recommendations

```go
func productionConfig() ldap.Config {
    return ldap.Config{
        Server: "ldaps://ldap.example.com:636",
        BaseDN: "dc=example,dc=com",

        DialTimeout:  10 * time.Second,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,

        Pool: &ldap.PoolConfig{
            MaxConnections:    100,
            MinConnections:    20,
            ConnectionTimeout: 10 * time.Second,
            GetTimeout:        10 * time.Second,
        },

        EnableCache: true,
        Cache: &ldap.CacheConfig{
            Enabled:          true,
            MaxSize:          100000,
            MaxMemoryMB:      256,
            TTL:              5 * time.Minute,
            NegativeCacheTTL: 30 * time.Second,
            // Trades CPU for memory on entries above CompressionThreshold.
            CompressionEnabled:   true,
            CompressionThreshold: 1024,
        },

        EnableMetrics: true,
        Performance: &ldap.PerformanceConfig{
            Enabled:            true,
            SlowQueryThreshold: 500 * time.Millisecond,
            FlushInterval:      30 * time.Second,
            // Sampling below 1.0 keeps the metrics buffer bounded under load.
            SampleRate: 0.1,
        },

        Resilience: &ldap.ResilienceConfig{
            EnableCircuitBreaker: true,
            CircuitBreaker:       ldap.DefaultCircuitBreakerConfig(),
        },
    }
}
```

### Deployment Checklist

```markdown
## Pre-Production Performance Checklist

### Configuration
- [ ] Connection pool sized appropriately
- [ ] Cache size based on available memory
- [ ] Timeouts configured for network latency
- [ ] Compression enabled for large responses
- [ ] Batch sizes optimized

### Monitoring
- [ ] Performance metrics exposed
- [ ] Alerting thresholds configured
- [ ] Logging levels appropriate (INFO/WARN)
- [ ] Distributed tracing integrated

### Testing
- [ ] Load testing completed
- [ ] Benchmarks meet requirements
- [ ] Memory leaks verified absent
- [ ] Race conditions checked

### Optimization
- [ ] Indexes verified on LDAP server
- [ ] Frequently accessed data cached
- [ ] Queries optimized for selectivity
- [ ] Connection pooling enabled
```

### Performance Troubleshooting

```go
// Common performance issues
func DiagnosePerformance(client *LDAP) *PerformanceDiagnostic {
    diag := &PerformanceDiagnostic{
        Timestamp: time.Now(),
    }

    // Check cache effectiveness
    cacheStats := client.cache.Stats()
    if cacheStats.HitRate < 70 {
        diag.Issues = append(diag.Issues,
            "Low cache hit rate - consider increasing TTL or cache size")
    }

    // Check connection pool
    poolStats := client.pool.Stats()
    if poolStats.WaitTime > 100*time.Millisecond {
        diag.Issues = append(diag.Issues,
            "High pool wait time - increase pool size")
    }

    // Check query performance
    perf := client.GetPerformanceStats()
    if perf.SlowQueries > 0 {
        diag.Issues = append(diag.Issues,
            fmt.Sprintf("Found %d slow queries", perf.SlowQueries))
        diag.SlowQueriesByType = perf.SlowQueriesByType
    }

    // Memory usage
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    if m.Alloc > 1024*1024*1024 { // 1GB
        diag.Issues = append(diag.Issues,
            "High memory usage - check for leaks")
    }

    return diag
}
```

---

*Performance Tuning Guide - Last Updated: 2026-09-17*
