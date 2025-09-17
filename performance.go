package ldap

import (
	"context"
	"log/slog"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// PerformanceConfig holds configuration for performance monitoring
type PerformanceConfig struct {
	// Enabled controls whether performance monitoring is active (default: true)
	Enabled bool
	// MetricsRetentionPeriod is how long to keep detailed metrics (default: 1 hour)
	MetricsRetentionPeriod time.Duration
	// SlowQueryThreshold defines what constitutes a slow query (default: 1 second)
	SlowQueryThreshold time.Duration
	// SampleRate controls what percentage of operations to track in detail (default: 100%)
	SampleRate float64
	// MaxSearchResults limits the number of results returned by searches (default: 0 = no limit)
	MaxSearchResults int
	// SearchTimeout is the per-search timeout (default: 30 seconds)
	SearchTimeout time.Duration
	// EnablePrefetch enables prefetching of related objects (default: false)
	EnablePrefetch bool
	// EnableBulkOperations enables batch processing optimizations (default: true)
	EnableBulkOperations bool
}

// DefaultPerformanceConfig returns a PerformanceConfig with sensible defaults
func DefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		Enabled:                true,
		MetricsRetentionPeriod: 1 * time.Hour,
		SlowQueryThreshold:     1 * time.Second,
		SampleRate:             1.0, // 100%
		MaxSearchResults:       0,   // No limit
		SearchTimeout:          30 * time.Second,
		EnablePrefetch:         false,
		EnableBulkOperations:   true,
	}
}

// PerformanceStats provides comprehensive performance metrics
type PerformanceStats struct {
	// Operation counters
	OperationsTotal  int64            // Total operations performed
	OperationsByType map[string]int64 // Operations broken down by type

	// Cache performance
	CacheHits     int64   // Total cache hits
	CacheMisses   int64   // Total cache misses
	CacheHitRatio float64 // Cache hit ratio as percentage

	// Timing metrics
	AvgResponseTime time.Duration // Average response time across all operations
	MinResponseTime time.Duration // Fastest operation time
	MaxResponseTime time.Duration // Slowest operation time
	P50ResponseTime time.Duration // 50th percentile response time
	P95ResponseTime time.Duration // 95th percentile response time
	P99ResponseTime time.Duration // 99th percentile response time

	// Performance issues
	SlowQueries       int64            // Number of queries exceeding threshold
	SlowQueriesByType map[string]int64 // Slow queries by operation type
	ErrorCount        int64            // Total errors encountered
	TimeoutCount      int64            // Operations that timed out

	// Connection metrics
	ConnectionPoolHits   int64   // Successful pool retrievals
	ConnectionPoolMisses int64   // Pool misses requiring new connections
	ConnectionPoolRatio  float64 // Pool hit ratio as percentage

	// Resource usage
	MemoryUsageMB  float64 // Current memory usage in MB
	GoroutineCount int     // Current number of goroutines

	// Recent performance data
	RecentOperations  []OperationMetric // Recent operation details
	TopSlowOperations []OperationMetric // Slowest operations

	// Background operations
	BackgroundRefreshes int64 // Background cache refresh operations
	BackgroundCleanups  int64 // Background cleanup operations
}

// OperationMetric represents metrics for a single operation
type OperationMetric struct {
	Operation    string        // Operation type (e.g., "FindUserByDN")
	Duration     time.Duration // Time taken
	CacheHit     bool          // Whether this was served from cache
	Error        error         // Any error that occurred
	Timestamp    time.Time     // When the operation occurred
	ConnectionID string        // Connection identifier for tracking
	ResultCount  int           // Number of results returned
	IsSlow       bool          // Whether this exceeded slow query threshold
}

// PerformanceMonitor tracks and analyzes performance metrics
type PerformanceMonitor struct {
	config *PerformanceConfig
	logger *slog.Logger

	// Metrics storage
	metrics     map[string]*operationStats // Per-operation statistics
	recentOps   []OperationMetric          // Recent operations buffer
	recentOpsMu sync.RWMutex               // Mutex for recent operations

	// Timing data for percentile calculations
	allTimes []time.Duration // All operation times (sampled)
	timesMu  sync.RWMutex    // Mutex for timing data

	// Atomic counters for thread-safe statistics
	totalOps   int64 // Total operations
	slowOps    int64 // Slow operations
	errorOps   int64 // Failed operations
	timeoutOps int64 // Timed out operations

	// Cache references for integrated metrics
	cache Cache           // Reference to cache for statistics integration
	pool  *ConnectionPool // Reference to connection pool

	// Background cleanup
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// operationStats holds statistics for a specific operation type
type operationStats struct {
	count         int64         // Number of operations
	totalDuration time.Duration // Total time spent
	minDuration   time.Duration // Minimum duration
	maxDuration   time.Duration // Maximum duration
	slowCount     int64         // Number of slow operations
	errorCount    int64         // Number of errors
	mu            sync.RWMutex  // Mutex for thread safety
}

// NewPerformanceMonitor creates a new performance monitoring system
func NewPerformanceMonitor(config *PerformanceConfig, logger *slog.Logger) *PerformanceMonitor {
	if config == nil {
		config = DefaultPerformanceConfig()
	}

	if logger == nil {
		logger = slog.Default()
	}

	monitor := &PerformanceMonitor{
		config:    config,
		logger:    logger,
		metrics:   make(map[string]*operationStats),
		recentOps: make([]OperationMetric, 0, 1000),
		allTimes:  make([]time.Duration, 0, 10000),
		stopChan:  make(chan struct{}),
	}

	if config.Enabled {
		monitor.startBackgroundCleanup()
		logger.Info("performance_monitor_created",
			slog.Duration("retention_period", config.MetricsRetentionPeriod),
			slog.Duration("slow_query_threshold", config.SlowQueryThreshold),
			slog.Float64("sample_rate", config.SampleRate))
	}

	return monitor
}

// RecordOperation records metrics for a completed operation
func (pm *PerformanceMonitor) RecordOperation(ctx context.Context, operation string, duration time.Duration, cacheHit bool, err error, resultCount int) {
	if !pm.config.Enabled {
		return
	}

	// Sample operations based on configured rate
	if pm.config.SampleRate < 1.0 && float64(time.Now().UnixNano()%1000)/1000.0 > pm.config.SampleRate {
		return
	}

	atomic.AddInt64(&pm.totalOps, 1)

	isSlow := duration > pm.config.SlowQueryThreshold
	if isSlow {
		atomic.AddInt64(&pm.slowOps, 1)
	}

	hasError := err != nil
	if hasError {
		atomic.AddInt64(&pm.errorOps, 1)
	}

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		atomic.AddInt64(&pm.timeoutOps, 1)
	}

	// Update operation-specific statistics
	pm.updateOperationStats(operation, duration, isSlow, hasError)

	// Record recent operation
	metric := OperationMetric{
		Operation:    operation,
		Duration:     duration,
		CacheHit:     cacheHit,
		Error:        err,
		Timestamp:    time.Now(),
		ConnectionID: pm.getConnectionID(ctx),
		ResultCount:  resultCount,
		IsSlow:       isSlow,
	}

	pm.addRecentOperation(metric)

	// Add to timing data for percentile calculations
	pm.addTimingData(duration)

	// Log slow operations
	if isSlow {
		pm.logger.Warn("slow_operation_detected",
			slog.String("operation", operation),
			slog.Duration("duration", duration),
			slog.Duration("threshold", pm.config.SlowQueryThreshold),
			slog.Bool("cache_hit", cacheHit),
			slog.Int("result_count", resultCount))
	}

	// Log errors
	if hasError {
		pm.logger.Error("operation_error",
			slog.String("operation", operation),
			slog.Duration("duration", duration),
			slog.String("error", err.Error()))
	}
}

// StartOperation returns a function to record the operation when complete
func (pm *PerformanceMonitor) StartOperation(ctx context.Context, operation string) func(cacheHit bool, err error, resultCount int) {
	if !pm.config.Enabled {
		return func(bool, error, int) {} // No-op
	}

	start := time.Now()

	return func(cacheHit bool, err error, resultCount int) {
		duration := time.Since(start)
		pm.RecordOperation(ctx, operation, duration, cacheHit, err, resultCount)
	}
}

// GetStats returns comprehensive performance statistics
func (pm *PerformanceMonitor) GetStats() PerformanceStats {
	if !pm.config.Enabled {
		return PerformanceStats{}
	}

	stats := PerformanceStats{
		OperationsTotal:   atomic.LoadInt64(&pm.totalOps),
		SlowQueries:       atomic.LoadInt64(&pm.slowOps),
		ErrorCount:        atomic.LoadInt64(&pm.errorOps),
		TimeoutCount:      atomic.LoadInt64(&pm.timeoutOps),
		OperationsByType:  make(map[string]int64),
		SlowQueriesByType: make(map[string]int64),
	}

	// Collect per-operation statistics
	for opType, opStats := range pm.metrics {
		opStats.mu.RLock()
		stats.OperationsByType[opType] = opStats.count
		stats.SlowQueriesByType[opType] = opStats.slowCount
		opStats.mu.RUnlock()
	}

	// Calculate timing percentiles
	pm.calculateTimingPercentiles(&stats)

	// Get cache statistics if available
	if pm.cache != nil {
		cacheStats := pm.cache.Stats()
		stats.CacheHits = cacheStats.Hits
		stats.CacheMisses = cacheStats.Misses
		stats.CacheHitRatio = cacheStats.HitRatio
		stats.BackgroundRefreshes = cacheStats.RefreshOps
		stats.BackgroundCleanups = cacheStats.CleanupOps
	}

	// Get connection pool statistics if available
	if pm.pool != nil {
		poolStats := pm.pool.Stats()
		stats.ConnectionPoolHits = poolStats.PoolHits
		stats.ConnectionPoolMisses = poolStats.PoolMisses
		total := stats.ConnectionPoolHits + stats.ConnectionPoolMisses
		if total > 0 {
			stats.ConnectionPoolRatio = float64(stats.ConnectionPoolHits) / float64(total) * 100
		}
	}

	// Get recent operations
	pm.recentOpsMu.RLock()
	stats.RecentOperations = make([]OperationMetric, len(pm.recentOps))
	copy(stats.RecentOperations, pm.recentOps)
	pm.recentOpsMu.RUnlock()

	// Get top slow operations
	stats.TopSlowOperations = pm.getTopSlowOperations(10)

	// Get memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	stats.MemoryUsageMB = float64(memStats.Alloc) / (1024 * 1024)
	stats.GoroutineCount = runtime.NumGoroutine()

	return stats
}

// SetCache sets the cache reference for integrated metrics
func (pm *PerformanceMonitor) SetCache(cache Cache) {
	pm.cache = cache
}

// SetConnectionPool sets the connection pool reference for integrated metrics
func (pm *PerformanceMonitor) SetConnectionPool(pool *ConnectionPool) {
	pm.pool = pool
}

// Close shuts down the performance monitor
func (pm *PerformanceMonitor) Close() error {
	if !pm.config.Enabled {
		return nil
	}

	if pm.stopChan != nil {
		close(pm.stopChan)
		pm.wg.Wait()
	}

	if pm.ticker != nil {
		pm.ticker.Stop()
	}

	pm.logger.Info("performance_monitor_closed",
		slog.Int64("total_operations", atomic.LoadInt64(&pm.totalOps)),
		slog.Int64("slow_operations", atomic.LoadInt64(&pm.slowOps)),
		slog.Int64("error_operations", atomic.LoadInt64(&pm.errorOps)))

	return nil
}

// Helper methods

// updateOperationStats updates statistics for a specific operation type
func (pm *PerformanceMonitor) updateOperationStats(operation string, duration time.Duration, isSlow, hasError bool) {
	stats, exists := pm.metrics[operation]
	if !exists {
		stats = &operationStats{
			minDuration: duration,
			maxDuration: duration,
		}
		pm.metrics[operation] = stats
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.count++
	stats.totalDuration += duration

	if duration < stats.minDuration {
		stats.minDuration = duration
	}
	if duration > stats.maxDuration {
		stats.maxDuration = duration
	}

	if isSlow {
		stats.slowCount++
	}

	if hasError {
		stats.errorCount++
	}
}

// addRecentOperation adds an operation to the recent operations buffer
func (pm *PerformanceMonitor) addRecentOperation(metric OperationMetric) {
	pm.recentOpsMu.Lock()
	defer pm.recentOpsMu.Unlock()

	// Keep only the most recent 1000 operations
	if len(pm.recentOps) >= 1000 {
		copy(pm.recentOps, pm.recentOps[1:])
		pm.recentOps[999] = metric
	} else {
		pm.recentOps = append(pm.recentOps, metric)
	}
}

// addTimingData adds timing data for percentile calculations
func (pm *PerformanceMonitor) addTimingData(duration time.Duration) {
	pm.timesMu.Lock()
	defer pm.timesMu.Unlock()

	// Keep only the most recent 10000 timings for percentile calculations
	if len(pm.allTimes) >= 10000 {
		copy(pm.allTimes, pm.allTimes[1:])
		pm.allTimes[9999] = duration
	} else {
		pm.allTimes = append(pm.allTimes, duration)
	}
}

// calculateTimingPercentiles calculates response time percentiles
func (pm *PerformanceMonitor) calculateTimingPercentiles(stats *PerformanceStats) {
	pm.timesMu.RLock()
	defer pm.timesMu.RUnlock()

	if len(pm.allTimes) == 0 {
		return
	}

	// Create a copy for sorting
	times := make([]time.Duration, len(pm.allTimes))
	copy(times, pm.allTimes)
	sort.Slice(times, func(i, j int) bool {
		return times[i] < times[j]
	})

	// Calculate percentiles
	stats.MinResponseTime = times[0]
	stats.MaxResponseTime = times[len(times)-1]

	// Calculate average
	var total time.Duration
	for _, t := range times {
		total += t
	}
	stats.AvgResponseTime = total / time.Duration(len(times))

	// Calculate percentiles
	stats.P50ResponseTime = times[len(times)*50/100]
	stats.P95ResponseTime = times[len(times)*95/100]
	stats.P99ResponseTime = times[len(times)*99/100]
}

// getTopSlowOperations returns the slowest operations
func (pm *PerformanceMonitor) getTopSlowOperations(limit int) []OperationMetric {
	pm.recentOpsMu.RLock()
	defer pm.recentOpsMu.RUnlock()

	// Find slow operations
	var slowOps []OperationMetric
	for _, op := range pm.recentOps {
		if op.IsSlow {
			slowOps = append(slowOps, op)
		}
	}

	// Sort by duration (slowest first)
	sort.Slice(slowOps, func(i, j int) bool {
		return slowOps[i].Duration > slowOps[j].Duration
	})

	// Return top N
	if len(slowOps) > limit {
		slowOps = slowOps[:limit]
	}

	return slowOps
}

// getConnectionID extracts connection identifier from context
func (pm *PerformanceMonitor) getConnectionID(ctx context.Context) string {
	if ctx == nil {
		return "unknown"
	}

	// Try to extract connection ID from context
	// This would be set by the connection pool if available
	if connID := ctx.Value("connection_id"); connID != nil {
		if id, ok := connID.(string); ok {
			return id
		}
	}

	return "direct"
}

// startBackgroundCleanup starts the background cleanup routine
func (pm *PerformanceMonitor) startBackgroundCleanup() {
	cleanupInterval := pm.config.MetricsRetentionPeriod / 4 // Clean up 4 times per retention period
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute
	}

	pm.ticker = time.NewTicker(cleanupInterval)

	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		defer pm.ticker.Stop()

		for {
			select {
			case <-pm.ticker.C:
				pm.performCleanup()
			case <-pm.stopChan:
				return
			}
		}
	}()
}

// performCleanup removes old metrics data
func (pm *PerformanceMonitor) performCleanup() {
	cutoff := time.Now().Add(-pm.config.MetricsRetentionPeriod)

	pm.recentOpsMu.Lock()
	// Remove operations older than retention period
	var kept []OperationMetric
	for _, op := range pm.recentOps {
		if op.Timestamp.After(cutoff) {
			kept = append(kept, op)
		}
	}
	pm.recentOps = kept
	pm.recentOpsMu.Unlock()

	// Force garbage collection if we've cleaned up a lot
	runtime.GC()

	pm.logger.Debug("performance_metrics_cleanup_completed",
		slog.Time("cutoff", cutoff),
		slog.Int("operations_retained", len(kept)))
}

// SearchOptions provides configuration for optimized search operations
type SearchOptions struct {
	// CacheKey is a custom cache key for this search (optional)
	CacheKey string
	// TTL overrides the default cache TTL (optional)
	TTL time.Duration
	// RefreshStale enables background refresh of stale entries
	RefreshStale bool
	// BackgroundLoad enables background loading to warm the cache
	BackgroundLoad bool
	// UseNegativeCache enables caching of negative results
	UseNegativeCache bool
	// MaxResults limits the number of results returned
	MaxResults int
	// Timeout sets a custom timeout for this operation
	Timeout time.Duration
	// AttributeFilter specifies which attributes to retrieve
	AttributeFilter []string
}

// DefaultSearchOptions returns SearchOptions with sensible defaults
func DefaultSearchOptions() *SearchOptions {
	return &SearchOptions{
		RefreshStale:     true,
		BackgroundLoad:   false,
		UseNegativeCache: true,
		MaxResults:       0, // No limit
		Timeout:          30 * time.Second,
		AttributeFilter:  nil, // All attributes
	}
}

// BulkSearchOptions provides configuration for bulk operations
type BulkSearchOptions struct {
	// BatchSize controls how many operations to process in parallel
	BatchSize int
	// Timeout is the total timeout for the bulk operation
	Timeout time.Duration
	// ContinueOnError determines whether to continue on individual failures
	ContinueOnError bool
	// UseCache enables caching for individual operations in the bulk
	UseCache bool
	// CachePrefix is used to generate cache keys for bulk operations
	CachePrefix string
}

// DefaultBulkSearchOptions returns BulkSearchOptions with sensible defaults
func DefaultBulkSearchOptions() *BulkSearchOptions {
	return &BulkSearchOptions{
		BatchSize:       10,
		Timeout:         5 * time.Minute,
		ContinueOnError: true,
		UseCache:        true,
		CachePrefix:     "bulk",
	}
}
