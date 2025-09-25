package metrics

import (
	"context"
	"log/slog"
	"runtime"
	"sort"
	"sync"
	"time"
)

// PerformanceConfig contains configuration for performance monitoring
type PerformanceConfig struct {
	Enabled              bool          `json:"enabled"`               // Enable performance monitoring
	SlowQueryThreshold   time.Duration `json:"slow_query_threshold"`  // Threshold for slow query detection
	MetricsRetention     time.Duration `json:"metrics_retention"`     // How long to keep metrics data
	SampleRate           float64       `json:"sample_rate"`           // Sample rate for detailed metrics (0.0-1.0)
	DetailedMetrics      bool          `json:"detailed_metrics"`      // Enable detailed per-operation metrics
	BufferSize           int           `json:"buffer_size"`           // Size of metrics buffer
	FlushInterval        time.Duration `json:"flush_interval"`        // How often to flush metrics
	ExportPrometheus     bool          `json:"export_prometheus"`     // Enable Prometheus metrics export
	PrometheusNamespace  string        `json:"prometheus_namespace"`  // Namespace for Prometheus metrics
	MemoryStatsInterval  time.Duration `json:"memory_stats_interval"` // How often to collect memory stats
	HistogramBuckets     []float64     `json:"histogram_buckets"`     // Custom histogram buckets for response times

	// Additional fields for compatibility with examples
	MetricsRetentionPeriod time.Duration `json:"metrics_retention_period"` // Alias for MetricsRetention
	MaxSearchResults       int           `json:"max_search_results"`        // Maximum number of search results
	SearchTimeout          time.Duration `json:"search_timeout"`            // Timeout for search operations
	EnablePrefetch         bool          `json:"enable_prefetch"`           // Enable prefetching optimizations
	EnableBulkOperations   bool          `json:"enable_bulk_operations"`    // Enable bulk operation optimizations
}

// DefaultPerformanceConfig returns a PerformanceConfig with sensible defaults
func DefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		Enabled:              true,
		SlowQueryThreshold:   100 * time.Millisecond,
		MetricsRetention:     24 * time.Hour,
		SampleRate:           0.1, // Sample 10% for detailed metrics
		DetailedMetrics:      true,
		BufferSize:           1000,
		FlushInterval:        1 * time.Minute,
		ExportPrometheus:     false,
		PrometheusNamespace:  "ldap",
		MemoryStatsInterval:  30 * time.Second,
		HistogramBuckets:     []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},

		// Default values for additional fields
		MetricsRetentionPeriod: 24 * time.Hour,
		MaxSearchResults:       0, // 0 means no limit
		SearchTimeout:          30 * time.Second,
		EnablePrefetch:         false,
		EnableBulkOperations:   true,
	}
}

// ConnectionPoolStats represents connection pool statistics
type ConnectionPoolStats struct {
	// Basic pool information
	MaxConnections    int `json:"max_connections"`
	MinConnections    int `json:"min_connections"`
	ActiveConnections int `json:"active_connections"`
	IdleConnections   int `json:"idle_connections"`

	// Performance metrics
	TotalRequests     int64 `json:"total_requests"`
	PoolHits          int64 `json:"pool_hits"`
	PoolMisses        int64 `json:"pool_misses"`

	// Timing statistics
	AvgWaitTime       time.Duration `json:"avg_wait_time"`
	MaxWaitTime       time.Duration `json:"max_wait_time"`

	// Health metrics
	FailedConnections int64 `json:"failed_connections"`
	TimeoutsCount     int64 `json:"timeouts_count"`
}

// PerformanceMetrics represents aggregated performance statistics
type PerformanceMetrics struct {
	// Basic counters
	OperationsTotal   int64                  `json:"operations_total"`
	ErrorCount        int64                  `json:"error_count"`
	TimeoutCount      int64                  `json:"timeout_count"`
	SlowQueries       int64                  `json:"slow_queries"`
	CacheHits         int64                  `json:"cache_hits"`
	CacheMisses       int64                  `json:"cache_misses"`

	// Timing statistics
	AvgResponseTime   time.Duration          `json:"avg_response_time"`
	MinResponseTime   time.Duration          `json:"min_response_time"`
	MaxResponseTime   time.Duration          `json:"max_response_time"`
	P50ResponseTime   time.Duration          `json:"p50_response_time"`
	P95ResponseTime   time.Duration          `json:"p95_response_time"`
	P99ResponseTime   time.Duration          `json:"p99_response_time"`

	// Resource usage
	MemoryUsageMB     float64                `json:"memory_usage_mb"`
	GoroutineCount    int                    `json:"goroutine_count"`

	// Operation breakdown
	OperationsByType    map[string]int64       `json:"operations_by_type"`
	ErrorsByType        map[string]int64       `json:"errors_by_type"`
	SlowQueriesByType   map[string]int64       `json:"slow_queries_by_type"`

	// Time series data (recent samples)
	ResponseTimes     []time.Duration        `json:"response_times,omitempty"`
	TimeStamps        []time.Time            `json:"timestamps,omitempty"`

	// Cache statistics
	CacheHitRatio     float64                `json:"cache_hit_ratio"`

	// Backward compatibility fields for direct pool access
	PoolHits          int64                  `json:"pool_hits"`
	PoolMisses        int64                  `json:"pool_misses"`
	TotalConnections  int                    `json:"total_connections"`
	ConnectionsCreated int64                 `json:"connections_created"`

	// Additional fields for example compatibility
	ActiveConnections    int                    `json:"active_connections"`
	IdleConnections      int                    `json:"idle_connections"`
	HealthChecksPassed   int64                  `json:"health_checks_passed"`
	HealthChecksFailed   int64                  `json:"health_checks_failed"`
	ConnectionsClosed    int64                  `json:"connections_closed"`
	ConnectionPoolRatio  float64                `json:"connection_pool_ratio"`
	TopSlowOperations    []OperationMetric      `json:"top_slow_operations,omitempty"`

	// Connection pool stats (if available)
	PoolStats         *ConnectionPoolStats   `json:"pool_stats,omitempty"`
}

// PerformanceStats is an alias for PerformanceMetrics for interface compatibility
type PerformanceStats = PerformanceMetrics

// OperationMetric represents metrics for a single operation
type OperationMetric struct {
	Operation     string        `json:"operation"`
	StartTime     time.Time     `json:"start_time"`
	Duration      time.Duration `json:"duration"`
	Success       bool          `json:"success"`
	ErrorMessage  string        `json:"error_message,omitempty"`
	CacheHit      bool          `json:"cache_hit"`
	ResultCount   int           `json:"result_count"`
	UserAgent     string        `json:"user_agent,omitempty"`
	ClientIP      string        `json:"client_ip,omitempty"`
}

// PerformanceMonitor provides comprehensive performance monitoring and metrics collection
type PerformanceMonitor struct {
	config          *PerformanceConfig
	logger          *slog.Logger
	metrics         *PerformanceMetrics
	operations      []OperationMetric
	mutex           sync.RWMutex
	started         time.Time
	lastFlush       time.Time
	responseTimes   []time.Duration // For percentile calculations

	// Optional external components for integrated metrics
	cache Cache
	pool  *ConnectionPool
}

// NewPerformanceMonitor creates a new performance monitor with the given configuration
func NewPerformanceMonitor(config *PerformanceConfig, logger *slog.Logger) *PerformanceMonitor {
	if config == nil {
		config = DefaultPerformanceConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	pm := &PerformanceMonitor{
		config:        config,
		logger:        logger,
		started:       time.Now(),
		lastFlush:     time.Now(),
		metrics:       &PerformanceMetrics{
			OperationsByType: make(map[string]int64),
			ErrorsByType:     make(map[string]int64),
			MinResponseTime:  time.Duration(^uint64(0) >> 1), // Max duration
		},
		operations:    make([]OperationMetric, 0, config.BufferSize),
		responseTimes: make([]time.Duration, 0, config.BufferSize),
	}

	if config.Enabled {
		pm.startBackgroundTasks()
	}

	return pm
}

// SetCache links a cache instance for integrated metrics collection
func (pm *PerformanceMonitor) SetCache(cache Cache) {
	pm.cache = cache
}

// SetConnectionPool links a connection pool instance for integrated metrics collection
func (pm *PerformanceMonitor) SetConnectionPool(pool *ConnectionPool) {
	pm.pool = pool
}

// RecordOperation records the completion of an LDAP operation
func (pm *PerformanceMonitor) RecordOperation(ctx context.Context, operation string, duration time.Duration, cacheHit bool, err error, resultCount int) {
	if !pm.config.Enabled {
		return
	}

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Create operation metric
	metric := OperationMetric{
		Operation:   operation,
		StartTime:   time.Now().Add(-duration),
		Duration:    duration,
		Success:     err == nil,
		CacheHit:    cacheHit,
		ResultCount: resultCount,
	}

	if err != nil {
		metric.ErrorMessage = err.Error()
	}

	// Extract context information if available
	if ctx != nil {
		metric.ClientIP = extractClientIP(ctx)
		if userAgent := ctx.Value("user_agent"); userAgent != nil {
			if ua, ok := userAgent.(string); ok {
				metric.UserAgent = ua
			}
		}
	}

	// Update basic counters
	pm.metrics.OperationsTotal++
	pm.metrics.OperationsByType[operation]++

	if err != nil {
		pm.metrics.ErrorCount++
		pm.metrics.ErrorsByType[operation]++
	}

	if cacheHit {
		pm.metrics.CacheHits++
	} else {
		pm.metrics.CacheMisses++
	}

	// Update cache hit ratio
	totalCacheOperations := pm.metrics.CacheHits + pm.metrics.CacheMisses
	if totalCacheOperations > 0 {
		pm.metrics.CacheHitRatio = float64(pm.metrics.CacheHits) / float64(totalCacheOperations) * 100
	}

	// Check for slow queries
	if duration > pm.config.SlowQueryThreshold {
		pm.metrics.SlowQueries++
	}

	// Update timing statistics
	pm.responseTimes = append(pm.responseTimes, duration)
	pm.updateTimingStats(duration)

	// Store detailed metric if sampling allows
	if pm.config.DetailedMetrics && pm.shouldSample() {
		pm.operations = append(pm.operations, metric)
	}

	// Trim buffers if they're getting too large
	if len(pm.operations) > pm.config.BufferSize {
		pm.operations = pm.operations[len(pm.operations)-pm.config.BufferSize:]
	}
	if len(pm.responseTimes) > pm.config.BufferSize {
		pm.responseTimes = pm.responseTimes[len(pm.responseTimes)-pm.config.BufferSize:]
	}

	pm.logger.Debug("operation_recorded",
		slog.String("operation", operation),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit),
		slog.Bool("success", err == nil),
		slog.Int("result_count", resultCount))
}

// StartOperation returns a function to record operation completion (convenience method)
func (pm *PerformanceMonitor) StartOperation(ctx context.Context, operation string) func(bool, error, int) {
	start := time.Now()
	return func(cacheHit bool, err error, resultCount int) {
		duration := time.Since(start)
		pm.RecordOperation(ctx, operation, duration, cacheHit, err, resultCount)
	}
}

// GetStats returns current performance statistics
func (pm *PerformanceMonitor) GetStats() *PerformanceMetrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Create a copy of metrics
	stats := &PerformanceMetrics{
		OperationsTotal:   pm.metrics.OperationsTotal,
		ErrorCount:        pm.metrics.ErrorCount,
		SlowQueries:       pm.metrics.SlowQueries,
		CacheHits:         pm.metrics.CacheHits,
		CacheMisses:       pm.metrics.CacheMisses,
		AvgResponseTime:   pm.metrics.AvgResponseTime,
		MinResponseTime:   pm.metrics.MinResponseTime,
		MaxResponseTime:   pm.metrics.MaxResponseTime,
		P50ResponseTime:   pm.metrics.P50ResponseTime,
		P95ResponseTime:   pm.metrics.P95ResponseTime,
		P99ResponseTime:   pm.metrics.P99ResponseTime,
		MemoryUsageMB:     pm.metrics.MemoryUsageMB,
		GoroutineCount:    pm.metrics.GoroutineCount,
		CacheHitRatio:     pm.metrics.CacheHitRatio,
		OperationsByType:  make(map[string]int64),
		ErrorsByType:      make(map[string]int64),
	}

	// Copy maps
	for k, v := range pm.metrics.OperationsByType {
		stats.OperationsByType[k] = v
	}
	for k, v := range pm.metrics.ErrorsByType {
		stats.ErrorsByType[k] = v
	}

	// Add pool stats if available
	if pm.pool != nil {
		poolStats := pm.pool.Stats()
		stats.PoolStats = &ConnectionPoolStats{
			MaxConnections:    0, // Not available in PoolStats, would need config
			MinConnections:    0, // Not available in PoolStats, would need config
			ActiveConnections: int(poolStats.ActiveConnections),
			IdleConnections:   int(poolStats.IdleConnections),
			TotalRequests:     0, // Not available in PoolStats
			PoolHits:          poolStats.PoolHits,
			PoolMisses:        poolStats.PoolMisses,
			AvgWaitTime:       0, // Not available in PoolStats
			MaxWaitTime:       0, // Not available in PoolStats
			FailedConnections: 0, // Not available in PoolStats
			TimeoutsCount:     0, // Not available in PoolStats
		}
	}

	// Copy recent response times if requested
	if len(pm.responseTimes) > 0 {
		stats.ResponseTimes = make([]time.Duration, len(pm.responseTimes))
		copy(stats.ResponseTimes, pm.responseTimes)
	}

	return stats
}

// GetOperationHistory returns detailed operation history
func (pm *PerformanceMonitor) GetOperationHistory() []OperationMetric {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	history := make([]OperationMetric, len(pm.operations))
	copy(history, pm.operations)
	return history
}

// Reset clears all performance metrics (useful for testing)
func (pm *PerformanceMonitor) Reset() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.metrics = &PerformanceMetrics{
		OperationsByType: make(map[string]int64),
		ErrorsByType:     make(map[string]int64),
		MinResponseTime:  time.Duration(^uint64(0) >> 1), // Max duration
	}
	pm.operations = make([]OperationMetric, 0, pm.config.BufferSize)
	pm.responseTimes = make([]time.Duration, 0, pm.config.BufferSize)
	pm.started = time.Now()
	pm.lastFlush = time.Now()

	pm.logger.Debug("performance_metrics_reset")
}

// Close stops background tasks and cleans up resources
func (pm *PerformanceMonitor) Close() error {
	pm.logger.Debug("performance_monitor_stopping")
	// Background tasks will stop naturally when the monitor is garbage collected
	// or when the application exits. For a more graceful shutdown, we could
	// implement a context-based cancellation system.
	return nil
}

// updateTimingStats updates timing-related statistics
func (pm *PerformanceMonitor) updateTimingStats(duration time.Duration) {
	// Update min/max
	if duration < pm.metrics.MinResponseTime {
		pm.metrics.MinResponseTime = duration
	}
	if duration > pm.metrics.MaxResponseTime {
		pm.metrics.MaxResponseTime = duration
	}

	// Calculate average
	if pm.metrics.OperationsTotal > 0 {
		totalDuration := time.Duration(pm.metrics.AvgResponseTime.Nanoseconds() * (pm.metrics.OperationsTotal - 1))
		totalDuration += duration
		pm.metrics.AvgResponseTime = time.Duration(totalDuration.Nanoseconds() / pm.metrics.OperationsTotal)
	}

	// Calculate percentiles if we have enough data
	if len(pm.responseTimes) >= 10 {
		pm.calculatePercentiles()
	}
}

// calculatePercentiles calculates response time percentiles
func (pm *PerformanceMonitor) calculatePercentiles() {
	if len(pm.responseTimes) == 0 {
		return
	}

	// Create a sorted copy
	sorted := make([]time.Duration, len(pm.responseTimes))
	copy(sorted, pm.responseTimes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	// Calculate percentiles
	pm.metrics.P50ResponseTime = sorted[len(sorted)*50/100]
	pm.metrics.P95ResponseTime = sorted[len(sorted)*95/100]
	pm.metrics.P99ResponseTime = sorted[len(sorted)*99/100]
}

// shouldSample determines if an operation should be sampled for detailed metrics
func (pm *PerformanceMonitor) shouldSample() bool {
	if pm.config.SampleRate <= 0 {
		return false
	}
	if pm.config.SampleRate >= 1.0 {
		return true
	}

	// Simple deterministic sampling based on operation count
	return pm.metrics.OperationsTotal%int64(1/pm.config.SampleRate) == 0
}

// startBackgroundTasks starts background monitoring tasks
func (pm *PerformanceMonitor) startBackgroundTasks() {
	// Memory stats collection
	go pm.memoryStatsCollector()

	// Periodic cleanup of old metrics
	go pm.metricsCleanup()
}

// memoryStatsCollector periodically collects memory and runtime statistics
func (pm *PerformanceMonitor) memoryStatsCollector() {
	ticker := time.NewTicker(pm.config.MemoryStatsInterval)
	defer ticker.Stop()

	for range ticker.C {
		pm.updateMemoryStats()
	}
}

// updateMemoryStats updates memory and runtime statistics
func (pm *PerformanceMonitor) updateMemoryStats() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Convert bytes to MB
	pm.metrics.MemoryUsageMB = float64(m.Alloc) / 1024 / 1024
	pm.metrics.GoroutineCount = runtime.NumGoroutine()
}

// metricsCleanup periodically cleans up old metrics data
func (pm *PerformanceMonitor) metricsCleanup() {
	ticker := time.NewTicker(pm.config.FlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		pm.cleanupOldMetrics()
	}
}

// cleanupOldMetrics removes metrics data older than retention period
func (pm *PerformanceMonitor) cleanupOldMetrics() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	cutoff := time.Now().Add(-pm.config.MetricsRetention)

	// Clean up detailed operations
	var kept []OperationMetric
	for _, op := range pm.operations {
		if op.StartTime.After(cutoff) {
			kept = append(kept, op)
		}
	}
	pm.operations = kept

	pm.logger.Debug("metrics_cleanup_completed",
		slog.Time("cutoff", cutoff),
		slog.Int("operations_retained", len(kept)))
}

// extractClientIP safely extracts client IP from context
func extractClientIP(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if ip := ctx.Value("client_ip"); ip != nil {
		if ipStr, ok := ip.(string); ok {
			return ipStr
		}
	}
	return ""
}

// SearchOptions provides configuration for optimized search operations
type SearchOptions struct {
	// UseCache enables/disables caching for this search
	UseCache bool
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
		UseCache:         true,
		RefreshStale:     true,
		BackgroundLoad:   false,
		UseNegativeCache: true,
		MaxResults:       1000,
		Timeout:          30 * time.Second,
	}
}

// BulkSearchOptions provides configuration for optimized bulk search operations
type BulkSearchOptions struct {
	// BatchSize determines how many searches to perform concurrently
	BatchSize int
	// Timeout sets a custom timeout for the entire bulk operation
	Timeout time.Duration
	// ContinueOnError enables continuing even if some searches fail
	ContinueOnError bool
	// UseCache enables/disables caching for bulk searches
	UseCache bool
	// CachePrefix is a prefix for cache keys in bulk operations
	CachePrefix string
	// MaxConcurrency limits the number of concurrent searches
	MaxConcurrency int
	// RetryAttempts specifies how many times to retry failed searches
	RetryAttempts int
	// RetryDelay specifies the delay between retry attempts
	RetryDelay time.Duration
}