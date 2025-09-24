package ldap

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// PrometheusExporter provides Prometheus-formatted metrics export
type PrometheusExporter struct {
	perfMonitor  *PerformanceMonitor
	rateLimiter  *RateLimiter
	cache        Cache
	pool         *ConnectionPool
	namespace    string
	labels       map[string]string
}

// PrometheusConfig configures the Prometheus metrics exporter
type PrometheusConfig struct {
	Namespace    string            // Metrics namespace (e.g., "ldap_client")
	Labels       map[string]string // Additional labels for all metrics
	IncludeHelp  bool              // Include help text for metrics
	IncludeType  bool              // Include type information for metrics
}

// DefaultPrometheusConfig returns sensible defaults for Prometheus export
func DefaultPrometheusConfig() *PrometheusConfig {
	return &PrometheusConfig{
		Namespace:   "ldap_client",
		Labels:      make(map[string]string),
		IncludeHelp: true,
		IncludeType: true,
	}
}

// NewPrometheusExporter creates a new Prometheus metrics exporter
func NewPrometheusExporter(config *PrometheusConfig) *PrometheusExporter {
	if config == nil {
		config = DefaultPrometheusConfig()
	}

	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}

	return &PrometheusExporter{
		namespace: config.Namespace,
		labels:    config.Labels,
	}
}

// SetPerformanceMonitor sets the performance monitor for metrics export
func (pe *PrometheusExporter) SetPerformanceMonitor(monitor *PerformanceMonitor) {
	pe.perfMonitor = monitor
}

// SetRateLimiter sets the rate limiter for metrics export
func (pe *PrometheusExporter) SetRateLimiter(limiter *RateLimiter) {
	pe.rateLimiter = limiter
}

// SetCache sets the cache for metrics export
func (pe *PrometheusExporter) SetCache(cache Cache) {
	pe.cache = cache
}

// SetConnectionPool sets the connection pool for metrics export
func (pe *PrometheusExporter) SetConnectionPool(pool *ConnectionPool) {
	pe.pool = pool
}

// WriteMetrics writes all metrics in Prometheus format to the provided writer
func (pe *PrometheusExporter) WriteMetrics(w io.Writer, config *PrometheusConfig) error {
	if config == nil {
		config = DefaultPrometheusConfig()
	}

	// Write performance metrics
	if pe.perfMonitor != nil {
		if err := pe.writePerformanceMetrics(w, config); err != nil {
			return fmt.Errorf("failed to write performance metrics: %w", err)
		}
	}

	// Write rate limiter metrics
	if pe.rateLimiter != nil {
		if err := pe.writeRateLimiterMetrics(w, config); err != nil {
			return fmt.Errorf("failed to write rate limiter metrics: %w", err)
		}
	}

	// Write cache metrics
	if pe.cache != nil {
		if err := pe.writeCacheMetrics(w, config); err != nil {
			return fmt.Errorf("failed to write cache metrics: %w", err)
		}
	}

	// Write connection pool metrics
	if pe.pool != nil {
		if err := pe.writePoolMetrics(w, config); err != nil {
			return fmt.Errorf("failed to write pool metrics: %w", err)
		}
	}

	return nil
}

// writePerformanceMetrics writes performance monitoring metrics
func (pe *PrometheusExporter) writePerformanceMetrics(w io.Writer, config *PrometheusConfig) error {
	stats := pe.perfMonitor.GetStats()

	// Operations metrics
	pe.writeMetric(w, config, "operations_total", "counter",
		"Total number of LDAP operations performed",
		float64(stats.OperationsTotal), nil)

	pe.writeMetric(w, config, "operations_errors_total", "counter",
		"Total number of LDAP operations that resulted in errors",
		float64(stats.ErrorCount), nil)

	pe.writeMetric(w, config, "operations_timeouts_total", "counter",
		"Total number of LDAP operations that timed out",
		float64(stats.TimeoutCount), nil)

	pe.writeMetric(w, config, "operations_slow_total", "counter",
		"Total number of slow LDAP operations",
		float64(stats.SlowQueries), nil)

	// Response time metrics
	pe.writeMetric(w, config, "response_time_seconds", "gauge",
		"Average response time for LDAP operations",
		stats.AvgResponseTime.Seconds(), map[string]string{"percentile": "avg"})

	pe.writeMetric(w, config, "response_time_seconds", "gauge",
		"50th percentile response time for LDAP operations",
		stats.P50ResponseTime.Seconds(), map[string]string{"percentile": "50"})

	pe.writeMetric(w, config, "response_time_seconds", "gauge",
		"95th percentile response time for LDAP operations",
		stats.P95ResponseTime.Seconds(), map[string]string{"percentile": "95"})

	pe.writeMetric(w, config, "response_time_seconds", "gauge",
		"99th percentile response time for LDAP operations",
		stats.P99ResponseTime.Seconds(), map[string]string{"percentile": "99"})

	pe.writeMetric(w, config, "response_time_seconds", "gauge",
		"Minimum response time for LDAP operations",
		stats.MinResponseTime.Seconds(), map[string]string{"percentile": "min"})

	pe.writeMetric(w, config, "response_time_seconds", "gauge",
		"Maximum response time for LDAP operations",
		stats.MaxResponseTime.Seconds(), map[string]string{"percentile": "max"})

	// Operation type breakdown
	for opType, count := range stats.OperationsByType {
		labels := map[string]string{"operation": opType}
		pe.writeMetric(w, config, "operations_by_type_total", "counter",
			"Total LDAP operations by type",
			float64(count), labels)
	}

	// Slow queries by type
	for opType, count := range stats.SlowQueriesByType {
		labels := map[string]string{"operation": opType}
		pe.writeMetric(w, config, "slow_operations_by_type_total", "counter",
			"Slow LDAP operations by type",
			float64(count), labels)
	}

	// Memory and resource metrics
	pe.writeMetric(w, config, "memory_usage_bytes", "gauge",
		"Current memory usage in bytes",
		float64(stats.MemoryUsageMB*1024*1024), nil)

	pe.writeMetric(w, config, "goroutines_active", "gauge",
		"Number of active goroutines",
		float64(stats.GoroutineCount), nil)

	return nil
}

// writeRateLimiterMetrics writes rate limiting metrics
func (pe *PrometheusExporter) writeRateLimiterMetrics(w io.Writer, config *PrometheusConfig) error {
	metrics := pe.rateLimiter.GetMetrics()

	// Basic attempt metrics
	pe.writeMetric(w, config, "rate_limiter_attempts_total", "counter",
		"Total authentication attempts processed by rate limiter",
		float64(metrics.TotalAttempts), nil)

	pe.writeMetric(w, config, "rate_limiter_blocked_total", "counter",
		"Total authentication attempts blocked by rate limiter",
		float64(metrics.BlockedAttempts), nil)

	pe.writeMetric(w, config, "rate_limiter_successful_total", "counter",
		"Total authentication attempts that passed rate limiting",
		float64(metrics.SuccessfulAttempts), nil)

	pe.writeMetric(w, config, "rate_limiter_whitelisted_total", "counter",
		"Total authentication attempts from whitelisted sources",
		float64(metrics.WhitelistedAttempts), nil)

	// Security metrics
	pe.writeMetric(w, config, "rate_limiter_violations_total", "counter",
		"Total rate limit violations",
		float64(metrics.ViolationEvents), nil)

	pe.writeMetric(w, config, "rate_limiter_suspicious_patterns_total", "counter",
		"Detected suspicious activity patterns",
		float64(metrics.SuspiciousPatterns), nil)

	pe.writeMetric(w, config, "rate_limiter_burst_attacks_total", "counter",
		"Detected burst attack patterns",
		float64(metrics.BurstAttacks), nil)

	pe.writeMetric(w, config, "rate_limiter_repeated_violators_total", "counter",
		"Identifiers with multiple violations",
		float64(metrics.RepeatedViolators), nil)

	// Current state metrics
	pe.writeMetric(w, config, "rate_limiter_active_lockouts", "gauge",
		"Currently locked out identifiers",
		float64(metrics.ActiveLockouts), nil)

	pe.writeMetric(w, config, "rate_limiter_unique_identifiers", "gauge",
		"Number of unique identifiers tracked",
		float64(metrics.UniqueIdentifiers), nil)

	// Performance metrics
	pe.writeMetric(w, config, "rate_limiter_check_duration_seconds", "gauge",
		"Average time for rate limit checks",
		metrics.AvgCheckTime.Seconds(), nil)

	pe.writeMetric(w, config, "rate_limiter_peak_concurrent_checks", "gauge",
		"Peak number of concurrent rate limit checks",
		float64(metrics.PeakConcurrentChecks), nil)

	pe.writeMetric(w, config, "rate_limiter_memory_bytes", "gauge",
		"Approximate memory usage by rate limiter",
		float64(metrics.MemoryUsageBytes), nil)

	return nil
}

// writeCacheMetrics writes cache performance metrics
func (pe *PrometheusExporter) writeCacheMetrics(w io.Writer, config *PrometheusConfig) error {
	stats := pe.cache.Stats()

	pe.writeMetric(w, config, "cache_hits_total", "counter",
		"Total cache hits",
		float64(stats.Hits), nil)

	pe.writeMetric(w, config, "cache_misses_total", "counter",
		"Total cache misses",
		float64(stats.Misses), nil)

	pe.writeMetric(w, config, "cache_hit_ratio", "gauge",
		"Cache hit ratio as percentage",
		stats.HitRatio, nil)

	pe.writeMetric(w, config, "cache_sets_total", "counter",
		"Total cache set operations",
		float64(stats.Sets), nil)

	pe.writeMetric(w, config, "cache_entries_current", "gauge",
		"Current number of cache entries",
		float64(stats.TotalEntries), nil)

	pe.writeMetric(w, config, "cache_evictions_total", "counter",
		"Total cache evictions",
		float64(stats.Evictions), nil)

	pe.writeMetric(w, config, "cache_memory_bytes", "gauge",
		"Approximate cache memory usage",
		float64(stats.MemoryUsageBytes), nil)

	return nil
}

// writePoolMetrics writes connection pool metrics
func (pe *PrometheusExporter) writePoolMetrics(w io.Writer, config *PrometheusConfig) error {
	stats := pe.pool.Stats()

	pe.writeMetric(w, config, "connection_pool_total", "gauge",
		"Total connections in pool",
		float64(stats.TotalConnections), nil)

	pe.writeMetric(w, config, "connection_pool_active", "gauge",
		"Active connections from pool",
		float64(stats.ActiveConnections), nil)

	pe.writeMetric(w, config, "connection_pool_idle", "gauge",
		"Idle connections in pool",
		float64(stats.IdleConnections), nil)

	pe.writeMetric(w, config, "connection_pool_hits_total", "counter",
		"Total successful connection pool retrievals",
		float64(stats.PoolHits), nil)

	pe.writeMetric(w, config, "connection_pool_misses_total", "counter",
		"Total connection pool misses requiring new connections",
		float64(stats.PoolMisses), nil)

	pe.writeMetric(w, config, "connection_pool_created_total", "counter",
		"Total connections created",
		float64(stats.ConnectionsCreated), nil)

	return nil
}

// writeMetric writes a single metric in Prometheus format
func (pe *PrometheusExporter) writeMetric(w io.Writer, config *PrometheusConfig,
	name, metricType, help string, value float64, extraLabels map[string]string) {

	fullName := name
	if pe.namespace != "" {
		fullName = pe.namespace + "_" + name
	}

	// Write help text if enabled
	if config.IncludeHelp && help != "" {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n", fullName, help); err != nil {
			// Log error writing help text
			return
		}
	}

	// Write type information if enabled
	if config.IncludeType && metricType != "" {
		if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", fullName, metricType); err != nil {
			// Log error writing type text
			return
		}
	}

	// Combine labels
	allLabels := make(map[string]string)
	for k, v := range pe.labels {
		allLabels[k] = v
	}
	for k, v := range extraLabels {
		allLabels[k] = v
	}

	// Format metric with labels
	if len(allLabels) > 0 {
		// Sort labels for consistent output
		var labelPairs []string
		for k, v := range allLabels {
			labelPairs = append(labelPairs, fmt.Sprintf("%s=\"%s\"", k, escapePrometheusValue(v)))
		}
		sort.Strings(labelPairs)

		if _, err := fmt.Fprintf(w, "%s{%s} %s\n", fullName, strings.Join(labelPairs, ","), formatPrometheusValue(value)); err != nil {
			// Log error writing metric with labels
			return
		}
	} else {
		if _, err := fmt.Fprintf(w, "%s %s\n", fullName, formatPrometheusValue(value)); err != nil {
			// Log error writing metric without labels
			return
		}
	}
}

// formatPrometheusValue formats a float64 value for Prometheus output
func formatPrometheusValue(value float64) string {
	// Handle special cases
	if value != value { // NaN
		return "NaN"
	}
	if math.IsInf(value, 1) { // +Inf
		return "+Inf"
	}
	if math.IsInf(value, -1) { // -Inf
		return "-Inf"
	}

	// Use Go's default formatting but avoid scientific notation for readability
	str := strconv.FormatFloat(value, 'f', -1, 64)
	return str
}

// escapePrometheusValue escapes a string value for use in Prometheus labels
func escapePrometheusValue(value string) string {
	// Escape backslashes and quotes
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\t", "\\t")
	return value
}

// GetMetricsSnapshot returns a string representation of all metrics in Prometheus format
func (pe *PrometheusExporter) GetMetricsSnapshot(config *PrometheusConfig) (string, error) {
	var buf strings.Builder
	if err := pe.WriteMetrics(&buf, config); err != nil {
		return "", err
	}
	return buf.String(), nil
}