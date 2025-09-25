package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/netresearch/simple-ldap-go/internal/cache"
	"github.com/netresearch/simple-ldap-go/internal/pool"
	"github.com/netresearch/simple-ldap-go/internal/validation"
)

// HealthStatus represents the overall health status
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheck represents the health status of a specific component
type HealthCheck struct {
	Name        string                 `json:"name"`
	Status      HealthStatus           `json:"status"`
	Description string                 `json:"description,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Details     map[string]interface{} `json:"details,omitempty"`
	LastCheck   time.Time              `json:"last_check"`
}

// HealthReport provides comprehensive health information
type HealthReport struct {
	OverallStatus HealthStatus           `json:"overall_status"`
	Timestamp     time.Time              `json:"timestamp"`
	Version       string                 `json:"version,omitempty"`
	Uptime        time.Duration          `json:"uptime"`
	Score         int                    `json:"score"` // 0-100 health score
	Checks        []HealthCheck          `json:"checks"`
	Summary       map[string]interface{} `json:"summary"`
}

// LDAPClient interface represents the minimal LDAP client needed for health monitoring
type LDAPClient interface {
	// Add methods needed by health monitor if any
}

// HealthMonitor provides health checking and scoring capabilities
type HealthMonitor struct {
	ldapClient      LDAPClient
	perfMonitor     *PerformanceMonitor
	rateLimiter     *validation.RateLimiter
	cache           cache.Cache
	pool            *pool.ConnectionPool
	prometheusExp   *PrometheusExporter
	startTime       time.Time
	version         string
	thresholds      *HealthThresholds
}

// HealthThresholds defines thresholds for health scoring
type HealthThresholds struct {
	// Performance thresholds
	MaxAvgResponseTime    time.Duration `json:"max_avg_response_time"`
	MaxErrorRate          float64       `json:"max_error_rate"`          // Percentage
	MaxSlowQueryRate      float64       `json:"max_slow_query_rate"`     // Percentage
	MinCacheHitRate       float64       `json:"min_cache_hit_rate"`      // Percentage

	// Rate limiter thresholds
	MaxBlockedRate        float64       `json:"max_blocked_rate"`        // Percentage
	MaxActiveLockouts     int64         `json:"max_active_lockouts"`
	MaxSuspiciousPatterns int64         `json:"max_suspicious_patterns"`

	// Resource thresholds
	MaxMemoryUsageMB      float64       `json:"max_memory_usage_mb"`
	MaxGoroutines         int           `json:"max_goroutines"`
	MinPoolConnections    int32         `json:"min_pool_connections"`

	// Connection thresholds
	ConnectionTimeoutSec  int           `json:"connection_timeout_sec"`
}

// DefaultHealthThresholds returns sensible health check thresholds
func DefaultHealthThresholds() *HealthThresholds {
	return &HealthThresholds{
		MaxAvgResponseTime:    2 * time.Second,
		MaxErrorRate:          5.0,   // 5%
		MaxSlowQueryRate:      10.0,  // 10%
		MinCacheHitRate:       80.0,  // 80%
		MaxBlockedRate:        15.0,  // 15%
		MaxActiveLockouts:     50,
		MaxSuspiciousPatterns: 10,
		MaxMemoryUsageMB:      500.0,
		MaxGoroutines:         1000,
		MinPoolConnections:    2,
		ConnectionTimeoutSec:  5,
	}
}

// NewHealthMonitor creates a new health monitoring system
func NewHealthMonitor(ldapClient LDAPClient, version string) *HealthMonitor {
	return &HealthMonitor{
		ldapClient: ldapClient,
		startTime:  time.Now(),
		version:    version,
		thresholds: DefaultHealthThresholds(),
	}
}

// SetPerformanceMonitor sets the performance monitor for health checks
func (hm *HealthMonitor) SetPerformanceMonitor(monitor *PerformanceMonitor) {
	hm.perfMonitor = monitor
}

// SetRateLimiter sets the rate limiter for health checks
func (hm *HealthMonitor) SetRateLimiter(limiter *validation.RateLimiter) {
	hm.rateLimiter = limiter
}

// SetCache sets the cache for health checks
func (hm *HealthMonitor) SetCache(cache cache.Cache) {
	hm.cache = cache
}

// SetConnectionPool sets the connection pool for health checks
func (hm *HealthMonitor) SetConnectionPool(pool *pool.ConnectionPool) {
	hm.pool = pool
}

// SetPrometheusExporter sets the Prometheus exporter for health checks
func (hm *HealthMonitor) SetPrometheusExporter(exporter *PrometheusExporter) {
	hm.prometheusExp = exporter
}

// SetThresholds updates the health check thresholds
func (hm *HealthMonitor) SetThresholds(thresholds *HealthThresholds) {
	hm.thresholds = thresholds
}

// GetHealthReport generates a comprehensive health report
func (hm *HealthMonitor) GetHealthReport(ctx context.Context) *HealthReport {
	report := &HealthReport{
		Timestamp: time.Now(),
		Version:   hm.version,
		Uptime:    time.Since(hm.startTime),
		Checks:    make([]HealthCheck, 0),
		Summary:   make(map[string]interface{}),
	}

	// Run all health checks
	checks := []func(context.Context) HealthCheck{
		hm.checkLDAPConnection,
		hm.checkPerformance,
		hm.checkRateLimiter,
		hm.checkCache,
		hm.checkConnectionPool,
		hm.checkResources,
	}

	var totalScore int
	healthyChecks := 0

	for _, check := range checks {
		result := check(ctx)
		report.Checks = append(report.Checks, result)

		// Calculate component score
		componentScore := hm.calculateComponentScore(result)
		totalScore += componentScore

		if result.Status == HealthStatusHealthy {
			healthyChecks++
		}
	}

	// Calculate overall health
	report.Score = totalScore / len(checks)
	report.OverallStatus = hm.calculateOverallStatus(report.Score, healthyChecks, len(checks))

	// Add summary information
	report.Summary["healthy_components"] = healthyChecks
	report.Summary["total_components"] = len(checks)
	report.Summary["health_percentage"] = float64(healthyChecks) / float64(len(checks)) * 100

	return report
}

// checkLDAPConnection verifies LDAP server connectivity
func (hm *HealthMonitor) checkLDAPConnection(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Name:      "ldap_connection",
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	start := time.Now()
	defer func() {
		check.Duration = time.Since(start)
	}()

	if hm.ldapClient == nil {
		check.Status = HealthStatusUnhealthy
		check.Error = "LDAP client not configured"
		return check
	}

	// Test connection
	conn, err := hm.ldapClient.GetConnection()
	if err != nil {
		check.Status = HealthStatusUnhealthy
		check.Error = fmt.Sprintf("Failed to get LDAP connection: %v", err)
		return check
	}
	defer func() { _ = conn.Close() }()

	// Simple connectivity test
	err = conn.Bind(hm.ldapClient.user, hm.ldapClient.password)
	if err != nil {
		check.Status = HealthStatusUnhealthy
		check.Error = fmt.Sprintf("Failed to bind to LDAP: %v", err)
		return check
	}

	check.Status = HealthStatusHealthy
	check.Description = "LDAP connection is healthy"
	check.Details["server"] = hm.ldapClient.config.Server
	check.Details["bind_successful"] = true

	// Check if response time is acceptable
	if check.Duration > hm.thresholds.MaxAvgResponseTime {
		check.Status = HealthStatusDegraded
		check.Description = "LDAP connection slow but functional"
	}

	return check
}

// checkPerformance evaluates performance metrics
func (hm *HealthMonitor) checkPerformance(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Name:      "performance",
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	start := time.Now()
	defer func() {
		check.Duration = time.Since(start)
	}()

	if hm.perfMonitor == nil {
		check.Status = HealthStatusHealthy
		check.Description = "Performance monitoring not enabled"
		return check
	}

	stats := hm.perfMonitor.GetStats()

	check.Details["total_operations"] = stats.OperationsTotal
	check.Details["avg_response_time_ms"] = stats.AvgResponseTime.Milliseconds()
	check.Details["error_count"] = stats.ErrorCount
	check.Details["slow_queries"] = stats.SlowQueries

	// Calculate error rate
	var errorRate float64
	if stats.OperationsTotal > 0 {
		errorRate = float64(stats.ErrorCount) / float64(stats.OperationsTotal) * 100
	}

	// Calculate slow query rate
	var slowQueryRate float64
	if stats.OperationsTotal > 0 {
		slowQueryRate = float64(stats.SlowQueries) / float64(stats.OperationsTotal) * 100
	}

	check.Details["error_rate_percent"] = errorRate
	check.Details["slow_query_rate_percent"] = slowQueryRate

	// Evaluate health
	issues := make([]string, 0)

	if stats.AvgResponseTime > hm.thresholds.MaxAvgResponseTime {
		issues = append(issues, fmt.Sprintf("High average response time: %v", stats.AvgResponseTime))
	}

	if errorRate > hm.thresholds.MaxErrorRate {
		issues = append(issues, fmt.Sprintf("High error rate: %.2f%%", errorRate))
	}

	if slowQueryRate > hm.thresholds.MaxSlowQueryRate {
		issues = append(issues, fmt.Sprintf("High slow query rate: %.2f%%", slowQueryRate))
	}

	if len(issues) == 0 {
		check.Status = HealthStatusHealthy
		check.Description = "Performance metrics are within healthy ranges"
	} else if len(issues) <= 1 {
		check.Status = HealthStatusDegraded
		check.Description = fmt.Sprintf("Performance issues detected: %s", issues[0])
	} else {
		check.Status = HealthStatusUnhealthy
		check.Error = fmt.Sprintf("Multiple performance issues: %v", issues)
	}

	return check
}

// checkRateLimiter evaluates rate limiter health
func (hm *HealthMonitor) checkRateLimiter(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Name:      "rate_limiter",
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	start := time.Now()
	defer func() {
		check.Duration = time.Since(start)
	}()

	if hm.rateLimiter == nil {
		check.Status = HealthStatusHealthy
		check.Description = "Rate limiting not enabled"
		return check
	}

	metrics := hm.rateLimiter.GetMetrics()

	check.Details["total_attempts"] = metrics.TotalAttempts
	check.Details["blocked_attempts"] = metrics.BlockedAttempts
	check.Details["active_lockouts"] = metrics.ActiveLockouts
	check.Details["suspicious_patterns"] = metrics.SuspiciousPatterns

	// Calculate blocked rate
	var blockedRate float64
	if metrics.TotalAttempts > 0 {
		blockedRate = float64(metrics.BlockedAttempts) / float64(metrics.TotalAttempts) * 100
	}

	check.Details["blocked_rate_percent"] = blockedRate

	// Evaluate security health
	issues := make([]string, 0)

	if blockedRate > hm.thresholds.MaxBlockedRate {
		issues = append(issues, fmt.Sprintf("High blocked rate: %.2f%%", blockedRate))
	}

	if metrics.ActiveLockouts > hm.thresholds.MaxActiveLockouts {
		issues = append(issues, fmt.Sprintf("High active lockouts: %d", metrics.ActiveLockouts))
	}

	if metrics.SuspiciousPatterns > hm.thresholds.MaxSuspiciousPatterns {
		issues = append(issues, fmt.Sprintf("High suspicious patterns: %d", metrics.SuspiciousPatterns))
	}

	if len(issues) == 0 {
		check.Status = HealthStatusHealthy
		check.Description = "Rate limiter metrics are healthy"
	} else if len(issues) <= 1 {
		check.Status = HealthStatusDegraded
		check.Description = fmt.Sprintf("Rate limiter concerns: %s", issues[0])
	} else {
		check.Status = HealthStatusUnhealthy
		check.Error = fmt.Sprintf("Rate limiter issues: %v", issues)
	}

	return check
}

// checkCache evaluates cache performance
func (hm *HealthMonitor) checkCache(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Name:      "cache",
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	start := time.Now()
	defer func() {
		check.Duration = time.Since(start)
	}()

	if hm.cache == nil {
		check.Status = HealthStatusHealthy
		check.Description = "Caching not enabled"
		return check
	}

	stats := hm.cache.Stats()

	check.Details["hits"] = stats.Hits
	check.Details["misses"] = stats.Misses
	check.Details["hit_ratio"] = stats.HitRatio
	check.Details["total_entries"] = stats.TotalEntries
	check.Details["memory_usage"] = stats.MemoryUsageBytes

	// Evaluate cache health
	if stats.HitRatio < hm.thresholds.MinCacheHitRate && stats.Hits+stats.Misses > 100 {
		check.Status = HealthStatusDegraded
		check.Description = fmt.Sprintf("Low cache hit ratio: %.2f%%", stats.HitRatio)
	} else {
		check.Status = HealthStatusHealthy
		check.Description = "cache.Cache performance is healthy"
	}

	return check
}

// checkConnectionPool evaluates connection pool health
func (hm *HealthMonitor) checkConnectionPool(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Name:      "connection_pool",
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	start := time.Now()
	defer func() {
		check.Duration = time.Since(start)
	}()

	if hm.pool == nil {
		check.Status = HealthStatusHealthy
		check.Description = "Connection pooling not enabled"
		return check
	}

	stats := hm.pool.Stats()

	check.Details["total_connections"] = stats.TotalConnections
	check.Details["active_connections"] = stats.ActiveConnections
	check.Details["idle_connections"] = stats.IdleConnections
	check.Details["pool_hits"] = stats.PoolHits
	check.Details["pool_misses"] = stats.PoolMisses

	// Evaluate pool health
	if stats.TotalConnections < hm.thresholds.MinPoolConnections {
		check.Status = HealthStatusDegraded
		check.Description = fmt.Sprintf("Low connection count: %d", stats.TotalConnections)
	} else {
		check.Status = HealthStatusHealthy
		check.Description = "Connection pool is healthy"
	}

	return check
}

// checkResources evaluates resource usage
func (hm *HealthMonitor) checkResources(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Name:      "resources",
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	start := time.Now()
	defer func() {
		check.Duration = time.Since(start)
	}()

	var memoryUsageMB float64
	var goroutineCount int

	if hm.perfMonitor != nil {
		stats := hm.perfMonitor.GetStats()
		memoryUsageMB = stats.MemoryUsageMB
		goroutineCount = stats.GoroutineCount
	}

	check.Details["memory_usage_mb"] = memoryUsageMB
	check.Details["goroutine_count"] = goroutineCount
	check.Details["uptime_seconds"] = time.Since(hm.startTime).Seconds()

	// Evaluate resource health
	issues := make([]string, 0)

	if memoryUsageMB > hm.thresholds.MaxMemoryUsageMB {
		issues = append(issues, fmt.Sprintf("High memory usage: %.2f MB", memoryUsageMB))
	}

	if goroutineCount > hm.thresholds.MaxGoroutines {
		issues = append(issues, fmt.Sprintf("High goroutine count: %d", goroutineCount))
	}

	if len(issues) == 0 {
		check.Status = HealthStatusHealthy
		check.Description = "Resource usage is within normal ranges"
	} else if len(issues) == 1 {
		check.Status = HealthStatusDegraded
		check.Description = issues[0]
	} else {
		check.Status = HealthStatusUnhealthy
		check.Error = fmt.Sprintf("Resource issues: %v", issues)
	}

	return check
}

// calculateComponentScore calculates a 0-100 score for a component
func (hm *HealthMonitor) calculateComponentScore(check HealthCheck) int {
	switch check.Status {
	case HealthStatusHealthy:
		return 100
	case HealthStatusDegraded:
		return 70
	case HealthStatusUnhealthy:
		return 0
	default:
		return 50
	}
}

// calculateOverallStatus determines overall health based on component scores
func (hm *HealthMonitor) calculateOverallStatus(score int, healthyChecks, totalChecks int) HealthStatus {
	healthyPercentage := float64(healthyChecks) / float64(totalChecks)

	if score >= 90 && healthyPercentage >= 0.9 {
		return HealthStatusHealthy
	} else if score >= 60 && healthyPercentage >= 0.6 {
		return HealthStatusDegraded
	} else {
		return HealthStatusUnhealthy
	}
}

// HTTPHealthHandler provides HTTP endpoints for health checks
type HTTPHealthHandler struct {
	monitor *HealthMonitor
}

// NewHTTPHealthHandler creates a new HTTP health handler
func NewHTTPHealthHandler(monitor *HealthMonitor) *HTTPHealthHandler {
	return &HTTPHealthHandler{
		monitor: monitor,
	}
}

// HandleHealth provides detailed health information
func (h *HTTPHealthHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	report := h.monitor.GetHealthReport(r.Context())

	// Set appropriate HTTP status code
	switch report.OverallStatus {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK) // Some systems prefer 200 for degraded
	case HealthStatusUnhealthy:
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		// If encoding fails, write a simple error response
		w.WriteHeader(http.StatusInternalServerError)
		if _, writeErr := w.Write([]byte(`{"error": "Failed to encode health report"}`)); writeErr != nil {
			// Log error if we have a logger available
			// For now, we silently ignore since this is rare and HTTP connection may be broken
			_ = writeErr // Explicitly acknowledge we're ignoring the error
		}
	}
}

// HandleLiveness provides simple liveness check
func (h *HTTPHealthHandler) HandleLiveness(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte("OK")); err != nil {
		// Log error if we have a logger available
		// For now, we silently ignore since this is rare and HTTP connection may be broken
		_ = err // Explicitly acknowledge we're ignoring the error
	}
}

// HandleReadiness provides readiness check
func (h *HTTPHealthHandler) HandleReadiness(w http.ResponseWriter, r *http.Request) {
	report := h.monitor.GetHealthReport(r.Context())

	// Readiness is stricter than liveness
	if report.OverallStatus == HealthStatusUnhealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte("NOT READY")); err != nil {
			// Log error if we have a logger available
			// For now, we silently ignore since this is rare and HTTP connection may be broken
			_ = err // Explicitly acknowledge we're ignoring the error
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte("READY")); err != nil {
		// Log error if we have a logger available
		// For now, we silently ignore since this is rare and HTTP connection may be broken
		_ = err // Explicitly acknowledge we're ignoring the error
	}
}

// HandleMetrics provides Prometheus metrics endpoint
func (h *HTTPHealthHandler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if h.monitor.prometheusExp == nil {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte("Metrics not enabled")); err != nil {
			// Log error if we have a logger available
			// For now, we silently ignore since this is rare and HTTP connection may be broken
			_ = err
		}
		return
	}

	config := DefaultPrometheusConfig()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if err := h.monitor.prometheusExp.WriteMetrics(w, config); err != nil {
		// If metrics writing fails, send an error response
		w.WriteHeader(http.StatusInternalServerError)
		if _, writeErr := w.Write([]byte("Failed to write metrics")); writeErr != nil {
			// Log error if we have a logger available
			// For now, we silently ignore since this is rare and HTTP connection may be broken
			_ = writeErr
		}
	}
}

// RegisterRoutes registers health check routes with an HTTP mux
func (h *HTTPHealthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/health/live", h.HandleLiveness)
	mux.HandleFunc("/health/ready", h.HandleReadiness)
	mux.HandleFunc("/metrics", h.HandleMetrics)
}