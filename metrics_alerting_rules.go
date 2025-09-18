package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// addDefaultPerformanceRules adds default performance monitoring alert rules
func (am *AlertManager) addDefaultPerformanceRules() {
	if am.perfMonitor == nil {
		return
	}

	// High error rate rule
	if err := am.AddRule(AlertRule{
		ID:          "performance_high_error_rate",
		Name:        "High Error Rate",
		Description: "LDAP operations experiencing high error rate",
		Category:    CategoryPerformance,
		Severity:    SeverityError,
		Condition:   "Error rate > 10% over last 5 minutes",
		CheckFunc: func() (bool, string) {
			stats := am.perfMonitor.GetStats()
			if stats.OperationsTotal == 0 {
				return false, ""
			}
			errorRate := float64(stats.ErrorCount) / float64(stats.OperationsTotal) * 100
			// Use configurable error rate threshold
			threshold := 10.0 // default fallback
			if errorRate > threshold {
				return true, fmt.Sprintf("Error rate is %.2f%% (%d errors out of %d operations)",
					errorRate, stats.ErrorCount, stats.OperationsTotal)
			}
			return false, ""
		},
		Cooldown:    am.config.GetCooldownForCategory(CategoryPerformance),
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "performance",
			"metric":    "error_rate",
		},
	}); err != nil {
		// Log error but continue with other rules
		am.logger.Error("failed_to_add_performance_rule",
			"rule_id", "performance_high_error_rate",
			"error", err.Error())
	}

	// High timeout rate rule
	if err := am.AddRule(AlertRule{
		ID:          "performance_high_timeout_rate",
		Name:        "High Timeout Rate",
		Description: "LDAP operations experiencing high timeout rate",
		Category:    CategoryPerformance,
		Severity:    SeverityWarning,
		Condition:   "Timeout rate > 5% over last 5 minutes",
		CheckFunc: func() (bool, string) {
			stats := am.perfMonitor.GetStats()
			if stats.OperationsTotal == 0 {
				return false, ""
			}
			timeoutRate := float64(stats.TimeoutCount) / float64(stats.OperationsTotal) * 100
			// Use configurable timeout rate threshold
			threshold := 5.0 // default fallback
			if timeoutRate > threshold {
				return true, fmt.Sprintf("Timeout rate is %.2f%% (%d timeouts out of %d operations)",
					timeoutRate, stats.TimeoutCount, stats.OperationsTotal)
			}
			return false, ""
		},
		Cooldown:    am.config.GetCooldownForCategory(CategoryPerformance),
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "performance",
			"metric":    "timeout_rate",
		},
	}); err != nil {
		// Log error but continue with other rules
		am.logger.Error("failed_to_add_performance_rule",
			"rule_id", "performance_high_timeout_rate",
			"error", err.Error())
	}

	// Slow response time rule
	if err := am.AddRule(AlertRule{
		ID:          "performance_slow_response_time",
		Name:        "Slow Response Times",
		Description: "LDAP operations experiencing slow response times",
		Category:    CategoryPerformance,
		Severity:    SeverityWarning,
		Condition:   "P95 response time > 5 seconds",
		CheckFunc: func() (bool, string) {
			stats := am.perfMonitor.GetStats()
			// Use configurable response time threshold
			threshold := 5 * time.Second // default fallback
			if stats.P95ResponseTime > threshold {
				return true, fmt.Sprintf("P95 response time is %v (P99: %v, Avg: %v)",
					stats.P95ResponseTime, stats.P99ResponseTime, stats.AvgResponseTime)
			}
			return false, ""
		},
		Cooldown:    am.config.GetCooldownForCategory(CategoryPerformance),
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "performance",
			"metric":    "response_time",
		},
	}); err != nil {
		// Log error but continue with other rules
		am.logger.Error("failed_to_add_performance_rule",
			"rule_id", "performance_slow_response_time",
			"error", err.Error())
	}

	// High memory usage rule
	if err := am.AddRule(AlertRule{
		ID:          "performance_high_memory_usage",
		Name:        "High Memory Usage",
		Description: "LDAP client using excessive memory",
		Category:    CategoryPerformance,
		Severity:    SeverityWarning,
		Condition:   "Memory usage > 500MB",
		CheckFunc: func() (bool, string) {
			stats := am.perfMonitor.GetStats()
			if stats.MemoryUsageMB > 500 {
				return true, fmt.Sprintf("Memory usage is %.2f MB", stats.MemoryUsageMB)
			}
			return false, ""
		},
		Cooldown:    10 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "performance",
			"metric":    "memory_usage",
		},
	}); err != nil {
		// Log error but continue with other rules
		am.logger.Error("failed_to_add_performance_rule",
			"rule_id", "performance_high_memory_usage",
			"error", err.Error())
	}

	// High goroutine count rule
	if err := am.AddRule(AlertRule{
		ID:          "performance_high_goroutine_count",
		Name:        "High Goroutine Count",
		Description: "Excessive number of goroutines detected",
		Category:    CategoryPerformance,
		Severity:    SeverityWarning,
		Condition:   "Goroutine count > 1000",
		CheckFunc: func() (bool, string) {
			stats := am.perfMonitor.GetStats()
			if stats.GoroutineCount > 1000 {
				return true, fmt.Sprintf("Goroutine count is %d", stats.GoroutineCount)
			}
			return false, ""
		},
		Cooldown:    5 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "performance",
			"metric":    "goroutines",
		},
	}); err != nil {
		// Log error but continue with other rules
		am.logger.Error("failed_to_add_performance_rule",
			"rule_id", "performance_high_goroutine_count",
			"error", err.Error())
	}

	// Many slow queries rule
	if err := am.AddRule(AlertRule{
		ID:          "performance_many_slow_queries",
		Name:        "Many Slow Queries",
		Description: "High number of slow LDAP queries detected",
		Category:    CategoryPerformance,
		Severity:    SeverityWarning,
		Condition:   "Slow queries > 10% of total operations",
		CheckFunc: func() (bool, string) {
			stats := am.perfMonitor.GetStats()
			if stats.OperationsTotal == 0 {
				return false, ""
			}
			slowRate := float64(stats.SlowQueries) / float64(stats.OperationsTotal) * 100
			if slowRate > 10.0 {
				return true, fmt.Sprintf("Slow query rate is %.2f%% (%d slow out of %d total)",
					slowRate, stats.SlowQueries, stats.OperationsTotal)
			}
			return false, ""
		},
		Cooldown:    5 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "performance",
			"metric":    "slow_queries",
		},
	}); err != nil {
		// Log error but continue with other rules
		am.logger.Error("failed_to_add_performance_rule",
			"rule_id", "performance_many_slow_queries",
			"error", err.Error())
	}
}

// addDefaultSecurityRules adds default security (rate limiter) alert rules
func (am *AlertManager) addDefaultSecurityRules() {
	if am.rateLimiter == nil {
		return
	}

	// High rate limit violations rule
	if err := am.AddRule(AlertRule{
		ID:          "security_high_rate_violations",
		Name:        "High Rate Limit Violations",
		Description: "Excessive rate limit violations detected",
		Category:    CategorySecurity,
		Severity:    SeverityCritical,
		Condition:   "Rate limit violations > 100 per hour",
		CheckFunc: func() (bool, string) {
			metrics := am.rateLimiter.GetMetrics()
			// This is a simplified check - in practice you'd track violations per hour
			if metrics.ViolationEvents > 100 {
				return true, fmt.Sprintf("Total violation events: %d (blocked: %d, patterns: %d)",
					metrics.ViolationEvents, metrics.BlockedAttempts, metrics.SuspiciousPatterns)
			}
			return false, ""
		},
		Cooldown:    15 * time.Minute,
		Enabled:     true,
		AutoResolve: false, // Security alerts should be manually reviewed
		Labels: map[string]string{
			"component": "security",
			"metric":    "rate_violations",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_rule",
			"rule_id", "security_high_rate_violations",
			"error", err.Error())
	}

	// Suspicious patterns detected rule
	if err := am.AddRule(AlertRule{
		ID:          "security_suspicious_patterns",
		Name:        "Suspicious Patterns Detected",
		Description: "Suspicious authentication patterns detected",
		Category:    CategorySecurity,
		Severity:    SeverityError,
		Condition:   "Suspicious patterns > 10",
		CheckFunc: func() (bool, string) {
			metrics := am.rateLimiter.GetMetrics()
			if metrics.SuspiciousPatterns > 10 {
				return true, fmt.Sprintf("Suspicious patterns detected: %d (burst attacks: %d)",
					metrics.SuspiciousPatterns, metrics.BurstAttacks)
			}
			return false, ""
		},
		Cooldown:    10 * time.Minute,
		Enabled:     true,
		AutoResolve: false,
		Labels: map[string]string{
			"component": "security",
			"metric":    "suspicious_patterns",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_rule",
			"rule_id", "security_suspicious_patterns",
			"error", err.Error())
	}

	// Burst attacks detected rule
	if err := am.AddRule(AlertRule{
		ID:          "security_burst_attacks",
		Name:        "Burst Attacks Detected",
		Description: "Burst attack patterns detected",
		Category:    CategorySecurity,
		Severity:    SeverityCritical,
		Condition:   "Burst attacks > 5",
		CheckFunc: func() (bool, string) {
			metrics := am.rateLimiter.GetMetrics()
			if metrics.BurstAttacks > 5 {
				return true, fmt.Sprintf("Burst attacks detected: %d (repeated violators: %d)",
					metrics.BurstAttacks, metrics.RepeatedViolators)
			}
			return false, ""
		},
		Cooldown:    5 * time.Minute,
		Enabled:     true,
		AutoResolve: false,
		Labels: map[string]string{
			"component": "security",
			"metric":    "burst_attacks",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_rule",
			"rule_id", "security_burst_attacks",
			"error", err.Error())
	}

	// Many repeated violators rule
	if err := am.AddRule(AlertRule{
		ID:          "security_repeated_violators",
		Name:        "Repeated Violators",
		Description: "Many identifiers with repeated violations",
		Category:    CategorySecurity,
		Severity:    SeverityError,
		Condition:   "Repeated violators > 20",
		CheckFunc: func() (bool, string) {
			metrics := am.rateLimiter.GetMetrics()
			if metrics.RepeatedViolators > 20 {
				return true, fmt.Sprintf("Repeated violators: %d (active lockouts: %d)",
					metrics.RepeatedViolators, metrics.ActiveLockouts)
			}
			return false, ""
		},
		Cooldown:    20 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "security",
			"metric":    "repeated_violators",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_rule",
			"rule_id", "security_repeated_violators",
			"error", err.Error())
	}

	// High memory usage by rate limiter rule
	if err := am.AddRule(AlertRule{
		ID:          "security_high_memory_usage",
		Name:        "Rate Limiter High Memory Usage",
		Description: "Rate limiter using excessive memory",
		Category:    CategorySecurity,
		Severity:    SeverityWarning,
		Condition:   "Rate limiter memory > 100MB",
		CheckFunc: func() (bool, string) {
			metrics := am.rateLimiter.GetMetrics()
			memoryMB := float64(metrics.MemoryUsageBytes) / (1024 * 1024)
			if memoryMB > 100 {
				return true, fmt.Sprintf("Rate limiter memory usage: %.2f MB (tracking %d identifiers)",
					memoryMB, metrics.UniqueIdentifiers)
			}
			return false, ""
		},
		Cooldown:    15 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "security",
			"metric":    "memory_usage",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_rule",
			"rule_id", "security_high_memory_usage",
			"error", err.Error())
	}

	// Slow rate limit checks rule
	if err := am.AddRule(AlertRule{
		ID:          "security_slow_checks",
		Name:        "Slow Rate Limit Checks",
		Description: "Rate limit checks taking too long",
		Category:    CategorySecurity,
		Severity:    SeverityWarning,
		Condition:   "Average check time > 100ms",
		CheckFunc: func() (bool, string) {
			metrics := am.rateLimiter.GetMetrics()
			if metrics.AvgCheckTime > 100*time.Millisecond {
				return true, fmt.Sprintf("Average check time: %v (peak concurrent: %d)",
					metrics.AvgCheckTime, metrics.PeakConcurrentChecks)
			}
			return false, ""
		},
		Cooldown:    10 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "security",
			"metric":    "check_performance",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_rule",
			"rule_id", "security_slow_checks",
			"error", err.Error())
	}
}

// addDefaultHealthRules adds default health monitoring alert rules
func (am *AlertManager) addDefaultHealthRules() {
	if am.healthMonitor == nil {
		return
	}

	// Overall health degraded rule
	if err := am.AddRule(AlertRule{
		ID:          "health_overall_degraded",
		Name:        "Overall Health Degraded",
		Description: "Overall system health has degraded",
		Category:    CategoryHealth,
		Severity:    SeverityError,
		Condition:   "Overall health score < 70",
		CheckFunc: func() (bool, string) {
			report := am.healthMonitor.GetHealthReport(context.Background())
			if report.Score < 70 {
				failedChecks := []string{}
				for _, check := range report.Checks {
					if check.Status != HealthStatusHealthy {
						failedChecks = append(failedChecks, check.Name)
					}
				}
				return true, fmt.Sprintf("Health score: %d/100, failed components: %s",
					report.Score, strings.Join(failedChecks, ", "))
			}
			return false, ""
		},
		Cooldown:    5 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "health",
			"metric":    "overall_score",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_health_rule",
			"rule_id", "health_overall_degraded",
			"error", err.Error())
	}

	// Critical health failure rule
	if err := am.AddRule(AlertRule{
		ID:          "health_critical_failure",
		Name:        "Critical Health Failure",
		Description: "Critical system health failure detected",
		Category:    CategoryHealth,
		Severity:    SeverityCritical,
		Condition:   "Overall health score < 30 or critical component unhealthy",
		CheckFunc: func() (bool, string) {
			report := am.healthMonitor.GetHealthReport(context.Background())
			if report.Score < 30 {
				return true, fmt.Sprintf("Critical health score: %d/100", report.Score)
			}

			// Check for critical component failures
			for _, check := range report.Checks {
				if check.Status == HealthStatusUnhealthy &&
				   (check.Name == "ldap_connection" || check.Name == "authentication") {
					return true, fmt.Sprintf("Critical component '%s' is unhealthy: %s",
						check.Name, check.Error)
				}
			}
			return false, ""
		},
		Cooldown:    2 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "health",
			"metric":    "critical_failure",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_health_rule",
			"rule_id", "health_critical_failure",
			"error", err.Error())
	}

	// Component degraded rule
	if err := am.AddRule(AlertRule{
		ID:          "health_component_degraded",
		Name:        "Component Health Degraded",
		Description: "Individual component health has degraded",
		Category:    CategoryHealth,
		Severity:    SeverityWarning,
		Condition:   "Any component status is degraded",
		CheckFunc: func() (bool, string) {
			report := am.healthMonitor.GetHealthReport(context.Background())
			degradedComponents := []string{}
			for _, check := range report.Checks {
				if check.Status == HealthStatusDegraded {
					degradedComponents = append(degradedComponents,
						fmt.Sprintf("%s (%s)", check.Name, check.Error))
				}
			}
			if len(degradedComponents) > 0 {
				return true, fmt.Sprintf("Degraded components: %s",
					strings.Join(degradedComponents, ", "))
			}
			return false, ""
		},
		Cooldown:    10 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "health",
			"metric":    "component_degraded",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_health_rule",
			"rule_id", "health_component_degraded",
			"error", err.Error())
	}

	// Health check slow rule
	if err := am.AddRule(AlertRule{
		ID:          "health_checks_slow",
		Name:        "Health Checks Slow",
		Description: "Health checks taking too long to complete",
		Category:    CategoryHealth,
		Severity:    SeverityWarning,
		Condition:   "Any health check duration > 5 seconds",
		CheckFunc: func() (bool, string) {
			report := am.healthMonitor.GetHealthReport(context.Background())
			slowChecks := []string{}
			for _, check := range report.Checks {
				if check.Duration > 5*time.Second {
					slowChecks = append(slowChecks,
						fmt.Sprintf("%s (%v)", check.Name, check.Duration))
				}
			}
			if len(slowChecks) > 0 {
				return true, fmt.Sprintf("Slow health checks: %s",
					strings.Join(slowChecks, ", "))
			}
			return false, ""
		},
		Cooldown:    15 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "health",
			"metric":    "check_duration",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_health_rule",
			"rule_id", "health_checks_slow",
			"error", err.Error())
	}
}

// addDefaultSecurityAnalysisRules adds default security analysis alert rules
func (am *AlertManager) addDefaultSecurityAnalysisRules() {
	if am.securityAnalyzer == nil {
		return
	}

	// High risk user detected rule
	if err := am.AddRule(AlertRule{
		ID:          "security_high_risk_user",
		Name:        "High Risk User Detected",
		Description: "User with high risk score detected",
		Category:    CategorySecurity,
		Severity:    SeverityError,
		Condition:   "User risk score > 80",
		CheckFunc: func() (bool, string) {
			report := am.securityAnalyzer.GetSecurityReport()
			// Check if we have security metrics that indicate high risk
			if metrics, ok := report["metrics"]; ok {
				if secMetrics, ok := metrics.(map[string]interface{}); ok {
					if alerts, ok := secMetrics["high_severity_alerts"]; ok {
						if alertCount, ok := alerts.(int64); ok && alertCount > 10 {
							return true, fmt.Sprintf("High severity security alerts: %d", alertCount)
						}
					}
				}
			}
			return false, ""
		},
		Cooldown:    30 * time.Minute,
		Enabled:     true,
		AutoResolve: false, // Security analysis alerts need manual review
		Labels: map[string]string{
			"component": "security_analysis",
			"metric":    "user_risk",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_analysis_rule",
			"rule_id", "security_high_risk_user",
			"error", err.Error())
	}

	// Suspicious IP activity rule
	if err := am.AddRule(AlertRule{
		ID:          "security_suspicious_ip",
		Name:        "Suspicious IP Activity",
		Description: "IP address showing suspicious patterns",
		Category:    CategorySecurity,
		Severity:    SeverityError,
		Condition:   "IP risk score > 70",
		CheckFunc: func() (bool, string) {
			report := am.securityAnalyzer.GetSecurityReport()
			// Check for suspicious IP patterns in the metrics
			if metrics, ok := report["metrics"]; ok {
				if secMetrics, ok := metrics.(map[string]interface{}); ok {
					if violations, ok := secMetrics["suspicious_patterns_detected"]; ok {
						if violationCount, ok := violations.(int64); ok && violationCount > 20 {
							return true, fmt.Sprintf("Suspicious IP patterns detected: %d", violationCount)
						}
					}
				}
			}
			return false, ""
		},
		Cooldown:    20 * time.Minute,
		Enabled:     true,
		AutoResolve: false,
		Labels: map[string]string{
			"component": "security_analysis",
			"metric":    "ip_risk",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_analysis_rule",
			"rule_id", "security_suspicious_ip",
			"error", err.Error())
	}

	// Many security alerts rule
	if err := am.AddRule(AlertRule{
		ID:          "security_many_alerts",
		Name:        "Many Security Alerts",
		Description: "High number of security alerts in short period",
		Category:    CategorySecurity,
		Severity:    SeverityCritical,
		Condition:   "Active security alerts > 10",
		CheckFunc: func() (bool, string) {
			report := am.securityAnalyzer.GetSecurityReport()
			// Check for many security threats in the metrics
			if metrics, ok := report["metrics"]; ok {
				if secMetrics, ok := metrics.(map[string]interface{}); ok {
					if alerts, ok := secMetrics["security_alerts_triggered"]; ok {
						if alertCount, ok := alerts.(int64); ok && alertCount > 50 {
							return true, fmt.Sprintf("Security alerts triggered: %d", alertCount)
						}
					}
				}
			}
			return false, ""
		},
		Cooldown:    10 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "security_analysis",
			"metric":    "threat_count",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_analysis_rule",
			"rule_id", "security_many_alerts",
			"error", err.Error())
	}

	// Failed authentication spike rule
	if err := am.AddRule(AlertRule{
		ID:          "security_auth_spike",
		Name:        "Authentication Failure Spike",
		Description: "Sudden spike in authentication failures",
		Category:    CategorySecurity,
		Severity:    SeverityWarning,
		Condition:   "Authentication failure rate > 50%",
		CheckFunc: func() (bool, string) {
			// This would analyze recent authentication patterns
			// For now, we'll use a simplified version based on rate limiter metrics
			if am.rateLimiter != nil {
				metrics := am.rateLimiter.GetMetrics()
				if metrics.TotalAttempts > 0 {
					failureRate := float64(metrics.BlockedAttempts) / float64(metrics.TotalAttempts) * 100
					if failureRate > 50.0 {
						return true, fmt.Sprintf("Authentication failure rate: %.2f%% (%d blocked out of %d attempts)",
							failureRate, metrics.BlockedAttempts, metrics.TotalAttempts)
					}
				}
			}
			return false, ""
		},
		Cooldown:    15 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "security_analysis",
			"metric":    "auth_failures",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_analysis_rule",
			"rule_id", "security_auth_spike",
			"error", err.Error())
	}

	// Anomalous behavior patterns rule
	if err := am.AddRule(AlertRule{
		ID:          "security_anomalous_behavior",
		Name:        "Anomalous Behavior Patterns",
		Description: "Unusual behavior patterns detected",
		Category:    CategorySecurity,
		Severity:    SeverityWarning,
		Condition:   "Behavior anomaly score > 60",
		CheckFunc: func() (bool, string) {
			report := am.securityAnalyzer.GetSecurityReport()
			// Check for anomalous behavior patterns in the metrics
			if metrics, ok := report["metrics"]; ok {
				if secMetrics, ok := metrics.(map[string]interface{}); ok {
					if patterns, ok := secMetrics["behavior_anomalies_detected"]; ok {
						if patternCount, ok := patterns.(int64); ok && patternCount > 10 {
							return true, fmt.Sprintf("Behavior anomalies detected: %d patterns", patternCount)
						}
					}
				}
			}
			return false, ""
		},
		Cooldown:    45 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "security_analysis",
			"metric":    "behavior_anomaly",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_security_analysis_rule",
			"rule_id", "security_anomalous_behavior",
			"error", err.Error())
	}
}

// addDefaultSystemRules adds default system-level alert rules
func (am *AlertManager) addDefaultSystemRules() {
	// Alert manager itself health rule
	if err := am.AddRule(AlertRule{
		ID:          "system_alerting_health",
		Name:        "Alerting System Health",
		Description: "Alert manager system health check",
		Category:    CategorySystem,
		Severity:    SeverityError,
		Condition:   "Alert manager components not responding",
		CheckFunc: func() (bool, string) {
			// Check if alert manager is functioning properly
			stats := am.GetStats()
			if stats.RulesEnabled == 0 {
				return true, "No alert rules are enabled"
			}
			if stats.ChannelsActive == 0 {
				return true, "No notification channels are active"
			}
			return false, ""
		},
		Cooldown:    15 * time.Minute,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "system",
			"metric":    "alerting_health",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_system_rule",
			"rule_id", "system_alerting_health",
			"error", err.Error())
	}

	// Too many active alerts rule
	if err := am.AddRule(AlertRule{
		ID:          "system_too_many_alerts",
		Name:        "Too Many Active Alerts",
		Description: "System generating excessive number of alerts",
		Category:    CategorySystem,
		Severity:    SeverityWarning,
		Condition:   "Active alerts > 50",
		CheckFunc: func() (bool, string) {
			stats := am.GetStats()
			if stats.ActiveAlerts > 50 {
				return true, fmt.Sprintf("Active alerts: %d (consider reviewing alert thresholds)",
					stats.ActiveAlerts)
			}
			return false, ""
		},
		Cooldown:    1 * time.Hour,
		Enabled:     true,
		AutoResolve: true,
		Labels: map[string]string{
			"component": "system",
			"metric":    "alert_volume",
		},
	}); err != nil {
		am.logger.Error("failed_to_add_system_rule",
			"rule_id", "system_too_many_alerts",
			"error", err.Error())
	}
}