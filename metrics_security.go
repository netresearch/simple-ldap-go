package ldap

import (
	"crypto/md5"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// SecurityMetrics provides comprehensive security monitoring and analytics
type SecurityMetrics struct {
	// Authentication patterns
	AuthSuccessTotal         int64 // Total successful authentications
	AuthFailureTotal         int64 // Total failed authentications
	AuthAttemptsByHour       map[int]int64 // Attempts by hour of day
	AuthFailuresByUser       map[string]int64 // Failed attempts by user
	AuthFailuresByIP         map[string]int64 // Failed attempts by IP

	// Suspicious activity detection
	BruteForceAttempts       int64 // Detected brute force attempts
	SuspiciousIPPatterns     int64 // IPs with suspicious behavior
	CredentialStuffingEvents int64 // Potential credential stuffing
	AnomalousUserBehavior    int64 // Users with anomalous patterns

	// Geographic and temporal analysis
	UnusualLocationLogins    int64 // Logins from unusual locations
	OffHourAuthentications   int64 // Authentications outside normal hours
	WeekendActivity          int64 // Weekend authentication activity

	// Account security
	AccountLockouts          int64 // Total account lockouts
	PasswordChangeRequests   int64 // Password change attempts
	PrivilegedAccountAccess  int64 // Access to privileged accounts

	// System security
	UnauthorizedOperations   int64 // Unauthorized operation attempts
	EscalationAttempts       int64 // Privilege escalation attempts
	DataExfiltrationWarnings int64 // Potential data exfiltration

	// Performance impact of security
	SecurityOverheadMs       float64 // Average security check overhead
	RateLimitingActive       bool    // Whether rate limiting is active
	LastSecurityScan         time.Time // Last security analysis run

	// Alert statistics
	SecurityAlertsTriggered  int64 // Total security alerts
	HighSeverityAlerts       int64 // High severity security alerts
	AlertResolutionTimeMs    float64 // Average alert resolution time
}

// SecurityAnalyzer provides advanced security analytics and threat detection
type SecurityAnalyzer struct {
	perfMonitor     *PerformanceMonitor
	rateLimiter     *RateLimiter
	logger          *slog.Logger

	// Security metrics storage
	metrics         SecurityMetrics
	metricsMu       sync.RWMutex

	// Behavioral analysis
	userPatterns    map[string]*UserBehaviorPattern
	ipPatterns      map[string]*IPBehaviorPattern
	patternsMu      sync.RWMutex

	// Alert configuration
	alertThresholds *SecurityThresholds
	alertCallbacks  []SecurityAlertCallback

	// Analysis configuration
	config          *SecurityAnalysisConfig

	// Background processing
	stopChan        chan struct{}
	wg              sync.WaitGroup
}

// UserBehaviorPattern tracks individual user behavior for anomaly detection
type UserBehaviorPattern struct {
	Username           string
	FirstSeen          time.Time
	LastSeen           time.Time
	TotalLogins        int64
	FailedLogins       int64
	SuccessfulLogins   int64

	// Temporal patterns
	LoginHours         map[int]int64 // Hour of day login frequency
	LoginDays          map[time.Weekday]int64 // Day of week patterns

	// Geographic patterns
	LoginIPs           map[string]int64 // IP addresses used
	Countries          map[string]int64 // Countries (if geo data available)

	// Security flags
	HasSuspiciousActivity bool
	RiskScore            float64 // 0-1 risk score
	LastRiskUpdate       time.Time
}

// IPBehaviorPattern tracks IP address behavior for threat detection
type IPBehaviorPattern struct {
	IPAddress          string
	FirstSeen          time.Time
	LastSeen           time.Time

	// Activity metrics
	TotalRequests      int64
	SuccessfulAuths    int64
	FailedAuths        int64
	UniqueUsers        map[string]bool

	// Pattern analysis
	RequestsPerHour    map[int]int64 // Hourly request distribution
	BurstActivity      int64         // High-frequency request periods

	// Security classification
	ThreatLevel        string // "low", "medium", "high", "critical"
	IsWhitelisted      bool
	IsBlacklisted      bool
	RiskScore          float64
}

// SecurityThresholds defines thresholds for security alerts
type SecurityThresholds struct {
	MaxFailedLoginsPerUser   int64         `json:"max_failed_logins_per_user"`
	MaxFailedLoginsPerIP     int64         `json:"max_failed_logins_per_ip"`
	BruteForceWindowMinutes  int           `json:"brute_force_window_minutes"`
	AnomalyDetectionEnabled  bool          `json:"anomaly_detection_enabled"`
	GeographicAnomalyEnabled bool          `json:"geographic_anomaly_enabled"`
	OffHoursThresholdPercent float64       `json:"off_hours_threshold_percent"`
	MaxRiskScore             float64       `json:"max_risk_score"`
}

// SecurityAlertCallback is called when a security alert is triggered
type SecurityAlertCallback func(alert SecurityAlert)

// SecurityAlert represents a security event requiring attention
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"` // "low", "medium", "high", "critical"
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"` // IP, username, etc.
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
	Actions     []string               `json:"recommended_actions"`
}

// SecurityAnalysisConfig configures security analysis behavior
type SecurityAnalysisConfig struct {
	AnalysisInterval     time.Duration `json:"analysis_interval"`
	RetentionPeriod      time.Duration `json:"retention_period"`
	EnableBehaviorAnalysis bool        `json:"enable_behavior_analysis"`
	EnableThreatIntel    bool          `json:"enable_threat_intel"`
	EnableGeolocation    bool          `json:"enable_geolocation"`
	RiskScoringEnabled   bool          `json:"risk_scoring_enabled"`
}

// DefaultSecurityThresholds returns secure default thresholds
func DefaultSecurityThresholds() *SecurityThresholds {
	return &SecurityThresholds{
		MaxFailedLoginsPerUser:   5,
		MaxFailedLoginsPerIP:     20,
		BruteForceWindowMinutes:  15,
		AnomalyDetectionEnabled:  true,
		GeographicAnomalyEnabled: false, // Requires geo IP database
		OffHoursThresholdPercent: 10.0,  // 10% threshold for off-hours activity
		MaxRiskScore:             0.8,   // Alert on risk scores above 80%
	}
}

// DefaultSecurityAnalysisConfig returns default analysis configuration
func DefaultSecurityAnalysisConfig() *SecurityAnalysisConfig {
	return &SecurityAnalysisConfig{
		AnalysisInterval:       5 * time.Minute,
		RetentionPeriod:        30 * 24 * time.Hour, // 30 days
		EnableBehaviorAnalysis: true,
		EnableThreatIntel:      false, // Requires external service
		EnableGeolocation:      false, // Requires geo IP database
		RiskScoringEnabled:     true,
	}
}

// NewSecurityAnalyzer creates a new security analytics system
func NewSecurityAnalyzer(logger *slog.Logger, config *SecurityAnalysisConfig) *SecurityAnalyzer {
	if config == nil {
		config = DefaultSecurityAnalysisConfig()
	}

	if logger == nil {
		logger = slog.Default()
	}

	analyzer := &SecurityAnalyzer{
		logger:          logger.With(slog.String("component", "security_analyzer")),
		userPatterns:    make(map[string]*UserBehaviorPattern),
		ipPatterns:      make(map[string]*IPBehaviorPattern),
		alertThresholds: DefaultSecurityThresholds(),
		alertCallbacks:  make([]SecurityAlertCallback, 0),
		config:          config,
		stopChan:        make(chan struct{}),
	}

	// Start background analysis
	analyzer.startBackgroundAnalysis()

	return analyzer
}

// SetPerformanceMonitor sets the performance monitor for security integration
func (sa *SecurityAnalyzer) SetPerformanceMonitor(monitor *PerformanceMonitor) {
	sa.perfMonitor = monitor
}

// SetRateLimiter sets the rate limiter for security integration
func (sa *SecurityAnalyzer) SetRateLimiter(limiter *RateLimiter) {
	sa.rateLimiter = limiter
}

// SetAlertThresholds updates security alert thresholds
func (sa *SecurityAnalyzer) SetAlertThresholds(thresholds *SecurityThresholds) {
	sa.alertThresholds = thresholds
}

// AddAlertCallback adds a callback for security alerts
func (sa *SecurityAnalyzer) AddAlertCallback(callback SecurityAlertCallback) {
	sa.alertCallbacks = append(sa.alertCallbacks, callback)
}

// RecordAuthenticationAttempt records authentication events for security analysis
func (sa *SecurityAnalyzer) RecordAuthenticationAttempt(username, ipAddress string, success bool, timestamp time.Time) {
	// Update basic metrics
	sa.metricsMu.Lock()
	if success {
		atomic.AddInt64(&sa.metrics.AuthSuccessTotal, 1)
	} else {
		atomic.AddInt64(&sa.metrics.AuthFailureTotal, 1)
	}

	// Track hourly patterns
	hour := timestamp.Hour()
	if sa.metrics.AuthAttemptsByHour == nil {
		sa.metrics.AuthAttemptsByHour = make(map[int]int64)
	}
	sa.metrics.AuthAttemptsByHour[hour]++

	// Track failures by user and IP
	if !success {
		if sa.metrics.AuthFailuresByUser == nil {
			sa.metrics.AuthFailuresByUser = make(map[string]int64)
		}
		if sa.metrics.AuthFailuresByIP == nil {
			sa.metrics.AuthFailuresByIP = make(map[string]int64)
		}
		sa.metrics.AuthFailuresByUser[username]++
		sa.metrics.AuthFailuresByIP[ipAddress]++
	}
	sa.metricsMu.Unlock()

	// Update behavioral patterns
	sa.updateUserPattern(username, ipAddress, success, timestamp)
	sa.updateIPPattern(ipAddress, username, success, timestamp)

	// Check for immediate security threats
	sa.checkImmediateThreats(username, ipAddress, success, timestamp)
}

// updateUserPattern updates user behavior patterns
func (sa *SecurityAnalyzer) updateUserPattern(username, ipAddress string, success bool, timestamp time.Time) {
	sa.patternsMu.Lock()
	defer sa.patternsMu.Unlock()

	pattern, exists := sa.userPatterns[username]
	if !exists {
		pattern = &UserBehaviorPattern{
			Username:     username,
			FirstSeen:    timestamp,
			LoginHours:   make(map[int]int64),
			LoginDays:    make(map[time.Weekday]int64),
			LoginIPs:     make(map[string]int64),
			Countries:    make(map[string]int64),
		}
		sa.userPatterns[username] = pattern
	}

	pattern.LastSeen = timestamp
	pattern.TotalLogins++
	pattern.LoginIPs[ipAddress]++
	pattern.LoginHours[timestamp.Hour()]++
	pattern.LoginDays[timestamp.Weekday()]++

	if success {
		pattern.SuccessfulLogins++
	} else {
		pattern.FailedLogins++
	}
}

// updateIPPattern updates IP behavior patterns
func (sa *SecurityAnalyzer) updateIPPattern(ipAddress, username string, success bool, timestamp time.Time) {
	sa.patternsMu.Lock()
	defer sa.patternsMu.Unlock()

	pattern, exists := sa.ipPatterns[ipAddress]
	if !exists {
		pattern = &IPBehaviorPattern{
			IPAddress:       ipAddress,
			FirstSeen:       timestamp,
			UniqueUsers:     make(map[string]bool),
			RequestsPerHour: make(map[int]int64),
			ThreatLevel:     "low",
		}
		sa.ipPatterns[ipAddress] = pattern
	}

	pattern.LastSeen = timestamp
	pattern.TotalRequests++
	pattern.UniqueUsers[username] = true
	pattern.RequestsPerHour[timestamp.Hour()]++

	if success {
		pattern.SuccessfulAuths++
	} else {
		pattern.FailedAuths++
	}
}

// checkImmediateThreats checks for immediate security threats requiring alerts
func (sa *SecurityAnalyzer) checkImmediateThreats(username, ipAddress string, success bool, timestamp time.Time) {
	if !success {
		// Check for brute force against user
		sa.metricsMu.RLock()
		userFailures := sa.metrics.AuthFailuresByUser[username]
		sa.metricsMu.RUnlock()
		if userFailures >= sa.alertThresholds.MaxFailedLoginsPerUser {
			sa.triggerAlert(SecurityAlert{
				ID:          sa.generateAlertID("brute_force_user", username),
				Type:        "brute_force",
				Severity:    "high",
				Title:       "Brute Force Attack Detected",
				Description: fmt.Sprintf("User %s has %d failed login attempts", username, userFailures),
				Source:      username,
				Timestamp:   timestamp,
				Details: map[string]interface{}{
					"username":       username,
					"failed_attempts": userFailures,
					"source_ip":      ipAddress,
				},
				Actions: []string{
					"Lock user account",
					"Notify user of suspicious activity",
					"Review authentication logs",
				},
			})
		}

		// Check for brute force from IP
		sa.metricsMu.RLock()
		ipFailures := sa.metrics.AuthFailuresByIP[ipAddress]
		sa.metricsMu.RUnlock()
		if ipFailures >= sa.alertThresholds.MaxFailedLoginsPerIP {
			sa.triggerAlert(SecurityAlert{
				ID:          sa.generateAlertID("brute_force_ip", ipAddress),
				Type:        "brute_force",
				Severity:    "medium",
				Title:       "IP Brute Force Attack Detected",
				Description: fmt.Sprintf("IP %s has %d failed login attempts", ipAddress, ipFailures),
				Source:      ipAddress,
				Timestamp:   timestamp,
				Details: map[string]interface{}{
					"source_ip":      ipAddress,
					"failed_attempts": ipFailures,
					"target_user":    username,
				},
				Actions: []string{
					"Block IP address",
					"Investigate source",
					"Review related authentication attempts",
				},
			})
		}
	}
}

// GetSecurityMetrics returns current security metrics
func (sa *SecurityAnalyzer) GetSecurityMetrics() SecurityMetrics {
	sa.metricsMu.RLock()
	defer sa.metricsMu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := sa.metrics

	// Add computed metrics
	if sa.rateLimiter != nil {
		rateLimiterMetrics := sa.rateLimiter.GetMetrics()
		metrics.AccountLockouts = rateLimiterMetrics.ActiveLockouts
		metrics.BruteForceAttempts = rateLimiterMetrics.ViolationEvents
		metrics.RateLimitingActive = true
	}

	metrics.LastSecurityScan = time.Now()

	return metrics
}

// AnalyzeBehaviorPatterns performs comprehensive behavior analysis
func (sa *SecurityAnalyzer) AnalyzeBehaviorPatterns() {
	if !sa.config.EnableBehaviorAnalysis {
		return
	}

	sa.patternsMu.Lock()
	defer sa.patternsMu.Unlock()

	now := time.Now()

	// Analyze user patterns
	for username, pattern := range sa.userPatterns {
		riskScore := sa.calculateUserRiskScore(pattern, now)
		pattern.RiskScore = riskScore
		pattern.LastRiskUpdate = now

		if riskScore > sa.alertThresholds.MaxRiskScore {
			sa.triggerAlert(SecurityAlert{
				ID:          sa.generateAlertID("high_risk_user", username),
				Type:        "behavioral_anomaly",
				Severity:    "medium",
				Title:       "High Risk User Behavior",
				Description: fmt.Sprintf("User %s has high risk score: %.2f", username, riskScore),
				Source:      username,
				Timestamp:   now,
				Details: map[string]interface{}{
					"username":        username,
					"risk_score":      riskScore,
					"total_logins":    pattern.TotalLogins,
					"failed_logins":   pattern.FailedLogins,
					"unique_ips":      len(pattern.LoginIPs),
				},
				Actions: []string{
					"Review user activity",
					"Require additional authentication",
					"Monitor future activity",
				},
			})
		}
	}

	// Analyze IP patterns
	for _, pattern := range sa.ipPatterns {
		sa.analyzeIPThreatLevel(pattern, now)
	}
}

// calculateUserRiskScore calculates a risk score for user behavior
func (sa *SecurityAnalyzer) calculateUserRiskScore(pattern *UserBehaviorPattern, now time.Time) float64 {
	var riskScore float64

	// Failed login ratio
	if pattern.TotalLogins > 0 {
		failureRate := float64(pattern.FailedLogins) / float64(pattern.TotalLogins)
		riskScore += failureRate * 0.4 // 40% weight
	}

	// Unusual IP count
	if len(pattern.LoginIPs) > 10 {
		ipRisk := float64(len(pattern.LoginIPs)-10) / 100.0
		if ipRisk > 0.3 {
			ipRisk = 0.3 // Cap at 30%
		}
		riskScore += ipRisk
	}

	// Temporal anomalies (logins outside normal hours)
	offHoursLogins := int64(0)
	for hour, count := range pattern.LoginHours {
		if hour < 6 || hour > 22 { // Consider 6 AM to 10 PM as normal hours
			offHoursLogins += count
		}
	}

	if pattern.TotalLogins > 0 {
		offHoursRatio := float64(offHoursLogins) / float64(pattern.TotalLogins)
		if offHoursRatio > sa.alertThresholds.OffHoursThresholdPercent/100.0 {
			riskScore += offHoursRatio * 0.2 // 20% weight
		}
	}

	// Account age factor (newer accounts are slightly riskier)
	accountAge := now.Sub(pattern.FirstSeen)
	if accountAge < 24*time.Hour {
		riskScore += 0.1 // 10% for very new accounts
	}

	// Cap risk score at 1.0
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}

// analyzeIPThreatLevel analyzes and updates IP threat levels
func (sa *SecurityAnalyzer) analyzeIPThreatLevel(pattern *IPBehaviorPattern, now time.Time) {
	// Calculate threat level based on various factors
	var threatScore float64

	// Failed authentication ratio
	if pattern.TotalRequests > 0 {
		failureRate := float64(pattern.FailedAuths) / float64(pattern.TotalRequests)
		threatScore += failureRate * 0.5 // 50% weight
	}

	// Request volume
	requestsPerDay := pattern.TotalRequests
	if accountAge := now.Sub(pattern.FirstSeen); accountAge > 0 {
		requestsPerDay = pattern.TotalRequests * int64(24*time.Hour) / int64(accountAge)
	}

	if requestsPerDay > 1000 {
		threatScore += 0.3 // High volume activity
	}

	// User targeting diversity
	uniqueUsers := len(pattern.UniqueUsers)
	if uniqueUsers > 20 {
		threatScore += 0.2 // Targeting many users
	}

	// Update threat level
	if threatScore >= 0.8 {
		pattern.ThreatLevel = "critical"
	} else if threatScore >= 0.6 {
		pattern.ThreatLevel = "high"
	} else if threatScore >= 0.4 {
		pattern.ThreatLevel = "medium"
	} else {
		pattern.ThreatLevel = "low"
	}

	pattern.RiskScore = threatScore
}

// triggerAlert triggers a security alert
func (sa *SecurityAnalyzer) triggerAlert(alert SecurityAlert) {
	atomic.AddInt64(&sa.metrics.SecurityAlertsTriggered, 1)

	if alert.Severity == "high" || alert.Severity == "critical" {
		atomic.AddInt64(&sa.metrics.HighSeverityAlerts, 1)
	}

	sa.logger.Warn("Security alert triggered",
		slog.String("alert_id", alert.ID),
		slog.String("type", alert.Type),
		slog.String("severity", alert.Severity),
		slog.String("source", alert.Source),
		slog.String("title", alert.Title))

	// Call registered callbacks
	for _, callback := range sa.alertCallbacks {
		go func(cb SecurityAlertCallback) {
			defer func() {
				if r := recover(); r != nil {
					sa.logger.Error("Alert callback panic",
						slog.Any("panic", r),
						slog.String("alert_id", alert.ID))
				}
			}()
			cb(alert)
		}(callback)
	}
}

// generateAlertID generates a unique alert ID
func (sa *SecurityAnalyzer) generateAlertID(alertType, source string) string {
	hash := md5.Sum([]byte(fmt.Sprintf("%s:%s:%d", alertType, source, time.Now().UnixNano())))
	return fmt.Sprintf("%s_%x", alertType, hash[:4])
}

// startBackgroundAnalysis starts background security analysis
func (sa *SecurityAnalyzer) startBackgroundAnalysis() {
	sa.wg.Add(1)
	go func() {
		defer sa.wg.Done()
		ticker := time.NewTicker(sa.config.AnalysisInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sa.AnalyzeBehaviorPatterns()
				sa.cleanupOldPatterns()
			case <-sa.stopChan:
				return
			}
		}
	}()
}

// cleanupOldPatterns removes old behavioral patterns
func (sa *SecurityAnalyzer) cleanupOldPatterns() {
	cutoff := time.Now().Add(-sa.config.RetentionPeriod)

	sa.patternsMu.Lock()
	defer sa.patternsMu.Unlock()

	// Clean up user patterns
	for username, pattern := range sa.userPatterns {
		if pattern.LastSeen.Before(cutoff) {
			delete(sa.userPatterns, username)
		}
	}

	// Clean up IP patterns
	for ipAddress, pattern := range sa.ipPatterns {
		if pattern.LastSeen.Before(cutoff) {
			delete(sa.ipPatterns, ipAddress)
		}
	}
}

// Close shuts down the security analyzer
func (sa *SecurityAnalyzer) Close() error {
	close(sa.stopChan)
	sa.wg.Wait()
	return nil
}

// GetSecurityReport generates a comprehensive security report
func (sa *SecurityAnalyzer) GetSecurityReport() map[string]interface{} {
	metrics := sa.GetSecurityMetrics()

	sa.patternsMu.RLock()
	userCount := len(sa.userPatterns)
	ipCount := len(sa.ipPatterns)

	// Calculate risk distribution
	riskDistribution := map[string]int{
		"low":      0,
		"medium":   0,
		"high":     0,
		"critical": 0,
	}

	for _, pattern := range sa.userPatterns {
		if pattern.RiskScore < 0.3 {
			riskDistribution["low"]++
		} else if pattern.RiskScore < 0.6 {
			riskDistribution["medium"]++
		} else if pattern.RiskScore < 0.8 {
			riskDistribution["high"]++
		} else {
			riskDistribution["critical"]++
		}
	}

	// Get top risky users
	type userRisk struct {
		Username  string  `json:"username"`
		RiskScore float64 `json:"risk_score"`
	}

	var riskyUsers []userRisk
	for username, pattern := range sa.userPatterns {
		if pattern.RiskScore > 0.5 {
			riskyUsers = append(riskyUsers, userRisk{
				Username:  username,
				RiskScore: pattern.RiskScore,
			})
		}
	}

	// Sort by risk score
	sort.Slice(riskyUsers, func(i, j int) bool {
		return riskyUsers[i].RiskScore > riskyUsers[j].RiskScore
	})

	// Limit to top 10
	if len(riskyUsers) > 10 {
		riskyUsers = riskyUsers[:10]
	}
	sa.patternsMu.RUnlock()

	return map[string]interface{}{
		"metrics":           metrics,
		"user_patterns":     userCount,
		"ip_patterns":       ipCount,
		"risk_distribution": riskDistribution,
		"top_risky_users":   riskyUsers,
		"analysis_config":   sa.config,
		"alert_thresholds":  sa.alertThresholds,
		"last_analysis":     time.Now(),
	}
}