package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

// AlertSeverity represents the severity level of an alert (reuses existing ErrorSeverity)
type AlertSeverity = ErrorSeverity

// AlertCategory represents the category of an alert
type AlertCategory string

const (
	CategorySecurity    AlertCategory = "security"
	CategoryPerformance AlertCategory = "performance"
	CategoryHealth      AlertCategory = "health"
	CategorySystem      AlertCategory = "system"
)

// Alert represents a monitoring alert
type Alert struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    AlertSeverity          `json:"severity"`
	Category    AlertCategory          `json:"category"`
	Timestamp   time.Time              `json:"timestamp"`
	Labels      map[string]string      `json:"labels"`
	Metadata    map[string]interface{} `json:"metadata"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

// AlertRule defines when to trigger an alert
type AlertRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Category         AlertCategory          `json:"category"`
	Severity         AlertSeverity          `json:"severity"`
	Condition        string                 `json:"condition"`        // Human-readable condition
	CheckFunc        func() (bool, string)  `json:"-"`               // Function to check condition
	Cooldown         time.Duration          `json:"cooldown"`        // Minimum time between alerts
	Labels           map[string]string      `json:"labels"`
	Metadata         map[string]interface{} `json:"metadata"`
	Enabled          bool                   `json:"enabled"`
	LastTriggered    *time.Time             `json:"last_triggered,omitempty"`
	TriggerCount     int64                  `json:"trigger_count"`
	AutoResolve      bool                   `json:"auto_resolve"`      // Auto-resolve when condition is false
	AutoResolveAfter time.Duration          `json:"auto_resolve_after"` // Auto-resolve after duration
}

// NotificationChannel defines how to send alerts
type NotificationChannel struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"` // "webhook", "email", "log"
	Config   map[string]interface{} `json:"config"`
	Enabled  bool                   `json:"enabled"`
	SendFunc func(Alert) error      `json:"-"`
}

// AlertingConfig configures the alerting system
type AlertingConfig struct {
	Enabled                bool                   `json:"enabled"`
	CheckInterval          time.Duration          `json:"check_interval"`
	MaxConcurrentChecks    int                    `json:"max_concurrent_checks"`
	AlertRetention         time.Duration          `json:"alert_retention"`
	DefaultCooldown        time.Duration          `json:"default_cooldown"`
	NotificationTimeout    time.Duration          `json:"notification_timeout"`
	GlobalLabels           map[string]string      `json:"global_labels"`
	SeverityFilters        []AlertSeverity        `json:"severity_filters"`
	CategoryFilters        []AlertCategory        `json:"category_filters"`
	NotificationChannels   []NotificationChannel  `json:"notification_channels"`
	Rules                  []AlertRule            `json:"rules"`
	WebhookConfig          *WebhookConfig         `json:"webhook_config,omitempty"`
	EmailConfig            *EmailConfig           `json:"email_config,omitempty"`
}

// WebhookConfig configures webhook notifications
type WebhookConfig struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers"`
	Timeout         time.Duration     `json:"timeout"`
	RetryAttempts   int               `json:"retry_attempts"`
	RetryInterval   time.Duration     `json:"retry_interval"`
	TLSVerify       bool              `json:"tls_verify"`
	BasicAuth       *BasicAuthConfig  `json:"basic_auth,omitempty"`
}

// EmailConfig configures email notifications
type EmailConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	From         string   `json:"from"`
	To           []string `json:"to"`
	Subject      string   `json:"subject"`
	UseTLS       bool     `json:"use_tls"`
	UseStartTLS  bool     `json:"use_starttls"`
}

// BasicAuthConfig for webhook authentication
type BasicAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AlertManager manages the alerting system
type AlertManager struct {
	config          *AlertingConfig
	rules           map[string]*AlertRule
	channels        map[string]*NotificationChannel
	activeAlerts    map[string]*Alert
	alertHistory    []*Alert
	perfMonitor     *PerformanceMonitor
	rateLimiter     *RateLimiter
	healthMonitor   *HealthMonitor
	securityAnalyzer *SecurityAnalyzer
	logger          *slog.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	mu              sync.RWMutex
	checkSemaphore  chan struct{}
	started         bool
}

// DefaultAlertingConfig returns sensible defaults for alerting
func DefaultAlertingConfig() *AlertingConfig {
	return &AlertingConfig{
		Enabled:              true,
		CheckInterval:        30 * time.Second,
		MaxConcurrentChecks:  5,
		AlertRetention:       24 * time.Hour,
		DefaultCooldown:      5 * time.Minute,
		NotificationTimeout:  10 * time.Second,
		GlobalLabels:         make(map[string]string),
		SeverityFilters:      []AlertSeverity{SeverityWarning, SeverityError, SeverityCritical},
		CategoryFilters:      []AlertCategory{CategorySecurity, CategoryPerformance, CategoryHealth, CategorySystem},
		NotificationChannels: []NotificationChannel{},
		Rules:                []AlertRule{},
		// Using DefaultCooldown for all alert types
	}
}

// GetCooldownForCategory returns the appropriate cooldown duration for an alert category
func (ac *AlertingConfig) GetCooldownForCategory(category AlertCategory) time.Duration {
	// Using DefaultCooldown for all categories for now
	return ac.DefaultCooldown
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertingConfig, logger *slog.Logger) *AlertManager {
	if config == nil {
		config = DefaultAlertingConfig()
	}

	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	am := &AlertManager{
		config:         config,
		rules:          make(map[string]*AlertRule),
		channels:       make(map[string]*NotificationChannel),
		activeAlerts:   make(map[string]*Alert),
		alertHistory:   make([]*Alert, 0),
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
		checkSemaphore: make(chan struct{}, config.MaxConcurrentChecks),
	}

	// Initialize rules and channels
	for i := range config.Rules {
		am.rules[config.Rules[i].ID] = &config.Rules[i]
	}

	for i := range config.NotificationChannels {
		channel := &config.NotificationChannels[i]
		am.setupNotificationChannel(channel)
		am.channels[channel.ID] = channel
	}

	return am
}

// SetPerformanceMonitor sets the performance monitor for alerting
func (am *AlertManager) SetPerformanceMonitor(monitor *PerformanceMonitor) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.perfMonitor = monitor
	am.addDefaultPerformanceRules()
}

// SetRateLimiter sets the rate limiter for alerting
func (am *AlertManager) SetRateLimiter(limiter *RateLimiter) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.rateLimiter = limiter
	am.addDefaultSecurityRules()
}

// SetHealthMonitor sets the health monitor for alerting
func (am *AlertManager) SetHealthMonitor(monitor *HealthMonitor) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.healthMonitor = monitor
	am.addDefaultHealthRules()
}

// SetSecurityAnalyzer sets the security analyzer for alerting
func (am *AlertManager) SetSecurityAnalyzer(analyzer *SecurityAnalyzer) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.securityAnalyzer = analyzer
	am.addDefaultSecurityAnalysisRules()
}

// Start begins the alerting system
func (am *AlertManager) Start() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.started {
		return fmt.Errorf("alert manager already started")
	}

	if !am.config.Enabled {
		am.logger.Info("Alert manager disabled in configuration")
		return nil
	}

	am.started = true

	// Start the check loop
	am.wg.Add(1)
	go am.checkLoop()

	// Start cleanup routine
	am.wg.Add(1)
	go am.cleanupLoop()

	am.logger.Info("Alert manager started",
		"check_interval", am.config.CheckInterval,
		"rules_count", len(am.rules),
		"channels_count", len(am.channels))

	return nil
}

// Stop stops the alerting system
func (am *AlertManager) Stop() {
	am.mu.Lock()
	if !am.started {
		am.mu.Unlock()
		return
	}
	am.started = false
	am.mu.Unlock()

	am.cancel()
	am.wg.Wait()

	am.logger.Info("Alert manager stopped")
}

// AddRule adds a new alert rule
func (am *AlertManager) AddRule(rule AlertRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	if rule.CheckFunc == nil {
		return fmt.Errorf("rule check function cannot be nil")
	}

	if rule.Cooldown == 0 {
		rule.Cooldown = am.config.DefaultCooldown
	}

	am.rules[rule.ID] = &rule
	am.logger.Info("Alert rule added", "rule_id", rule.ID, "name", rule.Name)
	return nil
}

// RemoveRule removes an alert rule
func (am *AlertManager) RemoveRule(ruleID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	delete(am.rules, ruleID)
	am.logger.Info("Alert rule removed", "rule_id", ruleID)
}

// AddNotificationChannel adds a new notification channel
func (am *AlertManager) AddNotificationChannel(channel NotificationChannel) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if channel.ID == "" {
		return fmt.Errorf("channel ID cannot be empty")
	}

	am.setupNotificationChannel(&channel)
	am.channels[channel.ID] = &channel
	am.logger.Info("Notification channel added", "channel_id", channel.ID, "type", channel.Type)
	return nil
}

// RemoveNotificationChannel removes a notification channel
func (am *AlertManager) RemoveNotificationChannel(channelID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	delete(am.channels, channelID)
	am.logger.Info("Notification channel removed", "channel_id", channelID)
}

// TriggerAlert manually triggers an alert
func (am *AlertManager) TriggerAlert(alert Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if alert.ID == "" {
		alert.ID = fmt.Sprintf("manual_%d", time.Now().UnixNano())
	}

	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	// Add global labels
	if alert.Labels == nil {
		alert.Labels = make(map[string]string)
	}
	for k, v := range am.config.GlobalLabels {
		alert.Labels[k] = v
	}

	am.processAlert(alert)
}

// GetActiveAlerts returns all active alerts
func (am *AlertManager) GetActiveAlerts() []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	alerts := make([]Alert, 0, len(am.activeAlerts))
	for _, alert := range am.activeAlerts {
		alerts = append(alerts, *alert)
	}

	// Sort by timestamp descending
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})

	return alerts
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}

	alerts := make([]Alert, limit)
	for i := 0; i < limit; i++ {
		alerts[i] = *am.alertHistory[len(am.alertHistory)-1-i]
	}

	return alerts
}

// ResolveAlert resolves an active alert
func (am *AlertManager) ResolveAlert(alertID string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return false
	}

	now := time.Now()
	alert.Resolved = true
	alert.ResolvedAt = &now

	// Move to history
	am.alertHistory = append(am.alertHistory, alert)
	delete(am.activeAlerts, alertID)

	am.logger.Info("Alert resolved", "alert_id", alertID, "title", alert.Title)
	return true
}

// checkLoop runs the main alert checking loop
func (am *AlertManager) checkLoop() {
	defer am.wg.Done()

	ticker := time.NewTicker(am.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.checkAllRules()
		}
	}
}

// checkAllRules checks all enabled rules
func (am *AlertManager) checkAllRules() {
	am.mu.RLock()
	rules := make([]*AlertRule, 0, len(am.rules))
	for _, rule := range am.rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	am.mu.RUnlock()

	for _, rule := range rules {
		select {
		case am.checkSemaphore <- struct{}{}:
			go am.checkRule(rule)
		case <-am.ctx.Done():
			return
		default:
			// Semaphore full, skip this check
			am.logger.Warn("Skipping rule check due to concurrency limit", "rule_id", rule.ID)
		}
	}
}

// checkRule checks a single rule
func (am *AlertManager) checkRule(rule *AlertRule) {
	defer func() { <-am.checkSemaphore }()

	// Check cooldown
	am.mu.RLock()
	if rule.LastTriggered != nil && time.Since(*rule.LastTriggered) < rule.Cooldown {
		am.mu.RUnlock()
		return
	}
	am.mu.RUnlock()

	// Execute check
	triggered, message := rule.CheckFunc()

	if triggered {
		am.mu.Lock()
		now := time.Now()
		rule.LastTriggered = &now
		rule.TriggerCount++

		alert := Alert{
			ID:          fmt.Sprintf("%s_%d", rule.ID, now.UnixNano()),
			Title:       rule.Name,
			Description: message,
			Severity:    rule.Severity,
			Category:    rule.Category,
			Timestamp:   now,
			Labels:      make(map[string]string),
			Metadata:    make(map[string]interface{}),
		}

		// Copy labels and metadata
		for k, v := range rule.Labels {
			alert.Labels[k] = v
		}
		for k, v := range rule.Metadata {
			alert.Metadata[k] = v
		}

		// Add global labels
		for k, v := range am.config.GlobalLabels {
			alert.Labels[k] = v
		}

		alert.Labels["rule_id"] = rule.ID
		alert.Metadata["trigger_count"] = rule.TriggerCount
		alert.Metadata["condition"] = rule.Condition

		am.mu.Unlock()

		am.processAlert(alert)
	} else if rule.AutoResolve {
		// Check for auto-resolution
		am.mu.Lock()
		for _, alert := range am.activeAlerts {
			if alert.Labels["rule_id"] == rule.ID && !alert.Resolved {
				now := time.Now()
				alert.Resolved = true
				alert.ResolvedAt = &now

				// Move to history
				am.alertHistory = append(am.alertHistory, alert)
				delete(am.activeAlerts, alert.ID)

				am.logger.Info("Alert auto-resolved", "alert_id", alert.ID, "rule_id", rule.ID)
				break
			}
		}
		am.mu.Unlock()
	}
}

// processAlert processes a triggered alert
func (am *AlertManager) processAlert(alert Alert) {
	// Check filters
	if !am.shouldSendAlert(alert) {
		return
	}

	am.mu.Lock()
	am.activeAlerts[alert.ID] = &alert
	am.alertHistory = append(am.alertHistory, &alert)
	am.mu.Unlock()

	am.logger.Warn("Alert triggered",
		"alert_id", alert.ID,
		"title", alert.Title,
		"severity", alert.Severity.String(),
		"category", string(alert.Category))

	// Send notifications
	am.sendNotifications(alert)
}

// shouldSendAlert checks if an alert should be sent based on filters
func (am *AlertManager) shouldSendAlert(alert Alert) bool {
	// Check severity filter
	if len(am.config.SeverityFilters) > 0 {
		found := false
		for _, severity := range am.config.SeverityFilters {
			if alert.Severity == severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check category filter
	if len(am.config.CategoryFilters) > 0 {
		found := false
		for _, category := range am.config.CategoryFilters {
			if alert.Category == category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// sendNotifications sends notifications through all enabled channels
func (am *AlertManager) sendNotifications(alert Alert) {
	am.mu.RLock()
	channels := make([]*NotificationChannel, 0, len(am.channels))
	for _, channel := range am.channels {
		if channel.Enabled {
			channels = append(channels, channel)
		}
	}
	am.mu.RUnlock()

	for _, channel := range channels {
		go am.sendNotification(channel, alert)
	}
}

// sendNotification sends a notification through a specific channel
func (am *AlertManager) sendNotification(channel *NotificationChannel, alert Alert) {
	ctx, cancel := context.WithTimeout(am.ctx, am.config.NotificationTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- channel.SendFunc(alert)
	}()

	select {
	case err := <-done:
		if err != nil {
			am.logger.Error("Failed to send notification",
				"channel_id", channel.ID,
				"channel_type", channel.Type,
				"alert_id", alert.ID,
				"error", err)
		} else {
			am.logger.Info("Notification sent",
				"channel_id", channel.ID,
				"channel_type", channel.Type,
				"alert_id", alert.ID)
		}
	case <-ctx.Done():
		am.logger.Error("Notification timeout",
			"channel_id", channel.ID,
			"channel_type", channel.Type,
			"alert_id", alert.ID)
	}
}

// setupNotificationChannel sets up the send function for a notification channel
func (am *AlertManager) setupNotificationChannel(channel *NotificationChannel) {
	switch channel.Type {
	case "webhook":
		channel.SendFunc = am.createWebhookSender(channel)
	case "log":
		channel.SendFunc = am.createLogSender(channel)
	case "email":
		channel.SendFunc = am.createEmailSender(channel)
	default:
		am.logger.Warn("Unknown notification channel type", "type", channel.Type)
		channel.SendFunc = func(Alert) error {
			return fmt.Errorf("unknown channel type: %s", channel.Type)
		}
	}
}

// createWebhookSender creates a webhook notification sender
func (am *AlertManager) createWebhookSender(channel *NotificationChannel) func(Alert) error {
	return func(alert Alert) error {
		payload, err := json.Marshal(alert)
		if err != nil {
			return fmt.Errorf("failed to marshal alert: %w", err)
		}

		url, ok := channel.Config["url"].(string)
		if !ok {
			return fmt.Errorf("webhook URL not configured")
		}

		req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "LDAP-AlertManager/1.0")

		// Add custom headers
		if headers, ok := channel.Config["headers"].(map[string]string); ok {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("webhook request failed: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
		}

		return nil
	}
}

// createLogSender creates a log notification sender
func (am *AlertManager) createLogSender(channel *NotificationChannel) func(Alert) error {
	return func(alert Alert) error {
		level := slog.LevelInfo
		switch alert.Severity {
		case SeverityWarning:
			level = slog.LevelWarn
		case SeverityError, SeverityCritical:
			level = slog.LevelError
		}

		am.logger.Log(context.Background(), level, "ALERT",
			"alert_id", alert.ID,
			"title", alert.Title,
			"description", alert.Description,
			"severity", alert.Severity.String(),
			"category", string(alert.Category),
			"labels", alert.Labels)

		return nil
	}
}

// createEmailSender creates an email notification sender (placeholder)
func (am *AlertManager) createEmailSender(channel *NotificationChannel) func(Alert) error {
	return func(alert Alert) error {
		// Email implementation would go here
		// For now, just log that we would send an email
		am.logger.Info("Would send email notification",
			"alert_id", alert.ID,
			"title", alert.Title,
			"severity", alert.Severity.String())
		return nil
	}
}

// cleanupLoop runs periodic cleanup of old alerts
func (am *AlertManager) cleanupLoop() {
	defer am.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.cleanupOldAlerts()
		}
	}
}

// cleanupOldAlerts removes old alerts from history
func (am *AlertManager) cleanupOldAlerts() {
	am.mu.Lock()
	defer am.mu.Unlock()

	cutoff := time.Now().Add(-am.config.AlertRetention)
	newHistory := make([]*Alert, 0, len(am.alertHistory))

	for _, alert := range am.alertHistory {
		if alert.Timestamp.After(cutoff) {
			newHistory = append(newHistory, alert)
		}
	}

	removed := len(am.alertHistory) - len(newHistory)
	am.alertHistory = newHistory

	if removed > 0 {
		am.logger.Info("Cleaned up old alerts", "removed_count", removed)
	}

	// Auto-resolve old active alerts if configured
	for id, alert := range am.activeAlerts {
		if alert.Timestamp.Before(cutoff) {
			now := time.Now()
			alert.Resolved = true
			alert.ResolvedAt = &now
			delete(am.activeAlerts, id)
			am.logger.Info("Auto-resolved old alert", "alert_id", id)
		}
	}
}

// GetStats returns alerting statistics
func (am *AlertManager) GetStats() AlertingStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := AlertingStats{
		RulesTotal:     int64(len(am.rules)),
		RulesEnabled:   0,
		ChannelsTotal:  int64(len(am.channels)),
		ChannelsActive: 0,
		ActiveAlerts:   int64(len(am.activeAlerts)),
		TotalAlerts:    int64(len(am.alertHistory)),
		AlertsByCategory: make(map[string]int64),
		AlertsBySeverity: make(map[string]int64),
	}

	for _, rule := range am.rules {
		if rule.Enabled {
			stats.RulesEnabled++
		}
	}

	for _, channel := range am.channels {
		if channel.Enabled {
			stats.ChannelsActive++
		}
	}

	for _, alert := range am.alertHistory {
		stats.AlertsByCategory[string(alert.Category)]++
		stats.AlertsBySeverity[alert.Severity.String()]++
	}

	return stats
}

// SetPerformanceConfig sets the performance configuration for threshold-based alerts
func (am *AlertManager) SetPerformanceConfig(config *PerformanceConfig) {
	// Note: PerformanceConfig is set via performance monitor
	_ = config
}

// Note: SetPerformanceMonitor method already defined above

// AlertingStats represents alerting system statistics
type AlertingStats struct {
	RulesTotal       int64            `json:"rules_total"`
	RulesEnabled     int64            `json:"rules_enabled"`
	ChannelsTotal    int64            `json:"channels_total"`
	ChannelsActive   int64            `json:"channels_active"`
	ActiveAlerts     int64            `json:"active_alerts"`
	TotalAlerts      int64            `json:"total_alerts"`
	AlertsByCategory map[string]int64 `json:"alerts_by_category"`
	AlertsBySeverity map[string]int64 `json:"alerts_by_severity"`
}