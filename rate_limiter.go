package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// RateLimiterConfig configures the rate limiting behavior
type RateLimiterConfig struct {
	// Maximum number of attempts allowed within the window
	MaxAttempts int
	// Time window for rate limiting
	Window time.Duration
	// Lockout duration after exceeding max attempts
	LockoutDuration time.Duration
	// Enable exponential backoff for repeated violations
	ExponentialBackoff bool
	// Maximum lockout duration with exponential backoff
	MaxLockoutDuration time.Duration
	// Time after which to reset the violation count
	ViolationResetTime time.Duration
	// Enable IP-based rate limiting in addition to username
	EnableIPLimiting bool
	// Whitelist of IPs or usernames that bypass rate limiting
	Whitelist []string
}

// DefaultRateLimiterConfig returns a secure default configuration
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		MaxAttempts:        5,
		Window:             15 * time.Minute,
		LockoutDuration:    30 * time.Minute,
		ExponentialBackoff: true,
		MaxLockoutDuration: 24 * time.Hour,
		ViolationResetTime: 24 * time.Hour,
		EnableIPLimiting:   true,
		Whitelist:          []string{},
	}
}

// AttemptRecord tracks authentication attempts for a specific identifier
type AttemptRecord struct {
	// Timestamps of attempts within the current window
	Attempts []time.Time
	// Number of times the rate limit has been violated
	ViolationCount int
	// Time when the identifier is locked out until
	LockedUntil time.Time
	// Last time this record was updated
	LastUpdate time.Time
	// IP addresses associated with attempts (if IP limiting is enabled)
	IPAddresses map[string]int
}

// RateLimiter provides rate limiting for authentication attempts
type RateLimiter struct {
	config  *RateLimiterConfig
	logger  *slog.Logger
	mu      sync.RWMutex
	records map[string]*AttemptRecord
	// Cleanup ticker
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

// NewRateLimiter creates a new rate limiter with the specified configuration
func NewRateLimiter(config *RateLimiterConfig, logger *slog.Logger) *RateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}

	if logger == nil {
		logger = slog.Default()
	}

	rl := &RateLimiter{
		config:   config,
		logger:   logger.With(slog.String("component", "rate_limiter")),
		records:  make(map[string]*AttemptRecord),
		stopChan: make(chan struct{}),
	}

	// Start cleanup routine
	rl.startCleanup()

	rl.logger.Info("Rate limiter initialized",
		slog.Int("max_attempts", config.MaxAttempts),
		slog.Duration("window", config.Window),
		slog.Duration("lockout", config.LockoutDuration),
		slog.Bool("exponential_backoff", config.ExponentialBackoff))

	return rl
}

// CheckAttempt checks if an authentication attempt should be allowed
// Returns nil if allowed, or an error describing why it's blocked
func (rl *RateLimiter) CheckAttempt(identifier string, ipAddress string) error {
	// Check whitelist
	if rl.isWhitelisted(identifier) || rl.isWhitelisted(ipAddress) {
		return nil
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Get or create record
	record, exists := rl.records[identifier]
	if !exists {
		record = &AttemptRecord{
			Attempts:     make([]time.Time, 0, rl.config.MaxAttempts),
			IPAddresses:  make(map[string]int),
			LastUpdate:   now,
		}
		rl.records[identifier] = record
	}

	// Check if currently locked out
	if now.Before(record.LockedUntil) {
		remainingTime := record.LockedUntil.Sub(now)
		rl.logger.Warn("Authentication attempt blocked - account locked",
			slog.String("identifier", identifier),
			slog.String("ip", ipAddress),
			slog.Duration("remaining_lockout", remainingTime))

		return fmt.Errorf("account locked due to too many failed attempts. Try again in %v", remainingTime.Round(time.Second))
	}

	// Reset violation count if enough time has passed
	if now.Sub(record.LastUpdate) > rl.config.ViolationResetTime {
		record.ViolationCount = 0
	}

	// Clean old attempts outside the window
	validAttempts := make([]time.Time, 0, len(record.Attempts))
	windowStart := now.Add(-rl.config.Window)
	for _, attempt := range record.Attempts {
		if attempt.After(windowStart) {
			validAttempts = append(validAttempts, attempt)
		}
	}
	record.Attempts = validAttempts

	// Check if we've exceeded the limit
	if len(record.Attempts) >= rl.config.MaxAttempts {
		// Calculate lockout duration
		lockoutDuration := rl.calculateLockoutDuration(record.ViolationCount)
		record.LockedUntil = now.Add(lockoutDuration)
		record.ViolationCount++
		record.LastUpdate = now

		rl.logger.Warn("Rate limit exceeded - account locked",
			slog.String("identifier", identifier),
			slog.String("ip", ipAddress),
			slog.Int("attempts", len(record.Attempts)),
			slog.Int("violation_count", record.ViolationCount),
			slog.Duration("lockout_duration", lockoutDuration))

		return fmt.Errorf("too many authentication attempts. Account locked for %v", lockoutDuration.Round(time.Second))
	}

	// Record the attempt
	record.Attempts = append(record.Attempts, now)
	record.LastUpdate = now

	// Track IP address if enabled
	if rl.config.EnableIPLimiting && ipAddress != "" {
		record.IPAddresses[ipAddress]++

		// Check for suspicious IP behavior (many different IPs)
		if len(record.IPAddresses) > 5 {
			rl.logger.Warn("Multiple IP addresses detected for identifier",
				slog.String("identifier", identifier),
				slog.Int("unique_ips", len(record.IPAddresses)))
		}
	}

	return nil
}

// RecordSuccess records a successful authentication, potentially resetting the attempt counter
func (rl *RateLimiter) RecordSuccess(identifier string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if record, exists := rl.records[identifier]; exists {
		// Clear attempts on successful authentication
		record.Attempts = make([]time.Time, 0, rl.config.MaxAttempts)
		// Optionally reset violation count on successful auth
		// This is a policy decision - you might want to keep it for security
		// record.ViolationCount = 0
		record.LastUpdate = time.Now()

		rl.logger.Debug("Successful authentication recorded",
			slog.String("identifier", identifier),
			slog.Int("violation_count", record.ViolationCount))
	}
}

// RecordFailure records a failed authentication attempt
func (rl *RateLimiter) RecordFailure(identifier string, ipAddress string) {
	// Use CheckAttempt to record the failure and apply rate limiting
	if err := rl.CheckAttempt(identifier, ipAddress); err != nil {
		rl.logger.Debug("Failed attempt recorded and rate limit applied",
			slog.String("identifier", identifier),
			slog.String("ip", ipAddress),
			slog.String("status", err.Error()))
	} else {
		rl.logger.Debug("Failed attempt recorded",
			slog.String("identifier", identifier),
			slog.String("ip", ipAddress),
			slog.Int("attempts_remaining", rl.config.MaxAttempts-rl.getAttemptCount(identifier)))
	}
}

// GetStatus returns the current status for an identifier
func (rl *RateLimiter) GetStatus(identifier string) (attempts int, lockedUntil time.Time, isLocked bool) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	record, exists := rl.records[identifier]
	if !exists {
		return 0, time.Time{}, false
	}

	now := time.Now()
	windowStart := now.Add(-rl.config.Window)

	// Count valid attempts
	for _, attempt := range record.Attempts {
		if attempt.After(windowStart) {
			attempts++
		}
	}

	if now.Before(record.LockedUntil) {
		return attempts, record.LockedUntil, true
	}

	return attempts, time.Time{}, false
}

// Reset clears the rate limit record for an identifier
func (rl *RateLimiter) Reset(identifier string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.records, identifier)

	rl.logger.Info("Rate limit reset for identifier",
		slog.String("identifier", identifier))
}

// Close stops the rate limiter and its background tasks
func (rl *RateLimiter) Close() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}

	close(rl.stopChan)
	rl.wg.Wait()

	rl.logger.Info("Rate limiter closed")
}

// Private methods

func (rl *RateLimiter) isWhitelisted(identifier string) bool {
	for _, whitelisted := range rl.config.Whitelist {
		if whitelisted == identifier {
			return true
		}
	}
	return false
}

func (rl *RateLimiter) calculateLockoutDuration(violationCount int) time.Duration {
	if !rl.config.ExponentialBackoff {
		return rl.config.LockoutDuration
	}

	// Exponential backoff: duration * 2^violationCount
	duration := rl.config.LockoutDuration
	for i := 0; i < violationCount; i++ {
		duration *= 2
		if duration > rl.config.MaxLockoutDuration {
			return rl.config.MaxLockoutDuration
		}
	}

	return duration
}

func (rl *RateLimiter) getAttemptCount(identifier string) int {
	record, exists := rl.records[identifier]
	if !exists {
		return 0
	}

	now := time.Now()
	windowStart := now.Add(-rl.config.Window)
	count := 0

	for _, attempt := range record.Attempts {
		if attempt.After(windowStart) {
			count++
		}
	}

	return count
}

func (rl *RateLimiter) startCleanup() {
	rl.cleanupTicker = time.NewTicker(1 * time.Hour)

	rl.wg.Add(1)
	go func() {
		defer rl.wg.Done()
		for {
			select {
			case <-rl.cleanupTicker.C:
				rl.cleanup()
			case <-rl.stopChan:
				return
			}
		}
	}()
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	expiredIdentifiers := make([]string, 0)

	for identifier, record := range rl.records {
		// Remove records that haven't been updated in a long time and aren't locked
		if now.Sub(record.LastUpdate) > 24*time.Hour && now.After(record.LockedUntil) {
			expiredIdentifiers = append(expiredIdentifiers, identifier)
		}
	}

	for _, identifier := range expiredIdentifiers {
		delete(rl.records, identifier)
	}

	if len(expiredIdentifiers) > 0 {
		rl.logger.Debug("Cleaned up expired rate limit records",
			slog.Int("removed", len(expiredIdentifiers)))
	}
}

// RateLimitedAuthenticator wraps an LDAP client with rate limiting
type RateLimitedAuthenticator struct {
	client      *LDAP
	rateLimiter *RateLimiter
	logger      *slog.Logger
}

// NewRateLimitedAuthenticator creates a new rate-limited authenticator
func NewRateLimitedAuthenticator(client *LDAP, config *RateLimiterConfig, logger *slog.Logger) *RateLimitedAuthenticator {
	if logger == nil {
		logger = slog.Default()
	}

	return &RateLimitedAuthenticator{
		client:      client,
		rateLimiter: NewRateLimiter(config, logger),
		logger:      logger.With(slog.String("component", "rate_limited_auth")),
	}
}

// Authenticate performs rate-limited authentication
func (rla *RateLimitedAuthenticator) Authenticate(ctx context.Context, username, password, ipAddress string) error {
	// Check rate limit before attempting authentication
	if err := rla.rateLimiter.CheckAttempt(username, ipAddress); err != nil {
		return fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Perform actual authentication
	_, err := rla.client.CheckPasswordForSAMAccountNameContext(ctx, username, password)

	if err != nil {
		// Record failure
		rla.rateLimiter.RecordFailure(username, ipAddress)
		rla.logger.Warn("Authentication failed",
			slog.String("username", username),
			slog.String("ip", ipAddress),
			slog.String("error", err.Error()))
		return err
	}

	// Record success
	rla.rateLimiter.RecordSuccess(username)
	rla.logger.Info("Authentication successful",
		slog.String("username", username),
		slog.String("ip", ipAddress))

	return nil
}

// GetRateLimitStatus returns the current rate limit status for a user
func (rla *RateLimitedAuthenticator) GetRateLimitStatus(username string) (attempts int, lockedUntil time.Time, isLocked bool) {
	return rla.rateLimiter.GetStatus(username)
}

// ResetRateLimit resets the rate limit for a specific user
func (rla *RateLimitedAuthenticator) ResetRateLimit(username string) {
	rla.rateLimiter.Reset(username)
}

// Close closes the rate limiter
func (rla *RateLimitedAuthenticator) Close() {
	rla.rateLimiter.Close()
}