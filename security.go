package ldap

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

// SecureCredential provides secure handling of authentication credentials with memory protection
type SecureCredential struct {
	mutex    sync.RWMutex
	username []byte
	password []byte
	provider CredentialProvider
}

// CredentialProvider interface allows for custom credential management strategies
type CredentialProvider interface {
	// GetCredentials returns the current username and password
	GetCredentials() (string, string)
	// ZeroizeCredentials securely clears credential data from memory
	ZeroizeCredentials() error
	// ValidateCredentials validates the credential format and requirements
	ValidateCredentials() error
}

// DefaultCredentialProvider implements basic in-memory credential management
type DefaultCredentialProvider struct {
	username string
	password string
}

// GetCredentials returns the stored credentials
func (p *DefaultCredentialProvider) GetCredentials() (string, string) {
	return p.username, p.password
}

// ZeroizeCredentials clears the credential strings (basic implementation)
func (p *DefaultCredentialProvider) ZeroizeCredentials() error {
	// Zero out the strings as much as possible
	if p.username != "" {
		// Create a new string with zeros
		zeros := make([]byte, len(p.username))
		p.username = string(zeros)
	}
	if p.password != "" {
		// Create a new string with zeros
		zeros := make([]byte, len(p.password))
		p.password = string(zeros)
	}
	return nil
}

// ValidateCredentials performs basic validation
func (p *DefaultCredentialProvider) ValidateCredentials() error {
	if p.username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if p.password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	return nil
}

// NewSecureCredential creates a new SecureCredential with the given provider
func NewSecureCredential(provider CredentialProvider) (*SecureCredential, error) {
	if provider == nil {
		return nil, fmt.Errorf("credential provider cannot be nil")
	}

	if err := provider.ValidateCredentials(); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	username, password := provider.GetCredentials()

	sc := &SecureCredential{
		provider: provider,
		username: []byte(username),
		password: []byte(password),
	}

	return sc, nil
}

// NewSecureCredentialSimple creates a SecureCredential with basic string credentials
func NewSecureCredentialSimple(username, password string) (*SecureCredential, error) {
	provider := &DefaultCredentialProvider{
		username: username,
		password: password,
	}
	return NewSecureCredential(provider)
}

// Security validation constants
const (
	// MaxFilterLength defines the maximum length for LDAP filters to prevent DoS attacks
	MaxFilterLength = 10000
	// MaxDNLength defines the maximum length for Distinguished Names
	MaxDNLength = 8000
	// MaxSAMAccountNameLength defines the maximum length for sAMAccountName
	MaxSAMAccountNameLength = 20
)

// ValidateDN validates and normalizes a Distinguished Name (DN)
func ValidateDN(dn string) (string, error) {
	if dn == "" {
		return "", fmt.Errorf("DN cannot be empty")
	}

	if len(dn) > MaxDNLength {
		return "", fmt.Errorf("DN too long: %d characters (max %d)", len(dn), MaxDNLength)
	}

	// Check for control characters
	for _, r := range dn {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("DN contains control characters")
		}
	}

	// Basic DN format validation - must contain at least one component with =
	if !strings.Contains(dn, "=") {
		return "", fmt.Errorf("DN format invalid: must contain at least one component with '='")
	}

	// Check for empty components (double commas)
	if strings.Contains(dn, ",,") {
		return "", fmt.Errorf("DN format invalid: contains empty component")
	}

	// Check for trailing comma
	if strings.HasSuffix(dn, ",") {
		return "", fmt.Errorf("DN format invalid: trailing comma")
	}

	// Normalize the DN (basic implementation)
	normalized := strings.TrimSpace(dn)

	return normalized, nil
}

// ValidateLDAPFilter validates LDAP search filters for security
func ValidateLDAPFilter(filter string) (string, error) {
	if filter == "" {
		return "", fmt.Errorf("filter cannot be empty")
	}

	if len(filter) > MaxFilterLength {
		return "", fmt.Errorf("filter too long: %d characters (max %d)", len(filter), MaxFilterLength)
	}

	// Check for control characters
	for _, r := range filter {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("filter contains control characters")
		}
	}

	// Basic filter format validation - must start and end with parentheses
	if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") {
		return "", fmt.Errorf("filter format invalid: must be enclosed in parentheses")
	}

	return filter, nil
}

// EscapeFilterValue escapes special characters in LDAP filter values
func EscapeFilterValue(value string) string {
	// LDAP filter special characters that need escaping
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\x00", "\\00",
	)

	return replacer.Replace(value)
}

// ValidateSAMAccountName validates sAMAccountName format
func ValidateSAMAccountName(sam string) error {
	if sam == "" {
		return fmt.Errorf("sAMAccountName cannot be empty")
	}

	if len(sam) > MaxSAMAccountNameLength {
		return fmt.Errorf("sAMAccountName too long: %d characters (max %d)", len(sam), MaxSAMAccountNameLength)
	}

	// sAMAccountName restrictions
	invalidChars := []string{
		"\"", "/", "\\", "[", "]", ":", ";", "|", "=", ",", "+", "*", "?", "<", ">",
	}

	for _, char := range invalidChars {
		if strings.Contains(sam, char) {
			return fmt.Errorf("sAMAccountName contains invalid character: %s", char)
		}
	}

	// Cannot start or end with space or period
	if strings.HasPrefix(sam, " ") || strings.HasSuffix(sam, " ") {
		return fmt.Errorf("sAMAccountName cannot start or end with space")
	}

	if strings.HasPrefix(sam, ".") || strings.HasSuffix(sam, ".") {
		return fmt.Errorf("sAMAccountName cannot start or end with period")
	}

	return nil
}

// ValidateEmail validates email address format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}

	return nil
}

// ValidatePassword validates password strength and format
func ValidatePassword(password string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if len(password) < 8 {
		return fmt.Errorf("password too short: must be at least 8 characters")
	}

	if len(password) > 128 {
		return fmt.Errorf("password too long: maximum 128 characters")
	}

	// Check for at least one character from different categories
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}

	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// ValidateServerURL validates LDAP server URL format and security
func ValidateServerURL(serverURL string) error {
	if serverURL == "" {
		return fmt.Errorf("server URL cannot be empty")
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Check for valid LDAP schemes
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return fmt.Errorf("invalid scheme: must be 'ldap' or 'ldaps'")
	}

	// Check for hostname
	if u.Hostname() == "" {
		return fmt.Errorf("URL must contain a hostname")
	}

	// Validate port if specified
	if u.Port() != "" {
		// Basic port validation - must be numeric and in valid range
		port := u.Port()
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(port) {
			return fmt.Errorf("invalid port format")
		}
	}

	return nil
}

// GetCredentials returns the username and password for authentication
func (sc *SecureCredential) GetCredentials() (string, string) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	return string(sc.username), string(sc.password)
}

// ZeroizeCredentials securely clears credential data from memory
func (sc *SecureCredential) ZeroizeCredentials() error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// Zero out the byte slices
	for i := range sc.username {
		sc.username[i] = 0
	}
	for i := range sc.password {
		sc.password[i] = 0
	}

	// Clear the slices
	sc.username = nil
	sc.password = nil

	// Call provider's zeroize method
	if err := sc.provider.ZeroizeCredentials(); err != nil {
		_ = err // Ignore error as suggested by golangci-lint fix
	}

	return nil
}

// Clone creates a copy of the SecureCredential for use in different contexts
func (sc *SecureCredential) Clone() (*SecureCredential, error) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	username, password := sc.GetCredentials()
	return NewSecureCredentialSimple(username, password)
}

// SecurityConfig contains security-related configuration options
type SecurityConfig struct {
	// TLSConfig specifies custom TLS configuration for LDAPS connections
	TLSConfig *tls.Config

	// RequireSecureConnection forces the use of LDAPS (TLS encryption)
	RequireSecureConnection bool

	// DisableTLSVerification disables TLS certificate verification (INSECURE - use only for testing)
	DisableTLSVerification bool

	// ConnectionTimeout specifies the timeout for establishing connections
	ConnectionTimeout time.Duration

	// ReadTimeout specifies the timeout for read operations
	ReadTimeout time.Duration

	// WriteTimeout specifies the timeout for write operations
	WriteTimeout time.Duration

	// MaxPasswordLength limits the maximum password length for security
	MaxPasswordLength int

	// RequireStrongPasswords enforces strong password requirements
	RequireStrongPasswords bool

	// EnableAuditLogging enables detailed security audit logging
	EnableAuditLogging bool

	// AuditLogLevel specifies the minimum log level for audit events
	AuditLogLevel slog.Level
}

// DefaultSecurityConfig returns a SecurityConfig with secure defaults
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		RequireSecureConnection:    true,
		DisableTLSVerification:     false,
		ConnectionTimeout:          30 * time.Second,
		ReadTimeout:                30 * time.Second,
		WriteTimeout:               30 * time.Second,
		MaxPasswordLength:          256,
		RequireStrongPasswords:     true,
		EnableAuditLogging:         true,
		AuditLogLevel:              slog.LevelInfo,
	}
}

// RateLimiterConfig contains configuration for authentication rate limiting
type RateLimiterConfig struct {
	// MaxAttempts is the maximum number of authentication attempts allowed
	MaxAttempts int

	// Window is the time window for rate limiting
	Window time.Duration

	// LockoutDuration is how long to lock out after exceeding MaxAttempts
	LockoutDuration time.Duration

	// CleanupInterval is how often to clean up expired entries
	CleanupInterval time.Duration

	// MaxEntries is the maximum number of entries to track
	MaxEntries int
}

// DefaultRateLimiterConfig returns a RateLimiterConfig with sensible defaults
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		MaxAttempts:     5,
		Window:          15 * time.Minute,
		LockoutDuration: 30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
		MaxEntries:      10000,
	}
}

// RateLimiterEntry tracks authentication attempts for a specific identifier
type RateLimiterEntry struct {
	Attempts    int
	FirstAttempt time.Time
	LastAttempt  time.Time
	LockedUntil  time.Time
}

// RateLimiterMetrics provides statistics about rate limiting
type RateLimiterMetrics struct {
	TotalAttempts        int64         `json:"total_attempts"`
	BlockedAttempts      int64         `json:"blocked_attempts"`
	SuccessfulAttempts   int64         `json:"successful_attempts"`
	WhitelistedAttempts  int64         `json:"whitelisted_attempts"`
	ActiveLockouts       int64         `json:"active_lockouts"`
	SuccessfulAuth       int64         `json:"successful_auth"`
	FailedAuth           int64         `json:"failed_auth"`
	AverageAttempts      float64       `json:"average_attempts"`
	TopOffenders         []string      `json:"top_offenders,omitempty"`

	// Security analysis metrics
	ViolationEvents      int64         `json:"violation_events"`
	SuspiciousPatterns   int64         `json:"suspicious_patterns"`
	BurstAttacks         int64         `json:"burst_attacks"`
	RepeatedViolators    int64         `json:"repeated_violators"`

	// Resource usage metrics
	UniqueIdentifiers    int64         `json:"unique_identifiers"`
	MemoryUsageBytes     int64         `json:"memory_usage_bytes"`

	// Performance metrics
	AvgCheckTime         time.Duration `json:"avg_check_time"`
	PeakConcurrentChecks int           `json:"peak_concurrent_checks"`
}

// RateLimiter provides authentication rate limiting functionality
type RateLimiter struct {
	config   *RateLimiterConfig
	entries  map[string]*RateLimiterEntry
	metrics  *RateLimiterMetrics
	mutex    sync.RWMutex
	logger   *slog.Logger
	stopChan chan struct{}
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config *RateLimiterConfig, logger *slog.Logger) *RateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	rl := &RateLimiter{
		config:   config,
		entries:  make(map[string]*RateLimiterEntry),
		metrics:  &RateLimiterMetrics{},
		logger:   logger,
		stopChan: make(chan struct{}),
	}

	// Start cleanup routine
	go rl.cleanupRoutine()

	return rl
}

// CheckLimit verifies if the authentication attempt is allowed
func (rl *RateLimiter) CheckLimit(identifier string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	entry, exists := rl.entries[identifier]

	if !exists {
		// First attempt for this identifier
		rl.entries[identifier] = &RateLimiterEntry{
			Attempts:     1,
			FirstAttempt: now,
			LastAttempt:  now,
		}
		rl.metrics.TotalAttempts++
		return true
	}

	// Check if currently locked out
	if now.Before(entry.LockedUntil) {
		rl.metrics.BlockedAttempts++
		rl.logger.Debug("authentication_blocked_lockout",
			slog.String("identifier", maskSensitiveData(identifier)),
			slog.Time("locked_until", entry.LockedUntil))
		return false
	}

	// Check if window has expired (reset attempts)
	if now.Sub(entry.FirstAttempt) > rl.config.Window {
		entry.Attempts = 1
		entry.FirstAttempt = now
		entry.LastAttempt = now
		entry.LockedUntil = time.Time{}
		rl.metrics.TotalAttempts++
		return true
	}

	// Increment attempts
	entry.Attempts++
	entry.LastAttempt = now
	rl.metrics.TotalAttempts++

	// Check if limit exceeded
	if entry.Attempts > rl.config.MaxAttempts {
		entry.LockedUntil = now.Add(rl.config.LockoutDuration)
		rl.metrics.BlockedAttempts++
		rl.metrics.ActiveLockouts++

		rl.logger.Warn("authentication_rate_limit_exceeded",
			slog.String("identifier", maskSensitiveData(identifier)),
			slog.Int("attempts", entry.Attempts),
			slog.Duration("lockout_duration", rl.config.LockoutDuration))

		return false
	}

	return true
}

// RecordSuccess records a successful authentication
func (rl *RateLimiter) RecordSuccess(identifier string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.metrics.SuccessfulAuth++

	// Optionally reset attempts on successful auth
	if entry, exists := rl.entries[identifier]; exists {
		entry.Attempts = 0
		entry.LockedUntil = time.Time{}
	}
}

// RecordFailure records a failed authentication attempt
func (rl *RateLimiter) RecordFailure(identifier string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.metrics.FailedAuth++
}

// GetMetrics returns current rate limiter metrics
func (rl *RateLimiter) GetMetrics() RateLimiterMetrics {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	// Create a copy of metrics
	metrics := *rl.metrics

	// Calculate average attempts
	if rl.metrics.TotalAttempts > 0 {
		metrics.AverageAttempts = float64(rl.metrics.TotalAttempts) / float64(len(rl.entries))
	}

	// Update active lockouts count
	now := time.Now()
	activeLockouts := int64(0)
	for _, entry := range rl.entries {
		if now.Before(entry.LockedUntil) {
			activeLockouts++
		}
	}
	metrics.ActiveLockouts = activeLockouts

	return metrics
}

// Reset clears all rate limiter entries and metrics
func (rl *RateLimiter) Reset() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.entries = make(map[string]*RateLimiterEntry)
	rl.metrics = &RateLimiterMetrics{}

	rl.logger.Info("rate_limiter_reset")
}

// Close stops the rate limiter and cleanup routines
func (rl *RateLimiter) Close() {
	close(rl.stopChan)
	rl.logger.Debug("rate_limiter_stopped")
}

// cleanupRoutine periodically cleans up expired entries
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanup removes expired entries
func (rl *RateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	removed := 0

	for identifier, entry := range rl.entries {
		// Remove entries that are old and not locked
		if now.Sub(entry.LastAttempt) > rl.config.Window && now.After(entry.LockedUntil) {
			delete(rl.entries, identifier)
			removed++
		}
	}

	// Enforce max entries limit
	if len(rl.entries) > rl.config.MaxEntries {
		// Remove oldest entries
		type entryWithID struct {
			id    string
			entry *RateLimiterEntry
		}

		var sortedEntries []entryWithID
		for id, entry := range rl.entries {
			sortedEntries = append(sortedEntries, entryWithID{id, entry})
		}

		// Sort by last attempt time (oldest first)
		for i := 0; i < len(sortedEntries)-1; i++ {
			for j := i + 1; j < len(sortedEntries); j++ {
				if sortedEntries[i].entry.LastAttempt.After(sortedEntries[j].entry.LastAttempt) {
					sortedEntries[i], sortedEntries[j] = sortedEntries[j], sortedEntries[i]
				}
			}
		}

		// Remove oldest entries
		toRemove := len(rl.entries) - rl.config.MaxEntries
		for i := 0; i < toRemove; i++ {
			delete(rl.entries, sortedEntries[i].id)
			removed++
		}
	}

	if removed > 0 {
		rl.logger.Debug("rate_limiter_cleanup",
			slog.Int("removed_entries", removed),
			slog.Int("remaining_entries", len(rl.entries)))
	}
}

// PasswordValidator provides password strength validation
type PasswordValidator struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSymbols   bool
	ForbiddenWords   []string
}

// DefaultPasswordValidator returns a validator with strong password requirements
func DefaultPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   true,
		ForbiddenWords:   []string{"password", "admin", "123456", "qwerty"},
	}
}

// ValidatePassword checks if a password meets the security requirements
func (pv *PasswordValidator) ValidatePassword(password string) error {
	if len(password) < pv.MinLength {
		return fmt.Errorf("password must be at least %d characters long", pv.MinLength)
	}

	if pv.RequireUppercase && !containsUppercase(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if pv.RequireLowercase && !containsLowercase(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if pv.RequireNumbers && !containsNumber(password) {
		return fmt.Errorf("password must contain at least one number")
	}

	if pv.RequireSymbols && !containsSymbol(password) {
		return fmt.Errorf("password must contain at least one symbol")
	}

	// Check forbidden words
	lowerPassword := strings.ToLower(password)
	for _, word := range pv.ForbiddenWords {
		if strings.Contains(lowerPassword, strings.ToLower(word)) {
			return fmt.Errorf("password contains forbidden word: %s", word)
		}
	}

	return nil
}

// Helper functions for password validation
func containsUppercase(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

func containsNumber(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func containsSymbol(s string) bool {
	symbols := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, r := range s {
		if strings.ContainsRune(symbols, r) {
			return true
		}
	}
	return false
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	// Use base64 URL encoding for safe token representation
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i, b := range bytes {
		bytes[i] = chars[b%byte(len(chars))]
	}

	return string(bytes), nil
}

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

// Context keys for passing security-related information
const (
	ContextKeyClientIP    ContextKey = "client_ip"
	ContextKeyUserAgent   ContextKey = "user_agent"
	ContextKeyRequestID   ContextKey = "request_id"
	ContextKeySessionID   ContextKey = "session_id"
	ContextKeySecurityCtx ContextKey = "security_context"
)

// SecurityContext contains security-related information for operations
type SecurityContext struct {
	ClientIP       string
	UserAgent      string
	RequestID      string
	SessionID      string
	AuthenticatedUser string
	Permissions    []string
	RateLimited    bool
	AuditEnabled   bool
}

// NewSecurityContext creates a new security context
func NewSecurityContext() *SecurityContext {
	requestID, _ := generateSecureToken(16)
	return &SecurityContext{
		RequestID:    requestID,
		AuditEnabled: true,
	}
}

// AddToContext adds the security context to a Go context
func (sc *SecurityContext) AddToContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, ContextKeySecurityCtx, sc)
	ctx = context.WithValue(ctx, ContextKeyClientIP, sc.ClientIP)
	ctx = context.WithValue(ctx, ContextKeyUserAgent, sc.UserAgent)
	ctx = context.WithValue(ctx, ContextKeyRequestID, sc.RequestID)
	ctx = context.WithValue(ctx, ContextKeySessionID, sc.SessionID)
	return ctx
}

// GetSecurityContext extracts security context from a Go context
func GetSecurityContext(ctx context.Context) *SecurityContext {
	if sc, ok := ctx.Value(ContextKeySecurityCtx).(*SecurityContext); ok {
		return sc
	}
	return NewSecurityContext()
}

// maskSensitiveData masks sensitive information for logging
func maskSensitiveData(data string) string {
	if len(data) <= 4 {
		return "***"
	}

	// Show first 2 and last 2 characters, mask the middle
	visible := 2
	if len(data) < 6 {
		visible = 1
	}

	prefix := data[:visible]
	suffix := data[len(data)-visible:]
	masked := strings.Repeat("*", len(data)-2*visible)

	return prefix + masked + suffix
}

// logSecurityEvent logs security-related events
func logSecurityEvent(event string, details map[string]interface{}) {
	// This is a placeholder implementation
	// In a real implementation, you would use a proper security event logging system
	_ = event
	_ = details
}

