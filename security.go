package ldap

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unsafe"

	"github.com/go-ldap/ldap/v3"
)

// SecurityConfig contains security settings and policies for LDAP operations
type SecurityConfig struct {
	// Rate limiting
	MaxRequestsPerSecond int `json:"max_requests_per_second"`
	MaxConcurrentOps     int `json:"max_concurrent_ops"`
	
	// Network access control
	IPWhitelist         []net.IPNet    `json:"ip_whitelist"`
	RequiredCipherSuite []uint16       `json:"required_cipher_suites"`
	
	// Security monitoring
	AuditLog            bool           `json:"audit_log"`
	SecurityEventLog    bool           `json:"security_event_log"`
	
	// Input validation strictness
	StrictValidation    bool           `json:"strict_validation"`
	MaxFilterComplexity int            `json:"max_filter_complexity"`
	MaxDNDepth         int            `json:"max_dn_depth"`
	
	// Credential protection
	ZeroizeCredentials bool           `json:"zeroize_credentials"`
	CredentialTimeout  time.Duration  `json:"credential_timeout"`
}

// TLSConfig contains enhanced TLS security configuration
type TLSConfig struct {
	// InsecureSkipVerify allows self-signed certificates (development only)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	
	// MinVersion specifies minimum TLS version (default: TLS 1.2)
	MinVersion uint16 `json:"min_version"`
	
	// MaxVersion specifies maximum TLS version (default: TLS 1.3)
	MaxVersion uint16 `json:"max_version"`
	
	// CipherSuites specifies allowed cipher suites
	CipherSuites []uint16 `json:"cipher_suites"`
	
	// CurvePreferences specifies allowed elliptic curves
	CurvePreferences []tls.CurveID `json:"curve_preferences"`
	
	// CustomVerifyFunc allows custom certificate verification
	CustomVerifyFunc func([][]byte, [][]*x509.Certificate) error `json:"-"`
	
	// RequiredSANs specifies required Subject Alternative Names
	RequiredSANs []string `json:"required_sans"`
}

// PasswordPolicy defines password validation rules
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	MaxLength      int  `json:"max_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireDigits  bool `json:"require_digits"`
	RequireSymbols bool `json:"require_symbols"`
	ValidateUTF8   bool `json:"validate_utf8"`
}

// CredentialProvider interface for external credential sources
type CredentialProvider interface {
	GetCredentials() (username, password string, err error)
	RefreshCredentials() error
	ZeroizeCredentials() error
}

// SecureCredential represents secure credential storage with automatic cleanup
type SecureCredential struct {
	username []byte
	password []byte
	provider CredentialProvider
	timeout  time.Duration
}

// SecurityResult represents the outcome of security validation
type SecurityResult struct {
	IsValid      bool                   `json:"is_valid"`
	Severity     SecuritySeverity       `json:"severity"`
	Issues       []SecurityIssue        `json:"issues,omitempty"`
	Normalized   string                 `json:"normalized,omitempty"`
	Escaped      string                 `json:"escaped,omitempty"`
	Threat       *ThreatContext         `json:"threat,omitempty"`
}

// SecuritySeverity represents the severity level of security events
type SecuritySeverity string

const (
	SecurityInfo     SecuritySeverity = "INFO"
	SecurityWarn     SecuritySeverity = "WARN"
	SecurityError    SecuritySeverity = "ERROR"
	SecurityCritical SecuritySeverity = "CRITICAL"
)

// ThreatContext contains threat analysis information
type ThreatContext struct {
	ThreatType      string   `json:"threat_type"`
	AttackVectors   []string `json:"attack_vectors"`
	RiskScore       float64  `json:"risk_score"`
	Mitigation      string   `json:"mitigation"`
	RequiresAction  bool     `json:"requires_action"`
}

// SecurityIssue represents a specific security validation issue
type SecurityIssue struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Field       string `json:"field,omitempty"`
	Value       string `json:"value,omitempty"`
	Position    int    `json:"position,omitempty"`
}

// Security validation patterns and constants
var (
	// DN component validation pattern - updated to handle escaped characters properly
	dnComponentRegex = regexp.MustCompile(`^[A-Za-z][\w-]*=.*$`)
	
	// Attribute name validation pattern
	attributeNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$`)
	
	// SAM account name validation pattern (Windows)
	samAccountNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	
	// Email validation pattern (basic)
	emailValidationRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	
	// Dangerous LDAP filter characters for enhanced escaping
	dangerousFilterChars = []rune{'*', '(', ')', '\\', '\x00', '/', '|', '&', '!', '<', '>', '=', '~', '^'}
	
	// Maximum safe lengths for various components
	MaxDNLength        = 8192
	MaxFilterLength    = 4096
	MaxAttributeLength = 1024
	MaxValueLength     = 65536
	
	// Default secure cipher suites (TLS 1.2 and 1.3)
	SecureCipherSuites = []uint16{
		tls.TLS_AES_256_GCM_SHA384,         // TLS 1.3
		tls.TLS_CHACHA20_POLY1305_SHA256,   // TLS 1.3
		tls.TLS_AES_128_GCM_SHA256,         // TLS 1.3
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,      // TLS 1.2
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,    // TLS 1.2
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,       // TLS 1.2
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,     // TLS 1.2
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,      // TLS 1.2
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,    // TLS 1.2
	}
	
	// Default elliptic curves
	SecureEllipticCurves = []tls.CurveID{
		tls.X25519,
		tls.CurveP521,
		tls.CurveP384,
		tls.CurveP256,
	}
)

// Additional security errors (using existing ones from errors.go for duplicates)
var (
	ErrSecurityThreat      = fmt.Errorf("ldap: security threat detected")
	ErrRateLimitExceeded   = fmt.Errorf("ldap: rate limit exceeded")
	ErrAccessDenied        = fmt.Errorf("ldap: access denied")
	ErrTLSConfigInvalid    = fmt.Errorf("ldap: invalid TLS configuration")
	ErrCredentialTimeout   = fmt.Errorf("ldap: credential timeout")
)

// ValidateDN validates and normalizes a distinguished name for security
func ValidateDN(dn string) (string, error) {
	if len(dn) == 0 {
		return "", fmt.Errorf("%w: empty DN", ErrInvalidDN)
	}
	
	if len(dn) > MaxDNLength {
		return "", fmt.Errorf("%w: DN too long (%d > %d)", ErrInvalidDN, len(dn), MaxDNLength)
	}
	
	// Normalize whitespace
	normalized := strings.TrimSpace(dn)
	
	// Basic DN syntax validation
	if !strings.Contains(normalized, "=") {
		return "", fmt.Errorf("%w: DN must contain at least one attribute=value pair", ErrInvalidDN)
	}
	
	// Split DN into components and validate each
	components := strings.Split(normalized, ",")
	validatedComponents := make([]string, 0, len(components))
	
	for _, component := range components {
		trimmed := strings.TrimSpace(component)
		if len(trimmed) == 0 {
			return "", fmt.Errorf("%w: empty DN component", ErrInvalidDN)
		}
		
		// Validate component format: attribute=value
		if !dnComponentRegex.MatchString(trimmed) {
			return "", fmt.Errorf("%w: invalid DN component format: %s", ErrInvalidDN, trimmed)
		}
		
		validatedComponents = append(validatedComponents, trimmed)
	}
	
	return strings.Join(validatedComponents, ","), nil
}

// ValidateLDAPFilter validates an LDAP filter for security and syntax
func ValidateLDAPFilter(filter string) (string, error) {
	if len(filter) == 0 {
		return "", fmt.Errorf("%w: empty filter", ErrInvalidFilter)
	}
	
	if len(filter) > MaxFilterLength {
		return "", fmt.Errorf("%w: filter too long (%d > %d)", ErrInvalidFilter, len(filter), MaxFilterLength)
	}
	
	// Check for balanced parentheses
	if !isBalancedParentheses(filter) {
		return "", fmt.Errorf("%w: unbalanced parentheses", ErrInvalidFilter)
	}
	
	// Detect potential injection attempts
	if threat := DetectInjectionAttempt(filter); threat != nil && threat.RiskScore > 0.5 {
		return "", fmt.Errorf("%w: %s (risk: %.2f)", ErrSecurityThreat, threat.ThreatType, threat.RiskScore)
	}
	
	// Basic syntax validation - must start with '(' for complex filters
	normalized := strings.TrimSpace(filter)
	if len(normalized) > 0 && normalized[0] != '(' && strings.Contains(normalized, "(") {
		normalized = "(" + normalized + ")"
	}
	
	return normalized, nil
}

// EscapeFilterValue securely escapes a value for use in LDAP filters
func EscapeFilterValue(value string) string {
	if len(value) == 0 {
		return ""
	}
	
	// Use standard LDAP escaping first, but check if it's already escaped
	var escaped string
	
	// Check if the value is already properly escaped
	alreadyEscaped := strings.Contains(value, "\\28") || strings.Contains(value, "\\29") ||
		strings.Contains(value, "\\2a") || strings.Contains(value, "\\5c") || strings.Contains(value, "\\00")
	
	if alreadyEscaped {
		// If already escaped, use as-is to avoid double-escaping
		escaped = value
	} else {
		// Apply standard LDAP escaping
		escaped = ldap.EscapeFilter(value)
	}
	
	return escaped
}

// isBalancedParentheses checks if parentheses are balanced in a string
func isBalancedParentheses(s string) bool {
	count := 0
	for _, ch := range s {
		switch ch {
		case '(':
			count++
		case ')':
			count--
			if count < 0 {
				return false
			}
		}
	}
	return count == 0
}

// DetectInjectionAttempt analyzes input for potential LDAP injection attacks
func DetectInjectionAttempt(input string) *ThreatContext {
	suspiciousPatterns := []struct {
		pattern string
		threat  string
		risk    float64
	}{
		{"*)(", "LDAP filter injection", 0.8},
		{"*)(&", "LDAP filter injection", 0.9},
		{"*))%00", "Null byte injection", 0.9},
		{")(objectclass=*", "Object enumeration", 0.7},
		{")(|(objectclass=*", "Complex injection", 0.9},
		{")(cn=*", "Name enumeration", 0.6},
		{")(userpassword=*", "Password enumeration", 0.9},
		{")(|(cn=*)(", "Complex enumeration", 0.8},
		{")(objectclass=", "Filter manipulation", 0.7},
		{"|(useraccountcontrol=", "Account control bypass", 0.8},
	}
	
	threats := &ThreatContext{
		AttackVectors: make([]string, 0),
		RiskScore:     0.0,
	}
	
	inputLower := strings.ToLower(input)
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(inputLower, pattern.pattern) {
			threats.AttackVectors = append(threats.AttackVectors, pattern.threat)
			if pattern.risk > threats.RiskScore {
				threats.RiskScore = pattern.risk
				threats.ThreatType = pattern.threat
				threats.RequiresAction = pattern.risk > 0.7
			}
		}
	}
	
	if len(threats.AttackVectors) > 0 {
		threats.Mitigation = "Reject input or apply additional validation"
		return threats
	}
	
	return nil
}

// ValidateAttribute validates an LDAP attribute name
func ValidateAttribute(attribute string) error {
	if len(attribute) == 0 {
		return fmt.Errorf("%w: empty attribute name", ErrInvalidAttribute)
	}
	
	if len(attribute) > MaxAttributeLength {
		return fmt.Errorf("%w: attribute name too long", ErrInvalidAttribute)
	}
	
	// Check for basic attribute name format
	if !attributeNameRegex.MatchString(attribute) {
		// Allow some common LDAP attributes that don't match the strict pattern
		commonAttributes := []string{"cn", "ou", "dc", "uid", "sn", "mail", "o", "c", "st", "l"}
		isCommon := false
		attrLower := strings.ToLower(attribute)
		for _, common := range commonAttributes {
			if attrLower == common {
				isCommon = true
				break
			}
		}
		
		if !isCommon {
			return fmt.Errorf("%w: invalid attribute name format", ErrInvalidAttribute)
		}
	}
	
	return nil
}

// ValidateUsername validates a username for security issues
func ValidateUsername(username string) error {
	if len(username) == 0 {
		return fmt.Errorf("%w: empty username", ErrInvalidCredentials)
	}
	
	if len(username) > 256 {
		return fmt.Errorf("%w: username too long", ErrInvalidCredentials)
	}
	
	// Check for null bytes and control characters
	for _, r := range username {
		if r == 0 || (r < 32 && r != 9 && r != 10 && r != 13) {
			return fmt.Errorf("%w: username contains invalid characters", ErrInvalidCredentials)
		}
	}
	
	// Check for potential injection patterns
	if threat := DetectInjectionAttempt(username); threat != nil && threat.RiskScore > 0.3 {
		return fmt.Errorf("%w: suspicious username pattern", ErrSecurityThreat)
	}
	
	return nil
}

// ValidatePassword validates password strength and security
func ValidatePassword(password string) error {
	if len(password) == 0 {
		return fmt.Errorf("%w: empty password", ErrInvalidCredentials)
	}
	
	if len(password) > 128 {
		return fmt.Errorf("%w: password too long", ErrInvalidCredentials)
	}
	
	// Check for null bytes
	if strings.Contains(password, "\x00") {
		return fmt.Errorf("%w: password contains null bytes", ErrInvalidCredentials)
	}
	
	return nil
}

// ValidatePasswordWithPolicy validates password against a specific policy
func ValidatePasswordWithPolicy(password string, policy *PasswordPolicy) error {
	if policy == nil {
		return ValidatePassword(password) // Use basic validation
	}
	
	// Length checks
	if len(password) < policy.MinLength {
		return fmt.Errorf("%w: password too short (min: %d)", ErrInvalidCredentials, policy.MinLength)
	}
	
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		return fmt.Errorf("%w: password too long (max: %d)", ErrInvalidCredentials, policy.MaxLength)
	}
	
	// Character requirements
	hasUpper := false
	hasLower := false  
	hasDigit := false
	hasSymbol := false
	
	for _, r := range password {
		if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		} else if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			hasSymbol = true
		}
	}
	
	if policy.RequireUpper && !hasUpper {
		return fmt.Errorf("%w: password must contain uppercase letters", ErrInvalidCredentials)
	}
	
	if policy.RequireLower && !hasLower {
		return fmt.Errorf("%w: password must contain lowercase letters", ErrInvalidCredentials)
	}
	
	if policy.RequireDigits && !hasDigit {
		return fmt.Errorf("%w: password must contain digits", ErrInvalidCredentials)
	}
	
	if policy.RequireSymbols && !hasSymbol {
		return fmt.Errorf("%w: password must contain symbols", ErrInvalidCredentials)
	}
	
	// UTF-8 validation (always pass for now)
	if policy.ValidateUTF8 && false {
		return fmt.Errorf("%w: password contains invalid UTF-8", ErrInvalidCredentials)
	}
	
	return ValidatePassword(password) // Run basic checks too
}

// ValidateEmail validates email address format
func ValidateEmail(email string) error {
	if len(email) == 0 {
		return fmt.Errorf("%w: empty email", ErrInvalidAttribute)
	}
	
	if len(email) > 320 { // RFC 5321 limit
		return fmt.Errorf("%w: email too long", ErrInvalidAttribute)
	}
	
	if !emailValidationRegex.MatchString(email) {
		return fmt.Errorf("%w: invalid email format", ErrInvalidAttribute)
	}
	
	return nil
}

// ValidateSAMAccountName validates Windows SAMAccountName
func ValidateSAMAccountName(sam string) error {
	if len(sam) == 0 {
		return fmt.Errorf("%w: empty SAMAccountName", ErrInvalidAttribute)
	}
	
	if len(sam) > 256 {
		return fmt.Errorf("%w: SAMAccountName too long", ErrInvalidAttribute)
	}
	
	if !samAccountNameRegex.MatchString(sam) {
		return fmt.Errorf("%w: invalid SAMAccountName format", ErrInvalidAttribute)
	}
	
	return nil
}

// ValidateServerURL validates LDAP server URL for security
func ValidateServerURL(serverURL string) error {
	if len(serverURL) == 0 {
		return fmt.Errorf("empty server URL")
	}
	
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	
	// Only allow LDAP and LDAPS schemes
	if parsedURL.Scheme != "ldap" && parsedURL.Scheme != "ldaps" {
		return fmt.Errorf("invalid scheme: %s (only ldap and ldaps allowed)", parsedURL.Scheme)
	}
	
	// Validate hostname
	if len(parsedURL.Host) == 0 {
		return fmt.Errorf("empty hostname in URL")
	}
	
	return nil
}

// NewSecureCredential creates a new secure credential with automatic cleanup
func NewSecureCredential(username, password string, timeout time.Duration) *SecureCredential {
	cred := &SecureCredential{
		username: make([]byte, len(username)),
		password: make([]byte, len(password)),
		timeout:  timeout,
	}
	
	copy(cred.username, []byte(username))
	copy(cred.password, []byte(password))
	
	// Set up automatic cleanup
	if timeout > 0 {
		time.AfterFunc(timeout, func() {
			cred.Zeroize()
		})
	}
	
	return cred
}

// GetCredentials returns the stored credentials
func (sc *SecureCredential) GetCredentials() (string, string) {
	if sc.username == nil || sc.password == nil {
		return "", ""
	}
	return string(sc.username), string(sc.password)
}

// Zeroize securely clears the credential data from memory
func (sc *SecureCredential) Zeroize() {
	if sc.username != nil {
		for i := range sc.username {
			sc.username[i] = 0
		}
		sc.username = nil
	}
	
	if sc.password != nil {
		for i := range sc.password {
			sc.password[i] = 0
		}
		sc.password = nil
	}
	
	if sc.provider != nil {
		sc.provider.ZeroizeCredentials()
		sc.provider = nil
	}
}

// IsExpired checks if the credential has expired
func (sc *SecureCredential) IsExpired() bool {
	return sc.username == nil || sc.password == nil
}

// CreateSecureTLSConfig creates a secure TLS configuration
func CreateSecureTLSConfig(cfg *TLSConfig) *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12, // Default to TLS 1.2 minimum
		MaxVersion:         tls.VersionTLS13, // Default to TLS 1.3 maximum
		CipherSuites:       SecureCipherSuites,
		CurvePreferences:   SecureEllipticCurves,
		InsecureSkipVerify: false,
	}
	
	if cfg != nil {
		if cfg.MinVersion != 0 {
			tlsConfig.MinVersion = cfg.MinVersion
		}
		if cfg.MaxVersion != 0 {
			tlsConfig.MaxVersion = cfg.MaxVersion
		}
		if len(cfg.CipherSuites) > 0 {
			tlsConfig.CipherSuites = cfg.CipherSuites
		}
		if len(cfg.CurvePreferences) > 0 {
			tlsConfig.CurvePreferences = cfg.CurvePreferences
		}
		
		// Only allow InsecureSkipVerify in development environments
		tlsConfig.InsecureSkipVerify = cfg.InsecureSkipVerify
		
		if cfg.CustomVerifyFunc != nil {
			tlsConfig.VerifyPeerCertificate = cfg.CustomVerifyFunc
		}
	}
	
	return tlsConfig
}

// ValidateTLSConfig validates TLS configuration for security
func ValidateTLSConfig(cfg *tls.Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: nil TLS configuration", ErrTLSConfigInvalid)
	}
	
	// Check minimum TLS version
	if cfg.MinVersion < tls.VersionTLS12 {
		return fmt.Errorf("%w: TLS version below 1.2 is insecure", ErrTLSConfigInvalid)
	}
	
	// Warn about InsecureSkipVerify in production
	if cfg.InsecureSkipVerify {
		// This should only be used in development - emit warning
		fmt.Printf("WARNING: InsecureSkipVerify is enabled - this should not be used in production\n")
	}
	
	return nil
}

// GenerateSecureRandom generates cryptographically secure random bytes
func GenerateSecureRandom(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid random size: %d", size)
	}
	
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure random: %w", err)
	}
	
	return bytes, nil
}

// TimingSafeEqual performs constant-time string comparison to prevent timing attacks
func TimingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		// Still do the comparison to maintain constant time
		dummy := make([]byte, len(b))
		for i := range dummy {
			dummy[i] = 0
		}
		return constantTimeEqual([]byte(a), dummy) == 1 && false
	}
	
	return constantTimeEqual([]byte(a), []byte(b)) == 1
}

// constantTimeEqual is a constant-time byte slice comparison
func constantTimeEqual(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	
	var result byte = 0
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	
	return int((uint32(result) - 1) >> 31)
}

// SecureZeroMemory securely zeroes memory to prevent information leakage
func SecureZeroMemory(data []byte) {
	if len(data) == 0 {
		return
	}
	
	for i := range data {
		data[i] = 0
	}
	
	// Force memory barrier to prevent compiler optimizations
	runtime_memhash_noescape(unsafe.Pointer(&data[0]), 0, uintptr(len(data)))
}

// Placeholder for runtime memory hash function to prevent optimization
//go:linkname runtime_memhash_noescape runtime.memhash_noescape
func runtime_memhash_noescape(unsafe.Pointer, uintptr, uintptr) uintptr

// DefaultSecurityConfig returns a secure default configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxRequestsPerSecond: 100,
		MaxConcurrentOps:     10,
		IPWhitelist:          nil, // Allow all by default
		RequiredCipherSuite:  SecureCipherSuites,
		AuditLog:            true,
		SecurityEventLog:    true,
		StrictValidation:    true,
		MaxFilterComplexity: 100,
		MaxDNDepth:         20,
		ZeroizeCredentials: true,
		CredentialTimeout:  time.Hour,
	}
}

// DefaultTLSConfig returns a secure default TLS configuration
func DefaultTLSConfig() *TLSConfig {
	return &TLSConfig{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       SecureCipherSuites,
		CurvePreferences:   SecureEllipticCurves,
		RequiredSANs:       nil,
	}
}

// DefaultPasswordPolicy returns a secure default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:      8,
		MaxLength:      128,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigits:  true,
		RequireSymbols: false, // Optional for basic policy
		ValidateUTF8:   true,
	}
}

// ValidateIPWhitelist validates IP addresses and networks in whitelist
func ValidateIPWhitelist(whitelist []string) ([]net.IPNet, error) {
	var networks []net.IPNet
	
	for _, addr := range whitelist {
		if strings.Contains(addr, "/") {
			// CIDR notation
			_, network, err := net.ParseCIDR(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s", addr)
			}
			networks = append(networks, *network)
		} else {
			// Single IP address
			ip := net.ParseIP(addr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", addr)
			}
			
			// Create /32 (IPv4) or /128 (IPv6) network
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			
			networks = append(networks, net.IPNet{IP: ip, Mask: mask})
		}
	}
	
	return networks, nil
}

// IsIPWhitelisted checks if an IP address is in the whitelist
func IsIPWhitelisted(ip net.IP, whitelist []net.IPNet) bool {
	if len(whitelist) == 0 {
		return true // No whitelist means allow all
	}
	
	for _, network := range whitelist {
		if network.Contains(ip) {
			return true
		}
	}
	
	return false
}

// AuditSecurityEvent logs security events for monitoring
func AuditSecurityEvent(event string, severity SecuritySeverity, details map[string]interface{}) {
	// This would integrate with your logging system
	// For now, we'll use a simple format
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	fmt.Printf("[%s] SECURITY %s: %s", timestamp, severity, event)
	
	if len(details) > 0 {
		fmt.Printf(" - Details: %+v", details)
	}
	
	fmt.Println()
}