package ldap

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Constants for validation limits
const (
	// MaxValueLength defines the maximum length for attribute values
	MaxValueLength = 8192
)

// Note: MaxFilterLength and MaxDNLength are defined in security.go

// PasswordAnalysis contains analysis results for password strength
type PasswordAnalysis struct {
	Length     int     `json:"length"`
	Strength   float64 `json:"strength"`   // 0.0 to 1.0
	Entropy    float64 `json:"entropy"`    // Bits of entropy
	HasUpper   bool    `json:"has_upper"`  // Contains uppercase letters
	HasLower   bool    `json:"has_lower"`  // Contains lowercase letters
	HasDigit   bool    `json:"has_digit"`  // Contains digits
	HasSpecial bool    `json:"has_special"` // Contains special characters
}

// ValidationSummary contains aggregated validation results
type ValidationSummary struct {
	TotalChecks       int                  `json:"total_checks"`
	PassedChecks      int                  `json:"passed_checks"`
	FailedChecks      int                  `json:"failed_checks"`
	OverallValid      bool                 `json:"overall_valid"`
	SecurityScore     float64              `json:"security_score"`    // 0.0 to 1.0
	Recommendations   []string             `json:"recommendations"`
	Results           []*ValidationResult  `json:"results"`
	GeneratedAt       time.Time            `json:"generated_at"`
}

// ValidationConfig contains configuration for input validation
type ValidationConfig struct {
	// Enable strict validation mode
	StrictMode bool `json:"strict_mode"`

	// Maximum lengths for various inputs
	MaxDNLength        int `json:"max_dn_length"`
	MaxFilterLength    int `json:"max_filter_length"`
	MaxAttributeLength int `json:"max_attribute_length"`
	MaxValueLength     int `json:"max_value_length"`

	// Allow lists for various inputs
	AllowedAttributes    []string `json:"allowed_attributes"`
	AllowedObjectClasses []string `json:"allowed_object_classes"`

	// Custom validation patterns
	CustomDNPattern        *regexp.Regexp `json:"-"`
	CustomAttributePattern *regexp.Regexp `json:"-"`

	// Security settings
	BlockSuspiciousPatterns bool `json:"block_suspicious_patterns"`
	ValidateUTF8            bool `json:"validate_utf8"`
	NormalizeInput          bool `json:"normalize_input"`
}

// ThreatContext contains information about potential security threats detected during validation
type ThreatContext struct {
	// Level of threat detected
	ThreatLevel string `json:"threat_level"` // low, medium, high, critical

	// List of specific threats detected
	DetectedThreats []string `json:"detected_threats"`

	// Source IP if available
	SourceIP string `json:"source_ip,omitempty"`

	// Confidence level in threat detection (0.0-1.0)
	Confidence float64 `json:"confidence"`

	// Recommended action
	RecommendedAction string `json:"recommended_action"` // allow, warn, block, escalate

	// Risk score for the threat (0.0-1.0)
	RiskScore float64 `json:"risk_score"`

	// Additional metadata about the threat
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ValidationResult contains the result of input validation
type ValidationResult struct {
	Valid           bool                   `json:"valid"`
	NormalizedInput string                 `json:"normalized_input"`
	Warnings        []string               `json:"warnings"`
	Errors          []string               `json:"errors"`
	ThreatContext   *ThreatContext         `json:"threat_context,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// Validator provides comprehensive input validation for LDAP operations
type Validator struct {
	config *ValidationConfig
}

// DefaultValidationConfig returns a ValidationConfig with sensible defaults
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		StrictMode:              false,
		MaxDNLength:             MaxDNLength,     // Use constant from security.go
		MaxFilterLength:         MaxFilterLength, // Use constant from security.go
		MaxAttributeLength:      256,
		MaxValueLength:          MaxValueLength,
		AllowedAttributes:       []string{}, // Empty means allow all
		AllowedObjectClasses:    []string{}, // Empty means allow all
		BlockSuspiciousPatterns: true,
		ValidateUTF8:            true,
		NormalizeInput:          true,
	}
}

// NewValidator creates a new validator with the given configuration
func NewValidator(config *ValidationConfig) *Validator {
	if config == nil {
		config = DefaultValidationConfig()
	}
	return &Validator{config: config}
}

// ValidateDNSyntax validates a distinguished name syntax - alias for ValidateDN for compatibility
func (v *Validator) ValidateDNSyntax(dn string) *ValidationResult {
	result := v.ValidateDN(dn)

	// Add component count to metadata
	if result.Valid {
		components := strings.Split(strings.ReplaceAll(dn, " ", ""), ",")
		result.Metadata["component_count"] = len(components)
	}

	return result
}

// ValidateDN validates a distinguished name
func (v *Validator) ValidateDN(dn string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
		Metadata: make(map[string]interface{}),
	}

	// Check length
	if len(dn) > v.config.MaxDNLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("DN exceeds maximum length of %d characters", v.config.MaxDNLength))
	}

	// Check for empty DN
	if strings.TrimSpace(dn) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "DN cannot be empty")
		return result
	}

	// UTF-8 validation
	if v.config.ValidateUTF8 && !utf8.ValidString(dn) {
		result.Valid = false
		result.Errors = append(result.Errors, "DN contains invalid UTF-8 characters")
	}

	// Check for control characters
	for _, r := range dn {
		if unicode.IsControl(r) {
			result.Valid = false
			result.Errors = append(result.Errors, "DN contains control characters")
			break
		}
	}

	// Normalize input
	normalizedDN := dn
	if v.config.NormalizeInput {
		normalizedDN = strings.TrimSpace(dn)
		// Additional normalization could be added here
	}
	result.NormalizedInput = normalizedDN

	// Check for suspicious patterns (only for injection patterns, not basic validation issues)
	if v.config.BlockSuspiciousPatterns {
		threats := v.detectInjectionThreats(dn)
		if len(threats.DetectedThreats) > 0 {
			result.ThreatContext = threats
			if threats.ThreatLevel == "high" || threats.ThreatLevel == "critical" {
				result.Valid = false
				result.Errors = append(result.Errors, "DN contains suspicious patterns")
			} else {
				result.Warnings = append(result.Warnings, "DN contains potentially suspicious patterns")
			}
		}
	}

	// Basic DN format validation
	if !v.isValidDNFormat(normalizedDN) {
		result.Valid = false
		result.Errors = append(result.Errors, "DN has invalid format")
	}

	return result
}

// ValidateFilter validates an LDAP search filter
func (v *Validator) ValidateFilter(filter string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
		Metadata: make(map[string]interface{}),
	}

	// Check length
	if len(filter) > v.config.MaxFilterLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Filter exceeds maximum length of %d characters", v.config.MaxFilterLength))
	}

	// Check for empty filter
	if strings.TrimSpace(filter) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Filter cannot be empty")
		return result
	}

	// UTF-8 validation
	if v.config.ValidateUTF8 && !utf8.ValidString(filter) {
		result.Valid = false
		result.Errors = append(result.Errors, "Filter contains invalid UTF-8 characters")
	}

	// Normalize input
	normalizedFilter := filter
	if v.config.NormalizeInput {
		normalizedFilter = strings.TrimSpace(filter)
	}
	result.NormalizedInput = normalizedFilter

	// Check for suspicious patterns
	if v.config.BlockSuspiciousPatterns {
		threats := v.detectInjectionThreats(filter)
		if len(threats.DetectedThreats) > 0 {
			result.ThreatContext = threats
			if threats.ThreatLevel == "high" || threats.ThreatLevel == "critical" {
				result.Valid = false
				result.Errors = append(result.Errors, "Filter contains suspicious patterns")
			} else {
				result.Warnings = append(result.Warnings, "Filter contains potentially suspicious patterns")
			}
		}
	}

	// Basic filter format validation
	if !v.isValidFilterFormat(normalizedFilter) {
		result.Valid = false
		result.Errors = append(result.Errors, "Filter has invalid format")
	}

	// Check complexity and add to metadata
	complexity := v.calculateFilterComplexity(normalizedFilter)
	result.Metadata["complexity"] = complexity

	// Fail if complexity is too high (threshold of 50 for very complex filters)
	if complexity > 50 {
		result.Valid = false
		result.Errors = append(result.Errors, "Filter too complex: maximum complexity exceeded")
	}

	return result
}


// ValidateCredentials validates username and password credentials
func (v *Validator) ValidateCredentials(username, password string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
		Metadata: make(map[string]interface{}),
	}

	// Validate username
	if strings.TrimSpace(username) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Username cannot be empty")
	}

	// Validate password
	if strings.TrimSpace(password) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Password cannot be empty")
	}

	// Check for reasonable length limits
	if len(username) > 255 {
		result.Valid = false
		result.Errors = append(result.Errors, "Username too long")
	}

	// UTF-8 validation
	if v.config.ValidateUTF8 {
		if !utf8.ValidString(username) {
			result.Valid = false
			result.Errors = append(result.Errors, "Username contains invalid UTF-8 characters")
		}
		if !utf8.ValidString(password) {
			result.Valid = false
			result.Errors = append(result.Errors, "Password contains invalid UTF-8 characters")
		}
	}

	// Check for control characters
	for _, r := range username {
		if unicode.IsControl(r) {
			result.Valid = false
			result.Errors = append(result.Errors, "Username contains control characters")
			break
		}
	}

	for _, r := range password {
		if unicode.IsControl(r) {
			result.Valid = false
			result.Errors = append(result.Errors, "Password contains control characters")
			break
		}
	}

	// Check for suspicious patterns in username
	if v.config.BlockSuspiciousPatterns {
		threats := v.detectInjectionThreats(username)
		if len(threats.DetectedThreats) > 0 {
			result.ThreatContext = threats
			if threats.ThreatLevel == "high" || threats.ThreatLevel == "critical" {
				result.Valid = false
				result.Errors = append(result.Errors, "Username contains suspicious patterns")
			}
		}
	}

	// Analyze password if credentials are valid so far
	if result.Valid {
		analysis := v.analyzePassword(password)
		result.Metadata["password_analysis"] = analysis
	}

	// Normalize inputs
	if v.config.NormalizeInput {
		result.NormalizedInput = strings.TrimSpace(username) + ":" + "[REDACTED]" // Don't expose password
	}

	return result
}

// ValidateAttribute validates an LDAP attribute name and value
func (v *Validator) ValidateAttribute(attributeName, attributeValue string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
		Metadata: make(map[string]interface{}),
	}

	// Check attribute name length
	if len(attributeName) > v.config.MaxAttributeLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Attribute name exceeds maximum length of %d characters", v.config.MaxAttributeLength))
	}

	// Check attribute value length
	if len(attributeValue) > v.config.MaxValueLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Attribute value exceeds maximum length of %d characters", v.config.MaxValueLength))
	}

	// Set metadata about value type early (even for invalid attribute names)
	result.Metadata["value_type"] = v.detectValueType(attributeValue)

	// Check for empty attribute name
	if strings.TrimSpace(attributeName) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Attribute name cannot be empty")
		return result
	}

	// UTF-8 validation
	if v.config.ValidateUTF8 {
		if !utf8.ValidString(attributeName) {
			result.Valid = false
			result.Errors = append(result.Errors, "Attribute name contains invalid UTF-8 characters")
		}
		if !utf8.ValidString(attributeValue) {
			result.Valid = false
			result.Errors = append(result.Errors, "Attribute value contains invalid UTF-8 characters")
		}
	}

	// Normalize inputs
	normalizedAttributeName := attributeName
	normalizedAttributeValue := attributeValue
	if v.config.NormalizeInput {
		normalizedAttributeName = strings.TrimSpace(attributeName)
		normalizedAttributeValue = strings.TrimSpace(attributeValue)
		// Special normalization for email addresses
		if strings.EqualFold(normalizedAttributeName, "mail") {
			normalizedAttributeValue = strings.ToLower(normalizedAttributeValue)
		}
	}
	result.NormalizedInput = normalizedAttributeValue

	// Check allowed attributes list
	if len(v.config.AllowedAttributes) > 0 {
		allowed := false
		for _, allowedAttr := range v.config.AllowedAttributes {
			if strings.EqualFold(normalizedAttributeName, allowedAttr) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Valid = false
			result.Errors = append(result.Errors, "Attribute name is not in the allowed list")
		}
	}

	// Basic attribute name validation
	if !v.isValidAttributeName(normalizedAttributeName) {
		result.Valid = false
		result.Errors = append(result.Errors, "Attribute name has invalid format")
	}

	// Validate specific attribute types
	if result.Valid {
		v.validateSpecificAttributeValue(normalizedAttributeName, normalizedAttributeValue, result)
	}

	return result
}

// ValidateValue validates an LDAP attribute value
func (v *Validator) ValidateValue(value string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
		Metadata: make(map[string]interface{}),
	}

	// Check length
	if len(value) > v.config.MaxValueLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Value exceeds maximum length of %d characters", v.config.MaxValueLength))
	}

	// UTF-8 validation
	if v.config.ValidateUTF8 && !utf8.ValidString(value) {
		result.Valid = false
		result.Errors = append(result.Errors, "Value contains invalid UTF-8 characters")
	}

	// Normalize input
	normalizedValue := value
	if v.config.NormalizeInput {
		normalizedValue = strings.TrimSpace(value)
	}
	result.NormalizedInput = normalizedValue

	// Check for suspicious patterns
	if v.config.BlockSuspiciousPatterns {
		threats := v.detectThreats(value)
		if len(threats.DetectedThreats) > 0 {
			result.ThreatContext = threats
			if threats.ThreatLevel == "high" || threats.ThreatLevel == "critical" {
				result.Valid = false
				result.Errors = append(result.Errors, "Value contains suspicious patterns")
			} else {
				result.Warnings = append(result.Warnings, "Value contains potentially suspicious patterns")
			}
		}
	}

	return result
}

// detectThreats analyzes input for potential security threats
func (v *Validator) detectThreats(input string) *ThreatContext {
	threats := &ThreatContext{
		ThreatLevel:       "low",
		DetectedThreats:   []string{},
		Confidence:        0.0,
		RecommendedAction: "allow",
		Metadata:          make(map[string]interface{}),
	}

	lowercaseInput := strings.ToLower(input)

	// Check for injection patterns
	injectionPatterns := []string{
		"*)(cn=*",
		"*)(objectclass=*",
		")(&(objectclass=*",
		"*)(|(cn=*",
		"script:",
		"javascript:",
		"eval(",
		"exec(",
	}

	for _, pattern := range injectionPatterns {
		if strings.Contains(lowercaseInput, pattern) {
			threats.DetectedThreats = append(threats.DetectedThreats, "ldap_injection")
			threats.ThreatLevel = "high"
			threats.Confidence = 0.8
			threats.RecommendedAction = "block"
			break
		}
	}

	// Check for dangerous control characters (null bytes and other problematic ones)
	for _, r := range input {
		if r == '\x00' || (unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r') {
			threats.DetectedThreats = append(threats.DetectedThreats, "control_characters")
			if threats.ThreatLevel == "low" {
				threats.ThreatLevel = "medium"
				threats.Confidence = 0.5
				threats.RecommendedAction = "warn"
			}
			break
		}
	}

	// Check for excessive length (potential DoS)
	if len(input) > 10000 {
		threats.DetectedThreats = append(threats.DetectedThreats, "excessive_length")
		threats.ThreatLevel = "medium"
		threats.Confidence = 0.6
		threats.RecommendedAction = "warn"
	}

	// Set risk score based on threat level
	switch threats.ThreatLevel {
	case "low":
		threats.RiskScore = 0.2
	case "medium":
		threats.RiskScore = 0.5
	case "high":
		threats.RiskScore = 0.8
	case "critical":
		threats.RiskScore = 1.0
	default:
		threats.RiskScore = 0.0
	}

	return threats
}

// detectInjectionThreats analyzes input for injection-specific threats only
func (v *Validator) detectInjectionThreats(input string) *ThreatContext {
	threats := &ThreatContext{
		ThreatLevel:       "low",
		DetectedThreats:   []string{},
		Confidence:        0.0,
		RecommendedAction: "allow",
		Metadata:          make(map[string]interface{}),
	}

	lowercaseInput := strings.ToLower(input)

	// Check for injection patterns only
	injectionPatterns := []string{
		"*)(cn=*",
		"*)(objectclass=*",
		")(&(objectclass=*",
		"*)(|(cn=*",
		"script:",
		"javascript:",
		"eval(",
		"exec(",
	}

	for _, pattern := range injectionPatterns {
		if strings.Contains(lowercaseInput, pattern) {
			threats.DetectedThreats = append(threats.DetectedThreats, "ldap_injection")
			threats.ThreatLevel = "high"
			threats.Confidence = 0.8
			threats.RecommendedAction = "block"
			break
		}
	}

	// Set risk score based on threat level
	switch threats.ThreatLevel {
	case "low":
		threats.RiskScore = 0.2
	case "medium":
		threats.RiskScore = 0.5
	case "high":
		threats.RiskScore = 0.8
	case "critical":
		threats.RiskScore = 1.0
	default:
		threats.RiskScore = 0.0
	}

	return threats
}

// isValidDNFormat checks if the DN has a valid format
func (v *Validator) isValidDNFormat(dn string) bool {
	// Basic DN format check - should contain at least one "=" and proper structure
	if !strings.Contains(dn, "=") {
		return false
	}

	// Check for empty components (double commas)
	if strings.Contains(dn, ",,") {
		return false
	}

	// Check for balanced quotes
	quoteCount := strings.Count(dn, "\"")
	if quoteCount%2 != 0 {
		return false
	}

	// Additional custom pattern validation
	if v.config.CustomDNPattern != nil {
		return v.config.CustomDNPattern.MatchString(dn)
	}

	return true
}

// isValidFilterFormat checks if the filter has a valid format
func (v *Validator) isValidFilterFormat(filter string) bool {
	// Basic filter format check - should be enclosed in parentheses
	filter = strings.TrimSpace(filter)
	if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") {
		return false
	}

	// Check for balanced parentheses
	openCount := strings.Count(filter, "(")
	closeCount := strings.Count(filter, ")")
	if openCount != closeCount {
		return false
	}

	return true
}

// isValidAttributeName checks if the attribute name has a valid format
func (v *Validator) isValidAttributeName(attribute string) bool {
	// Basic attribute name validation - should start with letter, contain only letters, digits, hyphens
	if len(attribute) == 0 {
		return false
	}

	// First character should be a letter
	if !unicode.IsLetter(rune(attribute[0])) {
		return false
	}

	// Rest can be letters, digits, or hyphens
	for _, r := range attribute[1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
	}

	// Additional custom pattern validation
	if v.config.CustomAttributePattern != nil {
		return v.config.CustomAttributePattern.MatchString(attribute)
	}

	return true
}

// ValidateIPAddress validates an IP address
func ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateEmailFormat validates an email address format
func ValidateEmailFormat(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// SanitizeDN sanitizes a DN by removing or escaping dangerous characters
func SanitizeDN(dn string) string {
	// Basic sanitization - can be extended based on requirements
	sanitized := strings.TrimSpace(dn)

	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")

	// Remove other control characters except tab, newline, carriage return
	var result strings.Builder
	for _, r := range sanitized {
		if !unicode.IsControl(r) || r == '\t' || r == '\n' || r == '\r' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// SanitizeFilter sanitizes an LDAP filter by removing or escaping dangerous characters
func SanitizeFilter(filter string) string {
	// Basic sanitization for LDAP filters
	sanitized := strings.TrimSpace(filter)

	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")

	// Escape special LDAP characters
	replacements := map[string]string{
		"\\": "\\5c",
		"*":  "\\2a",
		"(":  "\\28",
		")":  "\\29",
		"\x00": "\\00",
	}

	for old, new := range replacements {
		sanitized = strings.ReplaceAll(sanitized, old, new)
	}

	return sanitized
}

// analyzePassword performs comprehensive password analysis
func (v *Validator) analyzePassword(password string) *PasswordAnalysis {
	analysis := &PasswordAnalysis{
		Length: len(password),
	}

	if len(password) == 0 {
		return analysis
	}

	// Character type analysis
	for _, r := range password {
		if unicode.IsUpper(r) {
			analysis.HasUpper = true
		} else if unicode.IsLower(r) {
			analysis.HasLower = true
		} else if unicode.IsDigit(r) {
			analysis.HasDigit = true
		} else if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			analysis.HasSpecial = true
		}
	}

	// Calculate entropy (simplified Shannon entropy)
	analysis.Entropy = v.calculatePasswordEntropy(password)

	// Calculate strength score (0.0 to 1.0)
	analysis.Strength = v.calculatePasswordStrength(password, analysis)

	return analysis
}

// calculatePasswordEntropy calculates the entropy of a password
func (v *Validator) calculatePasswordEntropy(password string) float64 {
	if len(password) == 0 {
		return 0.0
	}

	// Count frequency of each character
	freq := make(map[rune]int)
	for _, r := range password {
		freq[r]++
	}

	// Calculate Shannon entropy
	var entropy float64
	passwordLength := float64(len(password))
	for _, count := range freq {
		p := float64(count) / passwordLength
		entropy -= p * math.Log2(p)
	}

	return entropy * passwordLength / math.Log2(float64(len(freq)))
}

// calculatePasswordStrength calculates password strength score
func (v *Validator) calculatePasswordStrength(password string, analysis *PasswordAnalysis) float64 {
	var score float64

	// Length component (up to 0.35 points)
	lengthScore := math.Min(float64(analysis.Length)/10.0, 1.0) * 0.35
	score += lengthScore

	// Character diversity (up to 0.45 points)
	diversityScore := 0.0
	if analysis.HasLower {
		diversityScore += 0.1
	}
	if analysis.HasUpper {
		diversityScore += 0.1
	}
	if analysis.HasDigit {
		diversityScore += 0.125
	}
	if analysis.HasSpecial {
		diversityScore += 0.125
	}
	score += diversityScore

	// Entropy component (up to 0.2 points)
	entropyScore := math.Min(analysis.Entropy/40.0, 1.0) * 0.2
	score += entropyScore

	// Penalize common patterns - less harsh for longer passwords
	lowerPassword := strings.ToLower(password)
	commonPatterns := []string{"password", "123456", "qwerty", "admin", "letmein"}
	for _, pattern := range commonPatterns {
		if strings.Contains(lowerPassword, pattern) {
			// Scale penalty based on password length - longer passwords get less penalty
			penaltyFactor := 0.5 + (float64(len(password)) * 0.05) // 0.5 base + 0.05 per character
			if penaltyFactor > 0.8 {
				penaltyFactor = 0.8 // Cap at 80% of original score
			}
			score *= penaltyFactor
			break
		}
	}

	return math.Min(score, 1.0)
}

// detectValueType detects the type of a value
func (v *Validator) detectValueType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "empty"
	}

	// Check for IP address
	if ValidateIPAddress(value) {
		return "ip_address"
	}

	// Check for email
	if ValidateEmailFormat(value) {
		return "email"
	}

	// Check for DN
	if strings.Contains(value, "=") && strings.Contains(value, "DC=") {
		return "dn"
	}

	// Check for integer
	if _, err := strconv.Atoi(value); err == nil {
		return "integer"
	}

	// Check for float
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return "float"
	}

	// Check for date (ISO format)
	if matched, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2}$`, value); matched {
		return "date"
	}

	// Check for datetime (ISO format)
	if matched, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`, value); matched {
		return "datetime"
	}

	return "string"
}

// validateSpecificAttributeValue validates attribute values based on their names
func (v *Validator) validateSpecificAttributeValue(attrName, attrValue string, result *ValidationResult) {
	lowerAttrName := strings.ToLower(attrName)

	switch lowerAttrName {
	case "mail":
		if !ValidateEmailFormat(attrValue) {
			result.Valid = false
			result.Errors = append(result.Errors, "Invalid email format")
		}
	case "samaccountname":
		// SAM account name validation
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, attrValue); !matched {
			result.Valid = false
			result.Errors = append(result.Errors, "Invalid SAM account name format")
		}
	case "telephonenumber":
		// Phone number validation (basic)
		if matched, _ := regexp.MatchString(`^\+?[0-9\s\-\.\(\)]+$`, attrValue); !matched {
			result.Valid = false
			result.Errors = append(result.Errors, "Invalid phone number format")
		}
	case "postalcode":
		// Postal code validation (basic)
		if matched, _ := regexp.MatchString(`^[0-9A-Za-z\s\-]+$`, attrValue); !matched {
			result.Valid = false
			result.Errors = append(result.Errors, "Invalid postal code format")
		}
	case "useraccountcontrol":
		// User account control should be numeric
		if _, err := strconv.Atoi(attrValue); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, "User account control must be numeric")
		}
	}
}

// calculateFilterComplexity calculates the complexity score of an LDAP filter
func (v *Validator) calculateFilterComplexity(filter string) int {
	complexity := 0

	// Count parentheses (each pair adds complexity)
	complexity += strings.Count(filter, "(")

	// Count logical operators
	complexity += strings.Count(filter, "&")
	complexity += strings.Count(filter, "|")
	complexity += strings.Count(filter, "!")

	// Count wildcards
	complexity += strings.Count(filter, "*")

	return complexity
}

// CreateValidationSummary creates a summary from multiple validation results
func CreateValidationSummary(results []*ValidationResult) *ValidationSummary {
	summary := &ValidationSummary{
		TotalChecks:     len(results),
		Results:         results,
		GeneratedAt:     time.Now(),
		Recommendations: []string{},
	}

	// Count passed/failed
	for _, result := range results {
		if result.Valid {
			summary.PassedChecks++
		} else {
			summary.FailedChecks++
		}
	}

	// Overall validity
	summary.OverallValid = summary.FailedChecks == 0

	// Calculate security score
	if summary.TotalChecks > 0 {
		baseScore := float64(summary.PassedChecks) / float64(summary.TotalChecks)

		// Adjust for threat contexts
		threatPenalty := 0.0
		for _, result := range results {
			if result.ThreatContext != nil {
				threatPenalty += result.ThreatContext.RiskScore * 0.1
			}
		}

		summary.SecurityScore = math.Max(0.0, baseScore-threatPenalty)
	} else {
		summary.SecurityScore = 1.0
	}

	// Generate recommendations
	if summary.FailedChecks > 0 {
		summary.Recommendations = append(summary.Recommendations, "Review and fix validation errors")
	}
	if summary.SecurityScore < 0.8 {
		summary.Recommendations = append(summary.Recommendations, "Improve input security validation")
	}
	for _, result := range results {
		if result.ThreatContext != nil && result.ThreatContext.RiskScore > 0.5 {
			summary.Recommendations = append(summary.Recommendations, "Address security threats in inputs")
			break
		}
	}

	return summary
}


