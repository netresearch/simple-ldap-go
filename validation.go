package ldap

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

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
		MaxDNLength:             1024,
		MaxFilterLength:         4096,
		MaxAttributeLength:      256,
		MaxValueLength:          8192,
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

	// Normalize input
	normalizedDN := dn
	if v.config.NormalizeInput {
		normalizedDN = strings.TrimSpace(dn)
		// Additional normalization could be added here
	}
	result.NormalizedInput = normalizedDN

	// Check for suspicious patterns
	if v.config.BlockSuspiciousPatterns {
		threats := v.detectThreats(dn)
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
		threats := v.detectThreats(filter)
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

	return result
}

// ValidateAttribute validates an LDAP attribute name
func (v *Validator) ValidateAttribute(attribute string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
		Metadata: make(map[string]interface{}),
	}

	// Check length
	if len(attribute) > v.config.MaxAttributeLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Attribute name exceeds maximum length of %d characters", v.config.MaxAttributeLength))
	}

	// Check for empty attribute
	if strings.TrimSpace(attribute) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Attribute name cannot be empty")
		return result
	}

	// UTF-8 validation
	if v.config.ValidateUTF8 && !utf8.ValidString(attribute) {
		result.Valid = false
		result.Errors = append(result.Errors, "Attribute name contains invalid UTF-8 characters")
	}

	// Normalize input
	normalizedAttribute := attribute
	if v.config.NormalizeInput {
		normalizedAttribute = strings.TrimSpace(attribute)
	}
	result.NormalizedInput = normalizedAttribute

	// Check allowed attributes list
	if len(v.config.AllowedAttributes) > 0 {
		allowed := false
		for _, allowedAttr := range v.config.AllowedAttributes {
			if strings.EqualFold(normalizedAttribute, allowedAttr) {
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
	if !v.isValidAttributeName(normalizedAttribute) {
		result.Valid = false
		result.Errors = append(result.Errors, "Attribute name has invalid format")
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

	// Check for control characters
	for _, r := range input {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
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

	return threats
}

// isValidDNFormat checks if the DN has a valid format
func (v *Validator) isValidDNFormat(dn string) bool {
	// Basic DN format check - should contain at least one "=" and proper structure
	if !strings.Contains(dn, "=") {
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