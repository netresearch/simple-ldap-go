package ldap

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
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
	CustomDNPattern       *regexp.Regexp `json:"-"`
	CustomAttributePattern *regexp.Regexp `json:"-"`
	
	// Security settings
	BlockSuspiciousPatterns bool `json:"block_suspicious_patterns"`
	ValidateUTF8           bool `json:"validate_utf8"`
	NormalizeInput         bool `json:"normalize_input"`
}

// ValidationResult contains the result of input validation
type ValidationResult struct {
	Valid         bool                   `json:"valid"`
	NormalizedInput string               `json:"normalized_input"`
	Warnings      []string               `json:"warnings"`
	Errors        []string               `json:"errors"`
	ThreatContext *ThreatContext         `json:"threat_context,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// Validator provides comprehensive input validation for LDAP operations
type Validator struct {
	config *ValidationConfig
}

// NewValidator creates a new validator with the specified configuration
func NewValidator(config *ValidationConfig) *Validator {
	if config == nil {
		config = DefaultValidationConfig()
	}
	return &Validator{config: config}
}

// DefaultValidationConfig returns a secure default validation configuration
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		StrictMode:              true,
		MaxDNLength:            8192,
		MaxFilterLength:        4096,
		MaxAttributeLength:     1024,
		MaxValueLength:         65536,
		BlockSuspiciousPatterns: true,
		ValidateUTF8:           true,
		NormalizeInput:         true,
		AllowedAttributes: []string{
			// Common LDAP attributes
			"cn", "sn", "givenName", "displayName", "description", "mail",
			"telephoneNumber", "userPrincipalName", "sAMAccountName",
			"objectClass", "objectCategory", "distinguishedName",
			"memberOf", "member", "uniqueMember", "groupType",
			// Active Directory attributes
			"userAccountControl", "accountExpires", "lastLogon",
			"pwdLastSet", "lockoutTime", "badPwdCount",
			// Computer attributes
			"dNSHostName", "operatingSystem", "operatingSystemVersion",
			"servicePrincipalName", "msDS-SupportedEncryptionTypes",
		},
		AllowedObjectClasses: []string{
			"user", "person", "inetOrgPerson", "organizationalPerson",
			"group", "computer", "organizationalUnit", "domain",
			"container", "builtinDomain", "configuration",
		},
	}
}

// ValidateDNSyntax performs comprehensive DN validation
func (v *Validator) ValidateDNSyntax(dn string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
		Metadata: make(map[string]interface{}),
	}
	
	// Basic checks
	if len(dn) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "DN cannot be empty")
		return result
	}
	
	// Length validation
	if len(dn) > v.config.MaxDNLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("DN exceeds maximum length (%d > %d)", len(dn), v.config.MaxDNLength))
		return result
	}
	
	// UTF-8 validation
	if v.config.ValidateUTF8 && !utf8.ValidString(dn) {
		result.Valid = false
		result.Errors = append(result.Errors, "DN contains invalid UTF-8 sequences")
		return result
	}
	
	// Normalize input
	normalized := dn
	if v.config.NormalizeInput {
		normalized = v.normalizeDN(dn)
		result.NormalizedInput = normalized
	}
	
	// Security checks
	if v.config.BlockSuspiciousPatterns {
		threat := DetectInjectionAttempt(normalized)
		if threat != nil && threat.RiskScore > 0.5 {
			result.Valid = false
			result.ThreatContext = threat
			result.Errors = append(result.Errors, fmt.Sprintf("Suspicious pattern detected: %s", threat.ThreatType))
			return result
		} else if threat != nil {
			result.ThreatContext = threat
			result.Warnings = append(result.Warnings, fmt.Sprintf("Low-risk pattern detected: %s", threat.ThreatType))
		}
	}
	
	// Parse DN components
	components, err := v.parseDNComponents(normalized)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("DN parsing failed: %v", err))
		return result
	}
	
	result.Metadata["component_count"] = len(components)
	result.Metadata["components"] = components
	
	// Validate each component
	for i, component := range components {
		if err := v.validateDNComponent(component); err != nil {
			if v.config.StrictMode {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("Component %d invalid: %v", i, err))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Component %d warning: %v", i, err))
			}
		}
	}
	
	return result
}

// ValidateFilter performs comprehensive LDAP filter validation
func (v *Validator) ValidateFilter(filter string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
		Metadata: make(map[string]interface{}),
	}
	
	// Basic checks
	if len(filter) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "Filter cannot be empty")
		return result
	}
	
	// Length validation
	if len(filter) > v.config.MaxFilterLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Filter exceeds maximum length (%d > %d)", len(filter), v.config.MaxFilterLength))
		return result
	}
	
	// UTF-8 validation
	if v.config.ValidateUTF8 && !utf8.ValidString(filter) {
		result.Valid = false
		result.Errors = append(result.Errors, "Filter contains invalid UTF-8 sequences")
		return result
	}
	
	// Normalize input
	normalized := filter
	if v.config.NormalizeInput {
		normalized = v.normalizeFilter(filter)
		result.NormalizedInput = normalized
	}
	
	// Security checks
	if v.config.BlockSuspiciousPatterns {
		threat := DetectInjectionAttempt(normalized)
		if threat != nil && threat.RiskScore > 0.7 {
			result.Valid = false
			result.ThreatContext = threat
			result.Errors = append(result.Errors, fmt.Sprintf("High-risk injection pattern detected: %s", threat.ThreatType))
			return result
		} else if threat != nil && threat.RiskScore > 0.3 {
			result.ThreatContext = threat
			result.Warnings = append(result.Warnings, fmt.Sprintf("Suspicious pattern detected: %s", threat.ThreatType))
		}
	}
	
	// Structural validation
	if err := v.validateFilterStructure(normalized); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Filter structure invalid: %v", err))
		return result
	}
	
	// Parse and validate filter components
	complexity, attributes, err := v.analyzeFilter(normalized)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Filter analysis failed: %v", err))
		return result
	}
	
	result.Metadata["complexity"] = complexity
	result.Metadata["attributes"] = attributes
	result.Metadata["attribute_count"] = len(attributes)
	
	// Complexity check
	if complexity > 20 {
		if v.config.StrictMode {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Filter too complex (complexity: %d)", complexity))
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("High complexity filter (complexity: %d)", complexity))
		}
	}
	
	// Attribute validation
	if len(v.config.AllowedAttributes) > 0 {
		for _, attr := range attributes {
			if !v.isAllowedAttribute(attr) {
				if v.config.StrictMode {
					result.Valid = false
					result.Errors = append(result.Errors, fmt.Sprintf("Attribute not allowed: %s", attr))
				} else {
					result.Warnings = append(result.Warnings, fmt.Sprintf("Uncommon attribute used: %s", attr))
				}
			}
		}
	}
	
	return result
}

// ValidateAttribute performs comprehensive attribute validation
func (v *Validator) ValidateAttribute(name, value string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
		Metadata: make(map[string]interface{}),
	}
	
	// Validate attribute name
	if err := v.validateAttributeName(name); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid attribute name: %v", err))
		return result
	}
	
	// Validate attribute value
	if err := v.validateAttributeValue(name, value); err != nil {
		if v.config.StrictMode {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid attribute value: %v", err))
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Attribute value warning: %v", err))
		}
	}
	
	// Normalize value if requested
	if v.config.NormalizeInput {
		result.NormalizedInput = v.normalizeAttributeValue(name, value)
	}
	
	// Additional metadata
	result.Metadata["attribute_name"] = name
	result.Metadata["value_length"] = len(value)
	result.Metadata["value_type"] = v.detectValueType(value)
	
	return result
}

// ValidateCredentials performs credential validation with security checks
func (v *Validator) ValidateCredentials(username, password string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
		Metadata: make(map[string]interface{}),
	}
	
	// Validate username
	if len(username) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "Username cannot be empty")
		return result
	}
	
	// Username length check
	if len(username) > 256 {
		result.Valid = false
		result.Errors = append(result.Errors, "Username too long (max 256 characters)")
		return result
	}
	
	// Validate password
	if len(password) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "Password cannot be empty")
		return result
	}
	
	// UTF-8 validation
	if v.config.ValidateUTF8 {
		if !utf8.ValidString(username) {
			result.Valid = false
			result.Errors = append(result.Errors, "Username contains invalid UTF-8 sequences")
		}
		if !utf8.ValidString(password) {
			result.Valid = false
			result.Errors = append(result.Errors, "Password contains invalid UTF-8 sequences")
		}
	}
	
	// Security checks on username
	if v.config.BlockSuspiciousPatterns {
		threat := DetectInjectionAttempt(username)
		if threat != nil && threat.RiskScore > 0.3 {
			result.Valid = false
			result.ThreatContext = threat
			result.Errors = append(result.Errors, fmt.Sprintf("Suspicious username pattern: %s", threat.ThreatType))
			return result
		}
	}
	
	// Check for control characters
	for _, r := range username {
		if unicode.IsControl(r) && r != '\t' {
			result.Valid = false
			result.Errors = append(result.Errors, "Username contains control characters")
			break
		}
	}
	
	// Password security analysis (metadata only)
	passwordAnalysis := v.analyzePassword(password)
	result.Metadata["password_analysis"] = passwordAnalysis
	
	if passwordAnalysis.Strength < 0.3 {
		result.Warnings = append(result.Warnings, "Weak password detected")
	}
	
	return result
}

// Helper methods

func (v *Validator) normalizeDN(dn string) string {
	// Remove extra whitespace around commas
	normalized := regexp.MustCompile(`\s*,\s*`).ReplaceAllString(dn, ",")
	// Remove leading/trailing whitespace
	normalized = strings.TrimSpace(normalized)
	// Normalize case for attribute names (but not values)
	return normalized
}

func (v *Validator) normalizeFilter(filter string) string {
	// Remove unnecessary whitespace
	normalized := strings.TrimSpace(filter)
	// Additional normalization could be added here
	return normalized
}

func (v *Validator) normalizeAttributeValue(name, value string) string {
	switch strings.ToLower(name) {
	case "mail", "email":
		return strings.ToLower(strings.TrimSpace(value))
	case "samaccountname", "uid":
		return strings.ToLower(strings.TrimSpace(value))
	case "cn", "displayname", "description":
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(value)
	}
}

func (v *Validator) parseDNComponents(dn string) ([]map[string]string, error) {
	components := make([]map[string]string, 0)
	
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) == 0 {
			continue
		}
		
		kvPair := strings.SplitN(part, "=", 2)
		if len(kvPair) != 2 {
			return nil, fmt.Errorf("invalid DN component format: %s", part)
		}
		
		attribute := strings.TrimSpace(kvPair[0])
		value := strings.TrimSpace(kvPair[1])
		
		component := map[string]string{
			"attribute": attribute,
			"value":     value,
			"raw":       part,
		}
		
		components = append(components, component)
	}
	
	return components, nil
}

func (v *Validator) validateDNComponent(component map[string]string) error {
	attribute := component["attribute"]
	value := component["value"]
	
	// Validate attribute name
	if err := v.validateAttributeName(attribute); err != nil {
		return fmt.Errorf("invalid attribute in DN component: %w", err)
	}
	
	// Validate value
	if len(value) == 0 {
		return fmt.Errorf("empty value in DN component")
	}
	
	// Check for dangerous characters in value
	for _, r := range value {
		if unicode.IsControl(r) && r != '\t' && r != '\r' && r != '\n' {
			return fmt.Errorf("DN component value contains control characters")
		}
	}
	
	return nil
}

func (v *Validator) validateFilterStructure(filter string) error {
	// Check basic structure
	if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") {
		return fmt.Errorf("filter must be enclosed in parentheses")
	}
	
	// Check parentheses balance
	openCount := 0
	for _, r := range filter {
		if r == '(' {
			openCount++
		} else if r == ')' {
			openCount--
			if openCount < 0 {
				return fmt.Errorf("unbalanced parentheses in filter")
			}
		}
	}
	
	if openCount != 0 {
		return fmt.Errorf("unbalanced parentheses in filter")
	}
	
	// Basic syntax validation
	if strings.Contains(filter, "()") {
		return fmt.Errorf("filter contains empty parentheses")
	}
	
	return nil
}

func (v *Validator) analyzeFilter(filter string) (int, []string, error) {
	complexity := 0
	attributes := make(map[string]bool)
	
	// Count operators for complexity
	complexity += strings.Count(filter, "&") * 2
	complexity += strings.Count(filter, "|") * 2
	complexity += strings.Count(filter, "!") * 3
	complexity += strings.Count(filter, "*") * 1
	complexity += strings.Count(filter, "=") * 1
	complexity += strings.Count(filter, ">=") * 1
	complexity += strings.Count(filter, "<=") * 1
	complexity += strings.Count(filter, "~=") * 1
	
	// Extract attribute names (simple regex-based approach)
	attrRegex := regexp.MustCompile(`\(([a-zA-Z][a-zA-Z0-9-]*)[=<>~]`)
	matches := attrRegex.FindAllStringSubmatch(filter, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			attributes[match[1]] = true
		}
	}
	
	// Convert map keys to slice
	attrList := make([]string, 0, len(attributes))
	for attr := range attributes {
		attrList = append(attrList, attr)
	}
	
	return complexity, attrList, nil
}

func (v *Validator) validateAttributeName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("attribute name cannot be empty")
	}
	
	if len(name) > v.config.MaxAttributeLength {
		return fmt.Errorf("attribute name too long (%d > %d)", len(name), v.config.MaxAttributeLength)
	}
	
	// Check for dangerous characters
	for _, r := range name {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("attribute name contains invalid characters")
		}
	}
	
	// Validate format
	if !attributeNameRegex.MatchString(name) {
		return fmt.Errorf("invalid attribute name format")
	}
	
	return nil
}

func (v *Validator) validateAttributeValue(name, value string) error {
	if len(value) > v.config.MaxValueLength {
		return fmt.Errorf("attribute value too long (%d > %d)", len(value), v.config.MaxValueLength)
	}
	
	// Specific validation based on attribute type
	switch strings.ToLower(name) {
	case "mail", "email":
		return ValidateEmail(value)
	case "samaccountname":
		return ValidateSAMAccountName(value)
	case "telephonenumber":
		return v.validatePhoneNumber(value)
	case "postalcode":
		return v.validatePostalCode(value)
	case "useraccountcontrol":
		return v.validateUserAccountControl(value)
	}
	
	return nil
}

func (v *Validator) validatePhoneNumber(phone string) error {
	// Basic phone number validation
	phoneRegex := regexp.MustCompile(`^[+]?[0-9\s\-\(\)\.]{7,20}$`)
	if !phoneRegex.MatchString(phone) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

func (v *Validator) validatePostalCode(code string) error {
	// Basic postal code validation (very permissive)
	codeRegex := regexp.MustCompile(`^[A-Za-z0-9\s\-]{3,10}$`)
	if !codeRegex.MatchString(code) {
		return fmt.Errorf("invalid postal code format")
	}
	return nil
}

func (v *Validator) validateUserAccountControl(value string) error {
	// Validate that it's a valid integer
	_, err := fmt.Sscanf(value, "%d")
	if err != nil {
		return fmt.Errorf("userAccountControl must be a valid integer")
	}
	return nil
}

func (v *Validator) isAllowedAttribute(attr string) bool {
	if len(v.config.AllowedAttributes) == 0 {
		return true // No restriction
	}
	
	for _, allowed := range v.config.AllowedAttributes {
		if strings.EqualFold(attr, allowed) {
			return true
		}
	}
	
	return false
}

func (v *Validator) detectValueType(value string) string {
	// Simple type detection
	if net.ParseIP(value) != nil {
		return "ip_address"
	}
	
	if emailValidationRegex.MatchString(value) {
		return "email"
	}
	
	if _, err := time.Parse("2006-01-02", value); err == nil {
		return "date"
	}
	
	if _, err := time.Parse("2006-01-02T15:04:05Z", value); err == nil {
		return "datetime"
	}
	
	if strings.HasPrefix(value, "CN=") {
		return "dn"
	}
	
	if matched, _ := regexp.MatchString(`^[0-9]+$`, value); matched {
		return "integer"
	}
	
	if matched, _ := regexp.MatchString(`^[0-9]+\.[0-9]+$`, value); matched {
		return "float"
	}
	
	return "string"
}

// PasswordAnalysis contains the results of password analysis
type PasswordAnalysis struct {
	Length   int     `json:"length"`
	Strength float64 `json:"strength"` // 0.0 to 1.0
	HasUpper bool    `json:"has_upper"`
	HasLower bool    `json:"has_lower"`
	HasDigit bool    `json:"has_digit"`
	HasSpecial bool  `json:"has_special"`
	Entropy    float64 `json:"entropy"`
}

func (v *Validator) analyzePassword(password string) PasswordAnalysis {
	analysis := PasswordAnalysis{
		Length: len(password),
	}
	
	charTypes := 0
	
	for _, r := range password {
		if unicode.IsUpper(r) && !analysis.HasUpper {
			analysis.HasUpper = true
			charTypes++
		}
		if unicode.IsLower(r) && !analysis.HasLower {
			analysis.HasLower = true
			charTypes++
		}
		if unicode.IsDigit(r) && !analysis.HasDigit {
			analysis.HasDigit = true
			charTypes++
		}
		if (unicode.IsPunct(r) || unicode.IsSymbol(r)) && !analysis.HasSpecial {
			analysis.HasSpecial = true
			charTypes++
		}
	}
	
	// Simple strength calculation based on length and character variety
	lengthScore := float64(analysis.Length) / 20.0 // Max 20 chars for full score
	if lengthScore > 1.0 {
		lengthScore = 1.0
	}
	
	varietyScore := float64(charTypes) / 4.0 // Max 4 types for full score
	
	// Combined score
	analysis.Strength = (lengthScore * 0.6) + (varietyScore * 0.4)
	if analysis.Strength > 1.0 {
		analysis.Strength = 1.0
	}
	
	// Simple entropy calculation (not cryptographically accurate but indicative)
	charsetSize := 0
	if analysis.HasLower {
		charsetSize += 26
	}
	if analysis.HasUpper {
		charsetSize += 26
	}
	if analysis.HasDigit {
		charsetSize += 10
	}
	if analysis.HasSpecial {
		charsetSize += 32 // Approximate
	}
	
	if charsetSize > 0 && analysis.Length > 0 {
		// Entropy = length * log2(charset_size)
		analysis.Entropy = float64(analysis.Length) * (3.32 * float64(charsetSize)) / 100.0 // Simplified
	}
	
	return analysis
}

// ValidationSummary provides a summary of all validation results
type ValidationSummary struct {
	TotalChecks    int                       `json:"total_checks"`
	PassedChecks   int                       `json:"passed_checks"`
	FailedChecks   int                       `json:"failed_checks"`
	WarningCount   int                       `json:"warning_count"`
	ErrorCount     int                       `json:"error_count"`
	OverallValid   bool                      `json:"overall_valid"`
	SecurityScore  float64                   `json:"security_score"`
	Recommendations []string                 `json:"recommendations"`
	Results        []*ValidationResult       `json:"results"`
}

// CreateValidationSummary creates a summary from multiple validation results
func CreateValidationSummary(results []*ValidationResult) *ValidationSummary {
	summary := &ValidationSummary{
		TotalChecks:    len(results),
		PassedChecks:   0,
		FailedChecks:   0,
		WarningCount:   0,
		ErrorCount:     0,
		OverallValid:   true,
		SecurityScore:  1.0,
		Recommendations: make([]string, 0),
		Results:        results,
	}
	
	for _, result := range results {
		if result.Valid {
			summary.PassedChecks++
		} else {
			summary.FailedChecks++
			summary.OverallValid = false
		}
		
		summary.WarningCount += len(result.Warnings)
		summary.ErrorCount += len(result.Errors)
		
		// Adjust security score based on threats
		if result.ThreatContext != nil {
			threatImpact := result.ThreatContext.RiskScore * 0.5
			summary.SecurityScore -= threatImpact
		}
	}
	
	if summary.SecurityScore < 0 {
		summary.SecurityScore = 0
	}
	
	// Generate recommendations
	if summary.ErrorCount > 0 {
		summary.Recommendations = append(summary.Recommendations, "Address validation errors before proceeding")
	}
	if summary.WarningCount > 0 {
		summary.Recommendations = append(summary.Recommendations, "Review validation warnings for potential issues")
	}
	if summary.SecurityScore < 0.7 {
		summary.Recommendations = append(summary.Recommendations, "Consider enhancing input security measures")
	}
	
	return summary
}