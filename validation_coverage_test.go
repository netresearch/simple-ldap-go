//go:build !integration

package ldap

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// filterUTF8Errors returns only errors containing "UTF-8" from the list.
func filterUTF8Errors(errs []string) []string {
	var utf8Errs []string
	for _, e := range errs {
		if strings.Contains(strings.ToLower(e), "utf-8") || strings.Contains(strings.ToLower(e), "utf8") {
			utf8Errs = append(utf8Errs, e)
		}
	}
	return utf8Errs
}

// ---------- SanitizeDN ----------

func TestSanitizeDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal DN", "CN=test,DC=com", "CN=test,DC=com"},
		{"with null bytes", "CN=test\x00,DC=com", "CN=test,DC=com"},
		{"with control chars", "CN=test\x01\x02,DC=com", "CN=test,DC=com"},
		{"with leading/trailing spaces", "  CN=test,DC=com  ", "CN=test,DC=com"},
		{"preserves tabs", "CN=test\t,DC=com", "CN=test\t,DC=com"},
		{"preserves newlines", "CN=test\n,DC=com", "CN=test\n,DC=com"},
		{"preserves carriage return", "CN=test\r,DC=com", "CN=test\r,DC=com"},
		{"empty string", "", ""},
		{"mixed control and normal", "CN=\x00test\x07value,DC=com", "CN=testvalue,DC=com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeDN(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------- SanitizeFilter ----------

func TestSanitizeFilter(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"normal filter", "(objectClass=user)"},
		{"with null bytes", "(objectClass=user\x00)"},
		{"with spaces", "  (objectClass=user)  "},
		{"empty string", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFilter(tt.input)
			assert.NotContains(t, result, "\x00")
		})
	}
}

// ---------- Validator.ValidateValue ----------

func TestValidator_ValidateValue(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name        string
		value       string
		expectValid bool
		expectWarn  bool
	}{
		{"normal value", "hello world", true, false},
		{"empty value", "", true, false},
		{"too long value", strings.Repeat("x", MaxValueLength+1), false, false},
		{
			"injection pattern",
			"*)(cn=*",
			false,
			false,
		},
		{
			"control characters",
			"test\x01value",
			true,
			true, // medium threat = warning
		},
		{
			"excessive length value",
			strings.Repeat("a", 10001),
			false,
			false,
		},
		{
			"script injection",
			"javascript:alert(1)",
			false,
			false,
		},
		{
			"null byte",
			"test\x00value",
			true,
			true, // control chars = medium threat = warning
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateValue(tt.value)
			assert.Equal(t, tt.expectValid, result.Valid, "valid mismatch for %q, errors: %v", tt.value, result.Errors)
			if tt.expectWarn {
				assert.NotEmpty(t, result.Warnings)
			}
		})
	}
}

func TestValidator_ValidateValue_NoSuspiciousPatterns(t *testing.T) {
	config := DefaultValidationConfig()
	config.BlockSuspiciousPatterns = false
	validator := NewValidator(config)

	result := validator.ValidateValue("*)(cn=*")
	assert.True(t, result.Valid, "should allow suspicious patterns when blocking is disabled")
}

func TestValidator_ValidateValue_UTF8Disabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.ValidateUTF8 = false
	validator := NewValidator(config)

	result := validator.ValidateValue("test\xff")
	// UTF8 validation should be skipped, so invalid UTF-8 should not cause failure
	assert.True(t, result.Valid, "should pass when UTF-8 validation is disabled")
	assert.Empty(t, result.Errors, "should have no errors when UTF-8 validation is disabled")
}

func TestValidator_ValidateValue_NormalizeDisabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.NormalizeInput = false
	validator := NewValidator(config)

	result := validator.ValidateValue("  spaced  ")
	assert.Equal(t, "  spaced  ", result.NormalizedInput)
}

func TestValidator_ValidateValue_InvalidUTF8(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())
	result := validator.ValidateValue("test\xff")
	assert.False(t, result.Valid)
	assert.Contains(t, strings.Join(result.Errors, " "), "invalid UTF-8")
}

// ---------- detectThreats ----------

func TestValidator_DetectThreats(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name        string
		input       string
		threatLevel string
		hasThreats  bool
	}{
		{"clean input", "normal text", "low", false},
		{"ldap injection cn", "*)(cn=*", "high", true},
		{"ldap injection objectclass", "*)(objectclass=*", "high", true},
		{"objectclass injection 2", ")(&(objectclass=*", "high", true},
		{"or injection", "*)(|(cn=*", "high", true},
		{"script injection", "script:alert(1)", "high", true},
		{"javascript injection", "javascript:void(0)", "high", true},
		{"eval injection", "eval(payload)", "high", true},
		{"exec injection", "exec(cmd)", "high", true},
		{"control character null", "test\x00value", "medium", true},
		{"control character bell", "test\x07value", "medium", true},
		{"excessive length", strings.Repeat("x", 10001), "medium", true},
		// Tab, newline, CR are allowed control chars
		{"tab is ok", "test\tvalue", "low", false},
		{"newline is ok", "test\nvalue", "low", false},
		{"cr is ok", "test\rvalue", "low", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := validator.detectThreats(tt.input)
			assert.Equal(t, tt.threatLevel, threats.ThreatLevel)
			if tt.hasThreats {
				assert.NotEmpty(t, threats.DetectedThreats)
			} else {
				assert.Empty(t, threats.DetectedThreats)
			}
		})
	}
}

func TestValidator_DetectThreats_RiskScore(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	// Low
	threats := validator.detectThreats("clean")
	assert.Equal(t, 0.2, threats.RiskScore)

	// Medium
	threats = validator.detectThreats("test\x00val")
	assert.Equal(t, 0.5, threats.RiskScore)

	// High
	threats = validator.detectThreats("*)(cn=*")
	assert.Equal(t, 0.8, threats.RiskScore)
}

// ---------- detectInjectionThreats ----------

func TestValidator_DetectInjectionThreats(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	// Injection detected
	threats := validator.detectInjectionThreats("*)(cn=*")
	assert.Equal(t, "high", threats.ThreatLevel)
	assert.Contains(t, threats.DetectedThreats, "ldap_injection")
	assert.Equal(t, 0.8, threats.RiskScore)
	assert.Equal(t, "block", threats.RecommendedAction)

	// No injection
	threats = validator.detectInjectionThreats("CN=test,DC=com")
	assert.Equal(t, "low", threats.ThreatLevel)
	assert.Empty(t, threats.DetectedThreats)
	assert.Equal(t, 0.2, threats.RiskScore)
}

// ---------- isValidDNFormat edge cases ----------

func TestValidator_IsValidDNFormat(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name   string
		dn     string
		expect bool
	}{
		{"no equals sign", "CNtest", false},
		{"double comma", "CN=test,,DC=com", false},
		{"odd quotes", `CN="test,DC=com`, false},
		{"valid", "CN=test,DC=com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, validator.isValidDNFormat(tt.dn))
		})
	}
}

// ---------- isValidAttributeName edge cases ----------

func TestValidator_IsValidAttributeName(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name   string
		attr   string
		expect bool
	}{
		{"empty", "", false},
		{"starts with digit", "1attr", false},
		{"starts with letter", "attr", true},
		{"with digits", "attr123", true},
		{"with hyphens", "my-attr", true},
		{"with underscore", "my_attr", false},
		{"with special char", "attr!", false},
		{"single letter", "a", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, validator.isValidAttributeName(tt.attr))
		})
	}
}

func TestValidator_IsValidAttributeName_CustomPattern(t *testing.T) {
	config := DefaultValidationConfig()
	config.CustomAttributePattern = regexp.MustCompile(`^[a-z]+$`)
	validator := NewValidator(config)

	assert.True(t, validator.isValidAttributeName("abc"))
	assert.False(t, validator.isValidAttributeName("ABC"))
}

// ---------- ValidateAttribute edge cases ----------

func TestValidator_ValidateAttribute_AllowedAttributes(t *testing.T) {
	config := DefaultValidationConfig()
	config.AllowedAttributes = []string{"cn", "mail", "sAMAccountName"}
	validator := NewValidator(config)

	result := validator.ValidateAttribute("telephoneNumber", "+1-555-1234")
	assert.False(t, result.Valid)
	assert.Contains(t, strings.Join(result.Errors, " "), "not in the allowed list")
}

func TestValidator_ValidateAttribute_LongAttrName(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())
	longName := strings.Repeat("a", 300)
	result := validator.ValidateAttribute(longName, "value")
	assert.False(t, result.Valid)
}

func TestValidator_ValidateAttribute_InvalidUTF8(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	result := validator.ValidateAttribute("cn\xff", "value")
	assert.False(t, result.Valid)

	result2 := validator.ValidateAttribute("cn", "value\xff")
	assert.False(t, result2.Valid)
}

func TestValidator_ValidateAttribute_MailNormalization(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())
	result := validator.ValidateAttribute("mail", "  User@Example.COM  ")
	assert.Equal(t, "user@example.com", result.NormalizedInput)
}

// ---------- validateSpecificAttributeValue ----------

func TestValidator_ValidateSpecificAttributeValue(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name        string
		attrName    string
		attrValue   string
		expectValid bool
	}{
		{"valid mail", "mail", "user@example.com", true},
		{"invalid mail", "mail", "not-email", false},
		{"valid sam", "sAMAccountName", "john.doe", true},
		{"invalid sam", "sAMAccountName", "john doe!", false},
		{"valid phone", "telephoneNumber", "+49 123 456", true},
		{"invalid phone", "telephoneNumber", "abc-xyz!", false},
		{"valid postal", "postalCode", "12345", true},
		{"invalid postal", "postalCode", "!!!", false},
		{"valid uac", "userAccountControl", "512", true},
		{"invalid uac", "userAccountControl", "abc", false},
		{"unknown attribute", "description", "any value", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateAttribute(tt.attrName, tt.attrValue)
			assert.Equal(t, tt.expectValid, result.Valid, "errors: %v", result.Errors)
		})
	}
}

// ---------- detectValueType edge cases ----------

func TestValidator_DetectValueType_Empty(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())
	assert.Equal(t, "empty", validator.detectValueType(""))
	assert.Equal(t, "empty", validator.detectValueType("   "))
}

// ---------- calculatePasswordEntropy ----------

func TestValidator_CalculatePasswordEntropy_Empty(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())
	assert.Equal(t, 0.0, validator.calculatePasswordEntropy(""))
}

// ---------- analyzePassword empty ----------

func TestValidator_AnalyzePassword_Empty(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())
	analysis := validator.analyzePassword("")
	assert.Equal(t, 0, analysis.Length)
	assert.Equal(t, 0.0, analysis.Entropy)
	assert.Equal(t, 0.0, analysis.Strength)
}

// ---------- ValidateDN edge cases ----------

func TestValidator_ValidateDN_LowThreatLevel(t *testing.T) {
	config := DefaultValidationConfig()
	config.BlockSuspiciousPatterns = true
	validator := NewValidator(config)

	result := validator.ValidateDN("CN=test,DC=example,DC=com")
	assert.True(t, result.Valid)
}

func TestValidator_ValidateDN_UTF8Disabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.ValidateUTF8 = false
	validator := NewValidator(config)

	result := validator.ValidateDN("CN=test\xff,DC=com")
	// Should not fail on UTF-8 since check is disabled
	assert.Empty(t, filterUTF8Errors(result.Errors), "should have no UTF-8 errors when validation is disabled")
}

func TestValidator_ValidateDN_NormalizeDisabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.NormalizeInput = false
	validator := NewValidator(config)

	result := validator.ValidateDN("  CN=test,DC=com  ")
	assert.Equal(t, "  CN=test,DC=com  ", result.NormalizedInput)
}

func TestValidator_ValidateDN_SuspiciousPatternsDisabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.BlockSuspiciousPatterns = false
	validator := NewValidator(config)

	result := validator.ValidateDN("CN=test,DC=com")
	assert.Nil(t, result.ThreatContext)
}

// ---------- ValidateFilter edge cases ----------

func TestValidator_ValidateFilter_UTF8Disabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.ValidateUTF8 = false
	validator := NewValidator(config)

	result := validator.ValidateFilter("(cn=test\xff)")
	// Should not fail on UTF-8 since check is disabled
	assert.Empty(t, filterUTF8Errors(result.Errors), "should have no UTF-8 errors when validation is disabled")
}

func TestValidator_ValidateFilter_NormalizeDisabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.NormalizeInput = false
	validator := NewValidator(config)

	result := validator.ValidateFilter("  (cn=test)  ")
	assert.Equal(t, "  (cn=test)  ", result.NormalizedInput)
}

func TestValidator_ValidateFilter_NoSuspiciousPatterns(t *testing.T) {
	config := DefaultValidationConfig()
	config.BlockSuspiciousPatterns = false
	validator := NewValidator(config)

	result := validator.ValidateFilter("(cn=test)")
	assert.True(t, result.Valid)
	assert.Nil(t, result.ThreatContext)
}

// ---------- ValidateCredentials edge cases ----------

func TestValidator_ValidateCredentials_ControlCharsInPassword(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())
	result := validator.ValidateCredentials("user", "pass\x00word")
	assert.False(t, result.Valid)
	assert.Contains(t, strings.Join(result.Errors, " "), "Password contains control characters")
}

func TestValidator_ValidateCredentials_NormalizeDisabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.NormalizeInput = false
	validator := NewValidator(config)

	result := validator.ValidateCredentials("user", "password")
	assert.Equal(t, "", result.NormalizedInput)
}

func TestValidator_ValidateCredentials_NoSuspiciousPatterns(t *testing.T) {
	config := DefaultValidationConfig()
	config.BlockSuspiciousPatterns = false
	validator := NewValidator(config)

	result := validator.ValidateCredentials("*)(cn=*", "password")
	assert.Nil(t, result.ThreatContext)
}

func TestValidator_ValidateCredentials_UTF8Disabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.ValidateUTF8 = false
	validator := NewValidator(config)

	result := validator.ValidateCredentials("user\xff", "pass\xff")
	// Should not fail on UTF-8 since validation is disabled
	assert.Empty(t, filterUTF8Errors(result.Errors), "should have no UTF-8 errors when validation is disabled")
}

// ---------- CreateValidationSummary edge cases ----------

func TestCreateValidationSummary_Empty(t *testing.T) {
	summary := CreateValidationSummary([]*ValidationResult{})
	assert.Equal(t, 0, summary.TotalChecks)
	assert.True(t, summary.OverallValid)
	assert.Equal(t, 1.0, summary.SecurityScore)
}

func TestCreateValidationSummary_AllValid(t *testing.T) {
	results := []*ValidationResult{
		{Valid: true, Warnings: []string{}, Errors: []string{}},
		{Valid: true, Warnings: []string{}, Errors: []string{}},
	}
	summary := CreateValidationSummary(results)
	assert.True(t, summary.OverallValid)
	assert.Equal(t, 1.0, summary.SecurityScore)
	assert.Empty(t, summary.Recommendations)
}

func TestCreateValidationSummary_WithThreats(t *testing.T) {
	results := []*ValidationResult{
		{
			Valid:    false,
			Errors:   []string{"bad"},
			Warnings: []string{},
			ThreatContext: &ThreatContext{
				RiskScore: 0.8,
			},
		},
	}
	summary := CreateValidationSummary(results)
	assert.False(t, summary.OverallValid)
	assert.Less(t, summary.SecurityScore, 1.0)
	found := false
	for _, r := range summary.Recommendations {
		if strings.Contains(r, "security threats") {
			found = true
			break
		}
	}
	assert.True(t, found, "should recommend addressing security threats")
}

func TestCreateValidationSummary_LowSecurityScore(t *testing.T) {
	results := make([]*ValidationResult, 10)
	for i := range results {
		results[i] = &ValidationResult{
			Valid:    false,
			Errors:   []string{"error"},
			Warnings: []string{},
		}
	}
	summary := CreateValidationSummary(results)
	assert.Less(t, summary.SecurityScore, 0.8)
	found := false
	for _, r := range summary.Recommendations {
		if strings.Contains(r, "Improve") {
			found = true
			break
		}
	}
	assert.True(t, found, "should recommend improving security validation")
}

// ---------- ValidateAttribute value_type metadata ----------

func TestValidator_ValidateAttribute_ValueTypeMetadata(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	result := validator.ValidateAttribute("", "192.168.1.1")
	require.NotNil(t, result.Metadata["value_type"])
	assert.Equal(t, "ip_address", result.Metadata["value_type"])
}

// ---------- calculateFilterComplexity ----------

func TestValidator_CalculateFilterComplexity(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name       string
		filter     string
		minComplex int
	}{
		{"simple", "(cn=test)", 1},
		{"with AND", "(&(cn=test)(sn=test))", 4},
		{"with OR", "(|(cn=test)(sn=test))", 4},
		{"with NOT", "(!(cn=test))", 3},
		{"with wildcard", "(cn=test*)", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			complexity := validator.calculateFilterComplexity(tt.filter)
			assert.GreaterOrEqual(t, complexity, tt.minComplex)
		})
	}
}

// ---------- isValidDNFormat with CustomDNPattern ----------

func TestValidator_IsValidDNFormat_CustomPattern(t *testing.T) {
	config := DefaultValidationConfig()
	config.CustomDNPattern = regexp.MustCompile(`^CN=[A-Z]`)
	validator := NewValidator(config)

	assert.True(t, validator.isValidDNFormat("CN=Admin,DC=com"))
	assert.False(t, validator.isValidDNFormat("CN=admin,DC=com"))
}

// ---------- ValidateAttribute NormalizeDisabled ----------

func TestValidator_ValidateAttribute_NormalizeDisabled(t *testing.T) {
	config := DefaultValidationConfig()
	config.NormalizeInput = false
	validator := NewValidator(config)

	result := validator.ValidateAttribute("cn", "  value  ")
	assert.Equal(t, "  value  ", result.NormalizedInput)
}

// ---------- ValidateDN medium threat level (warning branch) ----------

func TestValidator_ValidateDN_NoThreatDetected(t *testing.T) {
	// detectInjectionThreats only produces "low" (no threats) or "high" (injection found).
	// The "else" warning branch in ValidateDN is a defensive branch that can't be
	// reached through detectInjectionThreats alone.
	// This test verifies that a clean DN produces no threats.
	validator := NewValidator(DefaultValidationConfig())
	result := validator.ValidateDN("CN=normal user,DC=example,DC=com")
	assert.True(t, result.Valid)
	assert.Nil(t, result.ThreatContext, "clean DN should produce no threat context")
}

// ---------- ValidateFilter warning branch ----------

func TestValidator_ValidateFilter_NoThreatDetected(t *testing.T) {
	// detectInjectionThreats only produces "low" (no threats) or "high" (injection found).
	// The "else" warning branch in ValidateFilter (non-high, non-critical threats) is a
	// defensive branch that can't be reached through detectInjectionThreats alone.
	// This test verifies that a clean filter produces no threats.
	validator := NewValidator(DefaultValidationConfig())
	result := validator.ValidateFilter("(cn=normal)")
	assert.True(t, result.Valid)
	assert.Nil(t, result.ThreatContext, "clean filter should produce no threat context")
}

// ---------- detectThreats and detectInjectionThreats default switch cases ----------

// The "critical" and "default" cases in the risk score switch statements of
// detectThreats and detectInjectionThreats are unreachable because the threat
// level is only ever set to "low", "medium", or "high" within those functions.
// These are defensive default cases that can't be reached through normal execution.
