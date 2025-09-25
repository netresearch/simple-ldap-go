package validation

import (
	"regexp"
	"strings"
	"testing"
)

func TestValidator_ValidateDNSyntax(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name         string
		dn           string
		expectValid  bool
		expectThreat bool
	}{
		{
			name:         "Valid simple DN",
			dn:           "CN=test,DC=example,DC=com",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Valid complex DN with spaces",
			dn:           "CN=John Doe, OU=Users, DC=example, DC=com",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Empty DN",
			dn:           "",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Injection attempt",
			dn:           "CN=test*)(objectClass=*,DC=com",
			expectValid:  false,
			expectThreat: true,
		},
		{
			name:         "Invalid UTF-8",
			dn:           "CN=test\xff,DC=com",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Control characters",
			dn:           "CN=test\x00,DC=com",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Too long DN",
			dn:           strings.Repeat("CN="+strings.Repeat("a", 100)+",", 100) + "DC=com",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Missing equals sign",
			dn:           "CNtest,DCcom",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Empty component",
			dn:           "CN=test,,DC=com",
			expectValid:  false,
			expectThreat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateDNSyntax(tt.dn)

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v for DN %q. Errors: %v",
					tt.expectValid, result.Valid, tt.dn, result.Errors)
			}

			hasThreat := result.ThreatContext != nil
			if hasThreat != tt.expectThreat {
				t.Errorf("Expected threat=%v, got threat=%v for DN %q",
					tt.expectThreat, hasThreat, tt.dn)
			}

			// Check normalization
			if result.Valid && result.NormalizedInput == "" {
				t.Errorf("Expected normalized input for valid DN %q", tt.dn)
			}

			// Check metadata
			if result.Valid && result.Metadata["component_count"] == nil {
				t.Errorf("Expected component_count metadata for valid DN %q", tt.dn)
			}
		})
	}
}

func TestValidator_ValidateFilter(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name         string
		filter       string
		expectValid  bool
		expectThreat bool
	}{
		{
			name:         "Valid simple filter",
			filter:       "(objectClass=user)",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Valid complex filter",
			filter:       "(&(objectClass=user)(sAMAccountName=test))",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Valid OR filter",
			filter:       "(|(objectClass=user)(objectClass=person))",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Valid NOT filter",
			filter:       "(&(objectClass=user)(!(userAccountControl=514)))",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Empty filter",
			filter:       "",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Injection attempt",
			filter:       "*)(objectClass=*",
			expectValid:  false,
			expectThreat: true,
		},
		{
			name:         "Complex injection",
			filter:       "*)(&(objectClass=*)(userPassword=*)",
			expectValid:  false,
			expectThreat: true,
		},
		{
			name:         "Unbalanced parentheses",
			filter:       "(objectClass=user",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "No parentheses",
			filter:       "objectClass=user",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Invalid UTF-8",
			filter:       "(objectClass=user\xff)",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Too long filter",
			filter:       "(" + strings.Repeat("a", MaxFilterLength+1) + ")",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Overly complex filter",
			filter:       strings.Repeat("(&(objectClass=user)", 30) + strings.Repeat(")", 30),
			expectValid:  false,
			expectThreat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateFilter(tt.filter)

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v for filter %q. Errors: %v",
					tt.expectValid, result.Valid, tt.filter, result.Errors)
			}

			hasThreat := result.ThreatContext != nil && result.ThreatContext.RiskScore > 0.3
			if hasThreat != tt.expectThreat {
				t.Errorf("Expected threat=%v, got threat=%v for filter %q",
					tt.expectThreat, hasThreat, tt.filter)
			}

			// Check metadata
			if result.Valid && result.Metadata["complexity"] == nil {
				t.Errorf("Expected complexity metadata for valid filter %q", tt.filter)
			}
		})
	}
}

func TestValidator_ValidateAttribute(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name        string
		attrName    string
		attrValue   string
		expectValid bool
		expectWarn  bool
	}{
		{
			name:        "Valid CN attribute",
			attrName:    "cn",
			attrValue:   "John Doe",
			expectValid: true,
			expectWarn:  false,
		},
		{
			name:        "Valid email attribute",
			attrName:    "mail",
			attrValue:   "john.doe@example.com",
			expectValid: true,
			expectWarn:  false,
		},
		{
			name:        "Valid SAM account name",
			attrName:    "sAMAccountName",
			attrValue:   "john.doe",
			expectValid: true,
			expectWarn:  false,
		},
		{
			name:        "Invalid email format",
			attrName:    "mail",
			attrValue:   "invalid-email",
			expectValid: false,
			expectWarn:  false,
		},
		{
			name:        "Invalid SAM account name",
			attrName:    "sAMAccountName",
			attrValue:   "invalid@name",
			expectValid: false,
			expectWarn:  false,
		},
		{
			name:        "Empty attribute name",
			attrName:    "",
			attrValue:   "value",
			expectValid: false,
			expectWarn:  false,
		},
		{
			name:        "Invalid attribute name",
			attrName:    "invalid-attr-name!",
			attrValue:   "value",
			expectValid: false,
			expectWarn:  false,
		},
		{
			name:        "Too long attribute value",
			attrName:    "description",
			attrValue:   strings.Repeat("a", MaxValueLength+1),
			expectValid: false,
			expectWarn:  false,
		},
		{
			name:        "Valid phone number",
			attrName:    "telephoneNumber",
			attrValue:   "+1-555-123-4567",
			expectValid: true,
			expectWarn:  false,
		},
		{
			name:        "Invalid phone number",
			attrName:    "telephoneNumber",
			attrValue:   "not-a-phone-number",
			expectValid: false,
			expectWarn:  false,
		},
		{
			name:        "Valid postal code",
			attrName:    "postalCode",
			attrValue:   "12345",
			expectValid: true,
			expectWarn:  false,
		},
		{
			name:        "Valid user account control",
			attrName:    "userAccountControl",
			attrValue:   "512",
			expectValid: true,
			expectWarn:  false,
		},
		{
			name:        "Invalid user account control",
			attrName:    "userAccountControl",
			attrValue:   "not-a-number",
			expectValid: false,
			expectWarn:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateAttribute(tt.attrName, tt.attrValue)

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v for %s=%q. Errors: %v",
					tt.expectValid, result.Valid, tt.attrName, tt.attrValue, result.Errors)
			}

			hasWarnings := len(result.Warnings) > 0
			if hasWarnings != tt.expectWarn {
				t.Errorf("Expected warnings=%v, got warnings=%v for %s=%q",
					tt.expectWarn, hasWarnings, tt.attrName, tt.attrValue)
			}

			// Check normalization for specific attributes
			if result.Valid && tt.attrName == "mail" && result.NormalizedInput != "" {
				expected := strings.ToLower(strings.TrimSpace(tt.attrValue))
				if result.NormalizedInput != expected {
					t.Errorf("Expected normalized email %q, got %q", expected, result.NormalizedInput)
				}
			}

			// Check metadata
			if result.Metadata["value_type"] == nil {
				t.Errorf("Expected value_type metadata for %s=%q", tt.attrName, tt.attrValue)
			}
		})
	}
}

func TestValidator_ValidateCredentials(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name         string
		username     string
		password     string
		expectValid  bool
		expectThreat bool
	}{
		{
			name:         "Valid credentials",
			username:     "john.doe",
			password:     "SecurePass123",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Valid DN username",
			username:     "CN=John Doe,DC=example,DC=com",
			password:     "SecurePass123",
			expectValid:  true,
			expectThreat: false,
		},
		{
			name:         "Empty username",
			username:     "",
			password:     "SecurePass123",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Empty password",
			username:     "john.doe",
			password:     "",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Injection attempt in username",
			username:     "admin*)(objectClass=*",
			password:     "password",
			expectValid:  false,
			expectThreat: true,
		},
		{
			name:         "Too long username",
			username:     strings.Repeat("a", 300),
			password:     "SecurePass123",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Invalid UTF-8 username",
			username:     "user\xff",
			password:     "SecurePass123",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Invalid UTF-8 password",
			username:     "john.doe",
			password:     "pass\xff",
			expectValid:  false,
			expectThreat: false,
		},
		{
			name:         "Control characters in username",
			username:     "user\x00test",
			password:     "SecurePass123",
			expectValid:  false,
			expectThreat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateCredentials(tt.username, tt.password)

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v for %q:%q. Errors: %v",
					tt.expectValid, result.Valid, tt.username, tt.password, result.Errors)
			}

			hasThreat := result.ThreatContext != nil
			if hasThreat != tt.expectThreat {
				t.Errorf("Expected threat=%v, got threat=%v for %q:%q",
					tt.expectThreat, hasThreat, tt.username, tt.password)
			}

			// Check password analysis metadata
			if result.Valid && result.Metadata["password_analysis"] == nil {
				t.Errorf("Expected password analysis metadata for valid credentials")
			}
		})
	}
}

func TestValidator_Configuration(t *testing.T) {
	t.Run("Strict mode validation", func(t *testing.T) {
		strictConfig := DefaultValidationConfig()
		strictConfig.StrictMode = true
		strictValidator := NewValidator(strictConfig)

		lenientConfig := DefaultValidationConfig()
		lenientConfig.StrictMode = false
		lenientValidator := NewValidator(lenientConfig)

		// Test with a marginally valid DN component
		dn := "CN=test user,DC=example,DC=com"

		strictResult := strictValidator.ValidateDNSyntax(dn)
		lenientResult := lenientValidator.ValidateDNSyntax(dn)

		// Both should be valid for this test case, but strict might have more warnings
		if !strictResult.Valid || !lenientResult.Valid {
			t.Error("Both validators should accept valid DN")
		}
	})

	t.Run("Custom patterns", func(t *testing.T) {
		config := DefaultValidationConfig()
		config.CustomDNPattern = regexp.MustCompile(`^CN=[A-Z][a-z]+`)
		validator := NewValidator(config)

		// This should work with custom pattern
		result1 := validator.ValidateDNSyntax("CN=Test,DC=com")
		if !result1.Valid {
			t.Error("Should accept DN matching custom pattern")
		}
	})

	t.Run("Allowed attributes", func(t *testing.T) {
		config := DefaultValidationConfig()
		config.AllowedAttributes = []string{"cn", "mail"}
		validator := NewValidator(config)

		// Test allowed attribute
		result1 := validator.ValidateAttribute("cn", "test")
		if !result1.Valid {
			t.Error("Should accept allowed attribute")
		}

		// Test disallowed attribute
		result2 := validator.ValidateAttribute("description", "test")
		if result2.Valid {
			t.Error("Should reject disallowed attribute in strict mode")
		}
	})

	t.Run("Length limits", func(t *testing.T) {
		config := DefaultValidationConfig()
		config.MaxDNLength = 50
		validator := NewValidator(config)

		shortDN := "CN=test,DC=com"
		longDN := strings.Repeat("CN=verylongcomponentname,", 5) + "DC=com"

		result1 := validator.ValidateDNSyntax(shortDN)
		if !result1.Valid {
			t.Error("Should accept short DN within limit")
		}

		result2 := validator.ValidateDNSyntax(longDN)
		if result2.Valid {
			t.Error("Should reject DN exceeding length limit")
		}
	})
}

func TestValidationResult(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	t.Run("Valid result structure", func(t *testing.T) {
		result := validator.ValidateDNSyntax("CN=test,DC=com")

		if result == nil {
			t.Fatal("Result should not be nil")
		}

		if result.Errors == nil {
			t.Error("Errors slice should be initialized")
		}

		if result.Warnings == nil {
			t.Error("Warnings slice should be initialized")
		}

		if result.Metadata == nil {
			t.Error("Metadata map should be initialized")
		}

		if result.Valid && result.NormalizedInput == "" {
			t.Error("NormalizedInput should be set for valid results")
		}
	})

	t.Run("Invalid result structure", func(t *testing.T) {
		result := validator.ValidateDNSyntax("")

		if result.Valid {
			t.Error("Result should be invalid for empty DN")
		}

		if len(result.Errors) == 0 {
			t.Error("Should have error messages for invalid input")
		}
	})
}

func TestPasswordAnalysis(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name          string
		password      string
		minStrength   float64
		expectUpper   bool
		expectLower   bool
		expectDigit   bool
		expectSpecial bool
	}{
		{
			name:          "Strong password",
			password:      "SecureP@ssw0rd!",
			minStrength:   0.8,
			expectUpper:   true,
			expectLower:   true,
			expectDigit:   true,
			expectSpecial: true,
		},
		{
			name:          "Weak password",
			password:      "pass",
			minStrength:   0.0,
			expectUpper:   false,
			expectLower:   true,
			expectDigit:   false,
			expectSpecial: false,
		},
		{
			name:          "Numeric only",
			password:      "12345678",
			minStrength:   0.3,
			expectUpper:   false,
			expectLower:   false,
			expectDigit:   true,
			expectSpecial: false,
		},
		{
			name:          "Letters only",
			password:      "AbCdEfGh",
			minStrength:   0.5,
			expectUpper:   true,
			expectLower:   true,
			expectDigit:   false,
			expectSpecial: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := validator.analyzePassword(tt.password)

			if analysis.Length != len(tt.password) {
				t.Errorf("Expected length %d, got %d", len(tt.password), analysis.Length)
			}

			if analysis.Strength < tt.minStrength {
				t.Errorf("Expected strength >= %f, got %f", tt.minStrength, analysis.Strength)
			}

			if analysis.HasUpper != tt.expectUpper {
				t.Errorf("Expected HasUpper=%v, got %v", tt.expectUpper, analysis.HasUpper)
			}

			if analysis.HasLower != tt.expectLower {
				t.Errorf("Expected HasLower=%v, got %v", tt.expectLower, analysis.HasLower)
			}

			if analysis.HasDigit != tt.expectDigit {
				t.Errorf("Expected HasDigit=%v, got %v", tt.expectDigit, analysis.HasDigit)
			}

			if analysis.HasSpecial != tt.expectSpecial {
				t.Errorf("Expected HasSpecial=%v, got %v", tt.expectSpecial, analysis.HasSpecial)
			}

			if analysis.Entropy <= 0 && len(tt.password) > 0 {
				t.Error("Entropy should be positive for non-empty passwords")
			}
		})
	}
}

func TestValidationSummary(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	// Create multiple validation results
	results := []*ValidationResult{
		validator.ValidateDNSyntax("CN=test,DC=com"),            // Valid
		validator.ValidateDNSyntax(""),                          // Invalid
		validator.ValidateFilter("(objectClass=user)"),          // Valid
		validator.ValidateFilter("invalid"),                     // Invalid
		validator.ValidateAttribute("mail", "test@example.com"), // Valid
	}

	summary := CreateValidationSummary(results)

	if summary.TotalChecks != 5 {
		t.Errorf("Expected 5 total checks, got %d", summary.TotalChecks)
	}

	if summary.PassedChecks != 3 {
		t.Errorf("Expected 3 passed checks, got %d", summary.PassedChecks)
	}

	if summary.FailedChecks != 2 {
		t.Errorf("Expected 2 failed checks, got %d", summary.FailedChecks)
	}

	if summary.OverallValid {
		t.Error("Overall should be invalid when some checks fail")
	}

	if summary.SecurityScore < 0 || summary.SecurityScore > 1 {
		t.Errorf("Security score should be between 0 and 1, got %f", summary.SecurityScore)
	}

	if len(summary.Recommendations) == 0 {
		t.Error("Should have recommendations when there are errors")
	}

	if len(summary.Results) != 5 {
		t.Errorf("Should include all results, got %d", len(summary.Results))
	}
}

func TestValueTypeDetection(t *testing.T) {
	validator := NewValidator(DefaultValidationConfig())

	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"IP address", "192.168.1.1", "ip_address"},
		{"Email", "test@example.com", "email"},
		{"Date", "2023-12-25", "date"},
		{"DateTime", "2023-12-25T10:30:00Z", "datetime"},
		{"DN", "CN=test,DC=com", "dn"},
		{"Integer", "12345", "integer"},
		{"Float", "123.45", "float"},
		{"String", "regular text", "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.detectValueType(tt.value)
			if result != tt.expected {
				t.Errorf("Expected type %q for value %q, got %q", tt.expected, tt.value, result)
			}
		})
	}
}

// Benchmark tests for validation performance
func BenchmarkValidator_ValidateDNSyntax(b *testing.B) {
	validator := NewValidator(DefaultValidationConfig())
	dn := "CN=John Doe,OU=Users,OU=IT Department,DC=example,DC=com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateDNSyntax(dn)
	}
}

func BenchmarkValidator_ValidateFilter(b *testing.B) {
	validator := NewValidator(DefaultValidationConfig())
	filter := "(&(objectClass=user)(sAMAccountName=john.doe)(!(userAccountControl=514)))"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateFilter(filter)
	}
}

func BenchmarkValidator_ValidateAttribute(b *testing.B) {
	validator := NewValidator(DefaultValidationConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateAttribute("mail", "john.doe@example.com")
	}
}

func BenchmarkValidator_ValidateCredentials(b *testing.B) {
	validator := NewValidator(DefaultValidationConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateCredentials("john.doe", "SecurePassword123")
	}
}

func BenchmarkPasswordAnalysis(b *testing.B) {
	validator := NewValidator(DefaultValidationConfig())
	password := "SecureP@ssw0rd!123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.analyzePassword(password)
	}
}
