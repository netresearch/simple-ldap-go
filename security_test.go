package ldap

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

func TestValidateDN(t *testing.T) {
	tests := []struct {
		name        string
		dn          string
		expectValid bool
		expectError bool
	}{
		{"Valid simple DN", "CN=test,DC=example,DC=com", true, false},
		{"Valid complex DN", "CN=John Doe,OU=Users,OU=IT,DC=example,DC=com", true, false},
		{"Empty DN", "", false, true},
		{"Invalid format - no equals", "CNtest,DCexample", false, true},
		{"Invalid format - empty component", "CN=test,,DC=com", false, true},
		{"Invalid format - trailing comma", "CN=test,DC=com,", false, true},
		{"Control characters", "CN=test\x00,DC=com", false, true},
		{"Too long DN", strings.Repeat("CN="+strings.Repeat("a", 1000)+",", 10) + "DC=com", false, true},
		{"Special characters", "CN=O'Neill\\, John,DC=example,DC=com", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateDN(tt.dn)
			
			if tt.expectError && err == nil {
				t.Errorf("Expected error for DN %q, but got none", tt.dn)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Did not expect error for DN %q, but got: %v", tt.dn, err)
			}
			if tt.expectValid && err != nil {
				t.Errorf("Expected valid DN %q, but got error: %v", tt.dn, err)
			}
			if tt.expectValid && result == "" {
				t.Errorf("Expected normalized DN for %q, but got empty string", tt.dn)
			}
		})
	}
}

func TestValidateLDAPFilter(t *testing.T) {
	tests := []struct {
		name        string
		filter      string
		expectValid bool
	}{
		{"Valid simple filter", "(objectClass=user)", true},
		{"Valid complex filter", "(&(objectClass=user)(sAMAccountName=test))", true},
		{"Valid OR filter", "(|(objectClass=user)(objectClass=person))", true},
		{"Valid negation", "(&(objectClass=user)(!(userAccountControl=514)))", true},
		{"Empty filter", "", false},
		{"Unbalanced parentheses", "(objectClass=user", false},
		{"No parentheses", "objectClass=user", false},
		{"Null byte injection", "(objectClass=user\x00)", false},
		{"Overly complex filter", strings.Repeat("(&(objectClass=user)", 50), false},
		{"Too long filter", "(" + strings.Repeat("a", MaxFilterLength) + ")", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateLDAPFilter(tt.filter)
			
			if tt.expectValid && err != nil {
				t.Errorf("Expected valid filter %q, but got error: %v", tt.filter, err)
			}
			if !tt.expectValid && err == nil {
				t.Errorf("Expected invalid filter %q, but got no error", tt.filter)
			}
		})
	}
}

func TestEscapeFilterValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Normal text", "john", "john"},
		{"Parentheses", "test(user)", "test\\28user\\29"},
		{"Asterisk", "john*", "john\\2a"},
		{"Backslash", "domain\\user", "domain\\5cuser"},
		{"Null byte", "test\x00", "test\\00"},
		{"Complex injection", "*)(objectClass=*", "\\2a\\29\\28objectClass=\\2a"},
		{"Unicode", "tëst", "tëst"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeFilterValue(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeFilterValue(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateSAMAccountName(t *testing.T) {
	tests := []struct {
		name        string
		sam         string
		expectValid bool
	}{
		{"Valid simple", "john", true},
		{"Valid with number", "john123", true},
		{"Valid with dot", "john.doe", true},
		{"Valid underscore", "john_doe", true},
		{"Empty", "", false},
		{"Too short", "a", false},
		{"Too long", strings.Repeat("a", 100), false},
		{"Invalid character @", "john@doe", false},
		{"Invalid character space", "john doe", false},
		{"Invalid character +", "john+doe", false},
		{"Starts with number", "1john", false},
		{"Only numbers", "123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSAMAccountName(tt.sam)
			
			if tt.expectValid && err != nil {
				t.Errorf("Expected valid SAM %q, but got error: %v", tt.sam, err)
			}
			if !tt.expectValid && err == nil {
				t.Errorf("Expected invalid SAM %q, but got no error", tt.sam)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		expectValid bool
	}{
		{"Valid simple", "test@example.com", true},
		{"Valid with subdomain", "test@mail.example.com", true},
		{"Valid with plus", "test+tag@example.com", true},
		{"Valid with dot", "test.user@example.com", true},
		{"Empty", "", false},
		{"No @", "testexample.com", false},
		{"Multiple @", "test@example@com", false},
		{"No domain", "test@", false},
		{"No local part", "@example.com", false},
		{"Invalid character", "test user@example.com", false},
		{"Too long", strings.Repeat("a", 100) + "@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			
			if tt.expectValid && err != nil {
				t.Errorf("Expected valid email %q, but got error: %v", tt.email, err)
			}
			if !tt.expectValid && err == nil {
				t.Errorf("Expected invalid email %q, but got no error", tt.email)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectValid bool
	}{
		{"Valid strong password", "SecurePass123!", true},
		{"Valid with symbols", "MyP@ssw0rd", true},
		{"Too short", "Abc1", false},
		{"No uppercase", "securepass123", false},
		{"No lowercase", "SECUREPASS123", false},
		{"No digits", "SecurePassword", false},
		{"Common password", "password123", false},
		{"Another common", "Password123456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			
			if tt.expectValid && err != nil {
				t.Errorf("Expected valid password %q, but got error: %v", tt.password, err)
			}
			if !tt.expectValid && err == nil {
				t.Errorf("Expected invalid password %q, but got no error", tt.password)
			}
		})
	}
}

func TestValidateServerURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectValid bool
	}{
		{"Valid LDAP", "ldap://example.com:389", true},
		{"Valid LDAPS", "ldaps://example.com:636", true},
		{"Valid without port", "ldaps://example.com", true},
		{"Empty URL", "", false},
		{"Invalid scheme", "http://example.com", false},
		{"No hostname", "ldap://", false},
		{"Invalid port", "ldap://example.com:abc", false},
		{"Port out of range", "ldap://example.com:99999", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServerURL(tt.url)
			
			if tt.expectValid && err != nil {
				t.Errorf("Expected valid URL %q, but got error: %v", tt.url, err)
			}
			if !tt.expectValid && err == nil {
				t.Errorf("Expected invalid URL %q, but got no error", tt.url)
			}
		})
	}
}

func TestSecureCredential(t *testing.T) {
	t.Run("Basic operations", func(t *testing.T) {
		username := "testuser"
		password := "secretPassword123"
		timeout := 5 * time.Minute
		
		cred := NewSecureCredential(username, password, timeout)
		
		if cred.IsExpired() {
			t.Error("New credential should not be expired")
		}
		
		user, pass := cred.GetCredentials()
		if user != username || pass != password {
			t.Error("Credentials do not match original values")
		}
		
		cred.Zeroize()
		
		if !cred.IsExpired() {
			t.Error("Credential should be expired after Zeroize()")
		}
		
		user, pass = cred.GetCredentials()
		if user != "" || pass != "" {
			t.Error("Zeroized credential should return empty strings")
		}
	})
	
	t.Run("Multiple zeroize calls", func(t *testing.T) {
		cred := NewSecureCredential("testuser", "testpass", 5*time.Minute)
		cred.Zeroize()
		cred.Zeroize() // Should not panic
		
		if !cred.IsExpired() {
			t.Error("Credential should remain expired")
		}
	})
}

func TestValidateTLSConfig(t *testing.T) {
	// Test with secure configuration
	secureTLSConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		InsecureSkipVerify: false,
	}
	
	err := ValidateTLSConfig(secureTLSConfig)
	if err != nil {
		t.Errorf("Expected secure TLS config to be valid, got error: %v", err)
	}
	
	// Test with insecure configuration
	insecureTLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS10, // Too old
		InsecureSkipVerify: true,             // Insecure
	}
	
	err = ValidateTLSConfig(insecureTLSConfig)
	if err == nil {
		t.Error("Expected insecure TLS config to be invalid")
	}
}

func TestCreateSecureTLSConfig(t *testing.T) {
	// Test basic secure config creation
	cfg := &TLSConfig{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	
	tlsConfig := CreateSecureTLSConfig(cfg)
	if tlsConfig == nil {
		t.Error("Expected TLS config to be created")
	}
	
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion to be TLS 1.2, got %d", tlsConfig.MinVersion)
	}
	
	if tlsConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be false")
	}
}

func TestValidateIPWhitelist(t *testing.T) {
	tests := []struct {
		name      string
		whitelist []string
		expectErr bool
	}{
		{"Valid IP addresses", []string{"192.168.1.0/24", "10.0.0.0/8"}, false},
		{"Valid single IP", []string{"192.168.1.1/32"}, false},
		{"Invalid CIDR", []string{"192.168.1.0/99"}, true},
		{"Invalid IP", []string{"999.999.999.999/24"}, true},
		{"Empty slice", []string{}, false},
		{"Mixed valid/invalid", []string{"192.168.1.0/24", "invalid"}, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateIPWhitelist(tt.whitelist)
			
			if tt.expectErr && err == nil {
				t.Error("Expected error for invalid whitelist")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Did not expect error, got: %v", err)
			}
		})
	}
}