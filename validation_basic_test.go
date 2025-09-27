//go:build !integration

package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateIPAddress tests IP address validation
func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"valid IPv4", "192.168.1.1", true},
		{"valid IPv4 localhost", "127.0.0.1", true},
		{"valid IPv4 broadcast", "255.255.255.255", true},
		{"valid IPv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
		{"valid IPv6 short", "2001:db8::8a2e:370:7334", true},
		{"valid IPv6 localhost", "::1", true},
		{"invalid IPv4", "192.168.1.256", false},
		{"invalid IPv4 format", "192.168.1", false},
		{"invalid IPv6", "gggg::1", false},
		{"empty string", "", false},
		{"not an IP", "example.com", false},
		{"with port", "192.168.1.1:8080", false},
		{"with spaces", " 192.168.1.1 ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateIPAddress(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateEmailFormat tests email format validation
func TestValidateEmailFormat(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"valid email", "user@example.com", true},
		{"valid with subdomain", "user@mail.example.com", true},
		{"valid with plus", "user+tag@example.com", true},
		{"valid with dots", "first.last@example.com", true},
		{"valid with numbers", "user123@example123.com", true},
		{"valid with dash", "user@example-site.com", true},
		{"invalid without @", "userexample.com", false},
		{"invalid without domain", "user@", false},
		{"invalid without local", "@example.com", false},
		{"invalid with spaces", "user @example.com", false},
		{"invalid double @", "user@@example.com", false},
		{"empty string", "", false},
		{"just @", "@", false},
		{"invalid domain", "user@.com", false},
		{"invalid tld", "user@example.", false},
		{"special chars", "user!@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateEmailFormat(tt.email)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// BenchmarkValidateIPAddress benchmarks IP validation
func BenchmarkValidateIPAddress(b *testing.B) {
	ips := []string{
		"192.168.1.1",
		"2001:db8::8a2e:370:7334",
		"not-an-ip",
		"256.256.256.256",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ip := range ips {
			_ = ValidateIPAddress(ip)
		}
	}
}

// BenchmarkValidateEmailFormat benchmarks email validation
func BenchmarkValidateEmailFormat(b *testing.B) {
	emails := []string{
		"user@example.com",
		"first.last+tag@subdomain.example.org",
		"invalid-email",
		"@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, email := range emails {
			_ = ValidateEmailFormat(email)
		}
	}
}
