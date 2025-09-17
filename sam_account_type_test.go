package ldap

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSamAccountType(t *testing.T) {
	t.Run("sam account type constants", func(t *testing.T) {
		// Test all defined constants have correct values
		assert.Equal(t, SamAccountType(0x0), SamDomainObject)
		assert.Equal(t, SamAccountType(0x10000000), SamGroupObject)
		assert.Equal(t, SamAccountType(0x10000001), SamNonSecurityGroupObject)
		assert.Equal(t, SamAccountType(0x20000000), SamAliasObject)
		assert.Equal(t, SamAccountType(0x20000001), SamNonSecurityAliasObject)
		assert.Equal(t, SamAccountType(0x30000000), SamUserObject)
		assert.Equal(t, SamAccountType(0x30000001), SamMachineAccount)
		assert.Equal(t, SamAccountType(0x30000002), SamTrustAccount)
		assert.Equal(t, SamAccountType(0x40000000), SamAppBasicGroup)
		assert.Equal(t, SamAccountType(0x40000001), SamAppQueryGroup)
		assert.Equal(t, SamAccountType(0x7fffffff), SamAccountTypeMax)
	})
}

func TestSamAccountTypeString(t *testing.T) {
	tests := []struct {
		name     string
		samType  SamAccountType
		expected string
	}{
		{
			name:     "domain object",
			samType:  SamDomainObject,
			expected: "Domain Object",
		},
		{
			name:     "group object",
			samType:  SamGroupObject,
			expected: "Group Object",
		},
		{
			name:     "non-security group object",
			samType:  SamNonSecurityGroupObject,
			expected: "Non-Security Group Object",
		},
		{
			name:     "alias object",
			samType:  SamAliasObject,
			expected: "Alias Object",
		},
		{
			name:     "non-security alias object",
			samType:  SamNonSecurityAliasObject,
			expected: "Non-Security Alias Object",
		},
		{
			name:     "user object",
			samType:  SamUserObject,
			expected: "User Object / Normal User Account",
		},
		{
			name:     "machine account",
			samType:  SamMachineAccount,
			expected: "Machine Account",
		},
		{
			name:     "trust account",
			samType:  SamTrustAccount,
			expected: "Trust Account",
		},
		{
			name:     "app basic group",
			samType:  SamAppBasicGroup,
			expected: "App Basic Group",
		},
		{
			name:     "app query group",
			samType:  SamAppQueryGroup,
			expected: "App Query Group",
		},
		{
			name:     "account type max",
			samType:  SamAccountTypeMax,
			expected: "Account Type Max",
		},
		{
			name:     "unknown type",
			samType:  SamAccountType(0x12345678),
			expected: "Unknown",
		},
		{
			name:     "another unknown type",
			samType:  SamAccountType(999999),
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.samType.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSamAccountTypeValues(t *testing.T) {
	t.Run("verify specific constant values", func(t *testing.T) {
		// These values are from Microsoft documentation and should not change
		testCases := []struct {
			constant SamAccountType
			hexValue uint32
			decValue uint32
		}{
			{SamDomainObject, 0x0, 0},
			{SamGroupObject, 0x10000000, 268435456},
			{SamNonSecurityGroupObject, 0x10000001, 268435457},
			{SamAliasObject, 0x20000000, 536870912},
			{SamNonSecurityAliasObject, 0x20000001, 536870913},
			{SamUserObject, 0x30000000, 805306368},
			{SamMachineAccount, 0x30000001, 805306369},
			{SamTrustAccount, 0x30000002, 805306370},
			{SamAppBasicGroup, 0x40000000, 1073741824},
			{SamAppQueryGroup, 0x40000001, 1073741825},
			{SamAccountTypeMax, 0x7fffffff, 2147483647},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("constant_%s", tc.constant.String()), func(t *testing.T) {
				assert.Equal(t, tc.hexValue, uint32(tc.constant))
				assert.Equal(t, tc.decValue, uint32(tc.constant))
			})
		}
	})
}

func TestSamAccountTypeStringAllCases(t *testing.T) {
	t.Run("all defined constants have non-unknown strings", func(t *testing.T) {
		definedTypes := []SamAccountType{
			SamDomainObject,
			SamGroupObject,
			SamNonSecurityGroupObject,
			SamAliasObject,
			SamNonSecurityAliasObject,
			SamUserObject,
			SamMachineAccount,
			SamTrustAccount,
			SamAppBasicGroup,
			SamAppQueryGroup,
			SamAccountTypeMax,
		}

		for _, samType := range definedTypes {
			result := samType.String()
			assert.NotEqual(t, "Unknown", result,
				"Defined constant %d should not return 'Unknown'", uint32(samType))
			assert.NotEmpty(t, result,
				"Defined constant %d should not return empty string", uint32(samType))
		}
	})
}

func TestSamAccountTypeUsageScenarios(t *testing.T) {
	t.Run("common Active Directory scenarios", func(t *testing.T) {
		scenarios := []struct {
			name        string
			samType     SamAccountType
			description string
		}{
			{
				name:        "normal user account",
				samType:     SamUserObject,
				description: "Regular user accounts in Active Directory",
			},
			{
				name:        "computer account",
				samType:     SamMachineAccount,
				description: "Computer accounts (workstations, servers)",
			},
			{
				name:        "security group",
				samType:     SamGroupObject,
				description: "Security-enabled groups for permissions",
			},
			{
				name:        "distribution group",
				samType:     SamNonSecurityGroupObject,
				description: "Distribution groups for email lists",
			},
			{
				name:        "local group",
				samType:     SamAliasObject,
				description: "Local domain groups",
			},
			{
				name:        "trust account",
				samType:     SamTrustAccount,
				description: "Interdomain trust relationships",
			},
		}

		for _, scenario := range scenarios {
			t.Run(scenario.name, func(t *testing.T) {
				// Test that we can work with the type
				stringRep := scenario.samType.String()
				assert.NotEmpty(t, stringRep)
				assert.NotEqual(t, "Unknown", stringRep)

				// Test that we can convert back and forth
				value := uint32(scenario.samType)
				reconstructed := SamAccountType(value)
				assert.Equal(t, scenario.samType, reconstructed)
				assert.Equal(t, stringRep, reconstructed.String())
			})
		}
	})
}

func TestSamAccountTypeComparison(t *testing.T) {
	t.Run("type comparison operations", func(t *testing.T) {
		// Test equality
		assert.Equal(t, SamUserObject, SamUserObject)
		assert.NotEqual(t, SamUserObject, SamMachineAccount)

		// Test with uint32 conversion
		assert.Equal(t, uint32(SamUserObject), uint32(0x30000000))
		assert.True(t, SamUserObject == SamAccountType(0x30000000))

		// Test ordering (though not typically meaningful for account types)
		assert.True(t, SamDomainObject < SamGroupObject)
		assert.True(t, SamGroupObject < SamUserObject)
	})
}

func TestSamAccountTypeEdgeCases(t *testing.T) {
	t.Run("edge case values", func(t *testing.T) {
		edgeCases := []struct {
			name    string
			value   SamAccountType
			expects string
		}{
			{
				name:    "zero value",
				value:   SamAccountType(0),
				expects: "Domain Object",
			},
			{
				name:    "maximum uint32",
				value:   SamAccountType(0xFFFFFFFF),
				expects: "Unknown",
			},
			{
				name:    "just below SamAccountTypeMax",
				value:   SamAccountType(0x7ffffffe),
				expects: "Unknown",
			},
			{
				name:    "just above SamAccountTypeMax",
				value:   SamAccountType(0x80000000),
				expects: "Unknown",
			},
		}

		for _, tc := range edgeCases {
			t.Run(tc.name, func(t *testing.T) {
				result := tc.value.String()
				assert.Equal(t, tc.expects, result)
			})
		}
	})
}

func TestSamAccountTypeRange(t *testing.T) {
	t.Run("value ranges for different categories", func(t *testing.T) {
		// Domain objects: 0x0
		assert.True(t, SamDomainObject == 0x0)

		// Group objects: 0x1xxxxxxx
		assert.True(t, uint32(SamGroupObject)&0xF0000000 == 0x10000000)
		assert.True(t, uint32(SamNonSecurityGroupObject)&0xF0000000 == 0x10000000)

		// Alias objects: 0x2xxxxxxx
		assert.True(t, uint32(SamAliasObject)&0xF0000000 == 0x20000000)
		assert.True(t, uint32(SamNonSecurityAliasObject)&0xF0000000 == 0x20000000)

		// User objects: 0x3xxxxxxx
		assert.True(t, uint32(SamUserObject)&0xF0000000 == 0x30000000)
		assert.True(t, uint32(SamMachineAccount)&0xF0000000 == 0x30000000)
		assert.True(t, uint32(SamTrustAccount)&0xF0000000 == 0x30000000)

		// App groups: 0x4xxxxxxx
		assert.True(t, uint32(SamAppBasicGroup)&0xF0000000 == 0x40000000)
		assert.True(t, uint32(SamAppQueryGroup)&0xF0000000 == 0x40000000)
	})
}

func TestSamAccountTypeDocumentation(t *testing.T) {
	t.Run("verify documentation examples work", func(t *testing.T) {
		// Example 1: Check if an account is a user
		accountType := SamUserObject
		isUser := accountType == SamUserObject
		assert.True(t, isUser)

		// Example 2: Check if an account is a computer
		computerType := SamMachineAccount
		isComputer := computerType == SamMachineAccount
		assert.True(t, isComputer)

		// Example 3: Get human-readable description
		description := SamGroupObject.String()
		assert.Equal(t, "Group Object", description)

		// Example 4: Convert from uint32 (as would come from LDAP)
		var rawValue uint32 = 0x30000000
		converted := SamAccountType(rawValue)
		assert.Equal(t, SamUserObject, converted)
		assert.Equal(t, "User Object / Normal User Account", converted.String())
	})
}

func TestSamAccountTypeInSwitch(t *testing.T) {
	t.Run("usage in switch statements", func(t *testing.T) {
		testTypes := []SamAccountType{
			SamUserObject,
			SamMachineAccount,
			SamGroupObject,
			SamDomainObject,
			SamAccountType(999999), // Unknown
		}

		for _, samType := range testTypes {
			var category string

			switch samType {
			case SamUserObject:
				category = "User"
			case SamMachineAccount:
				category = "Computer"
			case SamGroupObject, SamNonSecurityGroupObject:
				category = "Group"
			case SamAliasObject, SamNonSecurityAliasObject:
				category = "Alias"
			case SamTrustAccount:
				category = "Trust"
			case SamAppBasicGroup, SamAppQueryGroup:
				category = "Application"
			case SamDomainObject:
				category = "Domain"
			default:
				category = "Unknown"
			}

			assert.NotEmpty(t, category)
			t.Logf("Type %s (%d) categorized as: %s", samType.String(), uint32(samType), category)
		}
	})
}

// Benchmark SamAccountType operations
func BenchmarkSamAccountTypeString(b *testing.B) {
	samType := SamUserObject

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = samType.String()
	}
}

func BenchmarkSamAccountTypeComparison(b *testing.B) {
	samType := SamUserObject

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = samType == SamUserObject
	}
}

func BenchmarkSamAccountTypeSwitch(b *testing.B) {
	samType := SamUserObject

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result string
		switch samType {
		case SamUserObject:
			result = "User"
		case SamMachineAccount:
			result = "Computer"
		case SamGroupObject:
			result = "Group"
		default:
			result = "Other"
		}
		_ = result
	}
}
