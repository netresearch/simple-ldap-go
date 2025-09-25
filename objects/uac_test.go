package objects

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUACFromUint32(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected UAC
	}{
		{
			name:  "normal enabled user account",
			value: 0x200, // ADS_UF_NORMAL_ACCOUNT
			expected: UAC{
				NormalAccount: true,
			},
		},
		{
			name:  "disabled normal user account",
			value: 0x202, // ADS_UF_NORMAL_ACCOUNT | ADS_UF_ACCOUNTDISABLE
			expected: UAC{
				NormalAccount:   true,
				AccountDisabled: true,
			},
		},
		{
			name:  "workstation trust account",
			value: 0x1000, // ADS_UF_WORKSTATION_TRUST_ACCOUNT
			expected: UAC{
				WorkstationTrustAccount: true,
			},
		},
		{
			name:  "server trust account",
			value: 0x2000, // ADS_UF_SERVER_TRUST_ACCOUNT
			expected: UAC{
				ServerTrustAccount: true,
			},
		},
		{
			name:  "user with no password expiration",
			value: 0x10200, // ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD
			expected: UAC{
				NormalAccount:        true,
				NoPasswordExpiration: true,
			},
		},
		{
			name:  "smart card required user",
			value: 0x40200, // ADS_UF_NORMAL_ACCOUNT | ADS_UF_SMARTCARD_REQUIRED
			expected: UAC{
				NormalAccount:     true,
				SmartCardRequired: true,
			},
		},
		{
			name:  "all flags set",
			value: 0xFFFFFFFF,
			expected: UAC{
				LogonScript:                        true,
				AccountDisabled:                    true,
				HomeDirRequired:                    true,
				Lockout:                            true,
				PasswordNotRequired:                true,
				PasswordCantChange:                 true,
				EncryptedTextPasswordAllowed:       true,
				TempDuplicateAccount:               true,
				NormalAccount:                      true,
				InterdomainTrustAccount:            true,
				WorkstationTrustAccount:            true,
				ServerTrustAccount:                 true,
				NoPasswordExpiration:               true,
				MNSLogonAccount:                    true,
				SmartCardRequired:                  true,
				TrustedForDelegation:               true,
				NotDelegated:                       true,
				UseDESKeyOnly:                      true,
				DontRequirePreauth:                 true,
				PasswordExpired:                    true,
				TrustedToAuthenticateForDelegation: true,
			},
		},
		{
			name:     "no flags set",
			value:    0,
			expected: UAC{}, // All fields should be false
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UACFromUint32(tt.value)

			// Compare each field individually for better error reporting
			assert.Equal(t, tt.expected.LogonScript, result.LogonScript, "LogonScript")
			assert.Equal(t, tt.expected.AccountDisabled, result.AccountDisabled, "AccountDisabled")
			assert.Equal(t, tt.expected.HomeDirRequired, result.HomeDirRequired, "HomeDirRequired")
			assert.Equal(t, tt.expected.Lockout, result.Lockout, "Lockout")
			assert.Equal(t, tt.expected.PasswordNotRequired, result.PasswordNotRequired, "PasswordNotRequired")
			assert.Equal(t, tt.expected.PasswordCantChange, result.PasswordCantChange, "PasswordCantChange")
			assert.Equal(t, tt.expected.EncryptedTextPasswordAllowed, result.EncryptedTextPasswordAllowed, "EncryptedTextPasswordAllowed")
			assert.Equal(t, tt.expected.TempDuplicateAccount, result.TempDuplicateAccount, "TempDuplicateAccount")
			assert.Equal(t, tt.expected.NormalAccount, result.NormalAccount, "NormalAccount")
			assert.Equal(t, tt.expected.InterdomainTrustAccount, result.InterdomainTrustAccount, "InterdomainTrustAccount")
			assert.Equal(t, tt.expected.WorkstationTrustAccount, result.WorkstationTrustAccount, "WorkstationTrustAccount")
			assert.Equal(t, tt.expected.ServerTrustAccount, result.ServerTrustAccount, "ServerTrustAccount")
			assert.Equal(t, tt.expected.NoPasswordExpiration, result.NoPasswordExpiration, "NoPasswordExpiration")
			assert.Equal(t, tt.expected.MNSLogonAccount, result.MNSLogonAccount, "MNSLogonAccount")
			assert.Equal(t, tt.expected.SmartCardRequired, result.SmartCardRequired, "SmartCardRequired")
			assert.Equal(t, tt.expected.TrustedForDelegation, result.TrustedForDelegation, "TrustedForDelegation")
			assert.Equal(t, tt.expected.NotDelegated, result.NotDelegated, "NotDelegated")
			assert.Equal(t, tt.expected.UseDESKeyOnly, result.UseDESKeyOnly, "UseDESKeyOnly")
			assert.Equal(t, tt.expected.DontRequirePreauth, result.DontRequirePreauth, "DontRequirePreauth")
			assert.Equal(t, tt.expected.PasswordExpired, result.PasswordExpired, "PasswordExpired")
			assert.Equal(t, tt.expected.TrustedToAuthenticateForDelegation, result.TrustedToAuthenticateForDelegation, "TrustedToAuthenticateForDelegation")
		})
	}
}

func TestUACUint32(t *testing.T) {
	tests := []struct {
		name     string
		uac      UAC
		expected uint32
	}{
		{
			name: "normal enabled user account",
			uac: UAC{
				NormalAccount: true,
			},
			expected: 0x200,
		},
		{
			name: "disabled normal user account",
			uac: UAC{
				NormalAccount:   true,
				AccountDisabled: true,
			},
			expected: 0x202,
		},
		{
			name: "workstation trust account",
			uac: UAC{
				WorkstationTrustAccount: true,
			},
			expected: 0x1000,
		},
		{
			name: "complex account with multiple flags",
			uac: UAC{
				NormalAccount:        true,
				NoPasswordExpiration: true,
				SmartCardRequired:    true,
			},
			expected: 0x50200, // 0x200 | 0x10000 | 0x40000
		},
		{
			name:     "empty UAC",
			uac:      UAC{},
			expected: 0,
		},
		{
			name: "single flags",
			uac: UAC{
				LogonScript: true,
			},
			expected: 0x1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.uac.Uint32()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUACRoundTrip(t *testing.T) {
	// Test that converting uint32 -> UAC -> uint32 preserves supported bits
	tests := []struct {
		originalValue uint32
		expectedValue uint32 // May differ from original if unsupported bits are filtered out
	}{
		{0x0, 0x0},              // No flags
		{0x200, 0x200},          // Normal account
		{0x202, 0x202},          // Disabled normal account
		{0x1000, 0x1000},        // Workstation trust account
		{0x2000, 0x2000},        // Server trust account
		{0x10200, 0x10200},      // Normal account with no password expiration
		{0x40200, 0x40200},      // Normal account with smart card required
		{0xFFFFFFFF, 0x1ff3bfb}, // All flags - only supported bits preserved (calculated from actual UAC implementation)
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("roundtrip_%x", test.originalValue), func(t *testing.T) {
			// Convert uint32 to UAC
			uac := UACFromUint32(test.originalValue)

			// Convert back to uint32
			convertedValue := uac.Uint32()

			// Should match expected value (may filter out unsupported bits)
			assert.Equal(t, test.expectedValue, convertedValue)
		})
	}
}

func TestUACString(t *testing.T) {
	tests := []struct {
		name             string
		uac              UAC
		expectedContains []string
		expectedEmpty    bool
	}{
		{
			name: "normal account",
			uac: UAC{
				NormalAccount: true,
			},
			expectedContains: []string{"NormalAccount"},
		},
		{
			name: "disabled account",
			uac: UAC{
				NormalAccount:   true,
				AccountDisabled: true,
			},
			expectedContains: []string{"NormalAccount", "AccountDisabled"},
		},
		{
			name: "complex account",
			uac: UAC{
				NormalAccount:        true,
				NoPasswordExpiration: true,
				SmartCardRequired:    true,
			},
			expectedContains: []string{"NormalAccount", "NoPasswordExpiration", "SmartCardRequired"},
		},
		{
			name:          "empty UAC",
			uac:           UAC{},
			expectedEmpty: true,
		},
		{
			name: "workstation trust account",
			uac: UAC{
				WorkstationTrustAccount: true,
			},
			expectedContains: []string{"WorkstationTrustAccount"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.uac.String()

			if tt.expectedEmpty {
				assert.Empty(t, result)
			} else {
				assert.NotEmpty(t, result)

				for _, expectedSubstring := range tt.expectedContains {
					assert.Contains(t, result, expectedSubstring)
				}

				// Should not end with trailing comma and space
				assert.False(t, strings.HasSuffix(result, ", "))
			}
		})
	}
}

func TestUACIndividualFlags(t *testing.T) {
	// Test each flag individually
	flagTests := []struct {
		name     string
		setValue func(*UAC)
		getValue func(UAC) bool
		flagBit  uint32
	}{
		{
			name:     "LogonScript",
			setValue: func(uac *UAC) { uac.LogonScript = true },
			getValue: func(uac UAC) bool { return uac.LogonScript },
			flagBit:  0x1,
		},
		{
			name:     "AccountDisabled",
			setValue: func(uac *UAC) { uac.AccountDisabled = true },
			getValue: func(uac UAC) bool { return uac.AccountDisabled },
			flagBit:  0x2,
		},
		{
			name:     "HomeDirRequired",
			setValue: func(uac *UAC) { uac.HomeDirRequired = true },
			getValue: func(uac UAC) bool { return uac.HomeDirRequired },
			flagBit:  0x8,
		},
		{
			name:     "Lockout",
			setValue: func(uac *UAC) { uac.Lockout = true },
			getValue: func(uac UAC) bool { return uac.Lockout },
			flagBit:  0x10,
		},
		{
			name:     "PasswordNotRequired",
			setValue: func(uac *UAC) { uac.PasswordNotRequired = true },
			getValue: func(uac UAC) bool { return uac.PasswordNotRequired },
			flagBit:  0x20,
		},
		{
			name:     "PasswordCantChange",
			setValue: func(uac *UAC) { uac.PasswordCantChange = true },
			getValue: func(uac UAC) bool { return uac.PasswordCantChange },
			flagBit:  0x40,
		},
		{
			name:     "EncryptedTextPasswordAllowed",
			setValue: func(uac *UAC) { uac.EncryptedTextPasswordAllowed = true },
			getValue: func(uac UAC) bool { return uac.EncryptedTextPasswordAllowed },
			flagBit:  0x80,
		},
		{
			name:     "TempDuplicateAccount",
			setValue: func(uac *UAC) { uac.TempDuplicateAccount = true },
			getValue: func(uac UAC) bool { return uac.TempDuplicateAccount },
			flagBit:  0x100,
		},
		{
			name:     "NormalAccount",
			setValue: func(uac *UAC) { uac.NormalAccount = true },
			getValue: func(uac UAC) bool { return uac.NormalAccount },
			flagBit:  0x200,
		},
		{
			name:     "InterdomainTrustAccount",
			setValue: func(uac *UAC) { uac.InterdomainTrustAccount = true },
			getValue: func(uac UAC) bool { return uac.InterdomainTrustAccount },
			flagBit:  0x800,
		},
		{
			name:     "WorkstationTrustAccount",
			setValue: func(uac *UAC) { uac.WorkstationTrustAccount = true },
			getValue: func(uac UAC) bool { return uac.WorkstationTrustAccount },
			flagBit:  0x1000,
		},
		{
			name:     "ServerTrustAccount",
			setValue: func(uac *UAC) { uac.ServerTrustAccount = true },
			getValue: func(uac UAC) bool { return uac.ServerTrustAccount },
			flagBit:  0x2000,
		},
		{
			name:     "NoPasswordExpiration",
			setValue: func(uac *UAC) { uac.NoPasswordExpiration = true },
			getValue: func(uac UAC) bool { return uac.NoPasswordExpiration },
			flagBit:  0x10000,
		},
		{
			name:     "MNSLogonAccount",
			setValue: func(uac *UAC) { uac.MNSLogonAccount = true },
			getValue: func(uac UAC) bool { return uac.MNSLogonAccount },
			flagBit:  0x20000,
		},
		{
			name:     "SmartCardRequired",
			setValue: func(uac *UAC) { uac.SmartCardRequired = true },
			getValue: func(uac UAC) bool { return uac.SmartCardRequired },
			flagBit:  0x40000,
		},
		{
			name:     "TrustedForDelegation",
			setValue: func(uac *UAC) { uac.TrustedForDelegation = true },
			getValue: func(uac UAC) bool { return uac.TrustedForDelegation },
			flagBit:  0x80000,
		},
		{
			name:     "NotDelegated",
			setValue: func(uac *UAC) { uac.NotDelegated = true },
			getValue: func(uac UAC) bool { return uac.NotDelegated },
			flagBit:  0x100000,
		},
		{
			name:     "UseDESKeyOnly",
			setValue: func(uac *UAC) { uac.UseDESKeyOnly = true },
			getValue: func(uac UAC) bool { return uac.UseDESKeyOnly },
			flagBit:  0x200000,
		},
		{
			name:     "DontRequirePreauth",
			setValue: func(uac *UAC) { uac.DontRequirePreauth = true },
			getValue: func(uac UAC) bool { return uac.DontRequirePreauth },
			flagBit:  0x400000,
		},
		{
			name:     "PasswordExpired",
			setValue: func(uac *UAC) { uac.PasswordExpired = true },
			getValue: func(uac UAC) bool { return uac.PasswordExpired },
			flagBit:  0x800000,
		},
		{
			name:     "TrustedToAuthenticateForDelegation",
			setValue: func(uac *UAC) { uac.TrustedToAuthenticateForDelegation = true },
			getValue: func(uac UAC) bool { return uac.TrustedToAuthenticateForDelegation },
			flagBit:  0x1000000,
		},
	}

	for _, tt := range flagTests {
		t.Run(tt.name, func(t *testing.T) {
			// Test setting individual flag
			uac := UAC{}
			tt.setValue(&uac)

			// Verify the flag is set
			assert.True(t, tt.getValue(uac), "Flag should be set")

			// Verify the correct bit is set in uint32 conversion
			value := uac.Uint32()
			assert.Equal(t, tt.flagBit, value, "Should set correct bit value")

			// Verify round-trip conversion
			reconstructed := UACFromUint32(value)
			assert.True(t, tt.getValue(reconstructed), "Flag should survive round-trip conversion")
		})
	}
}

func TestUACCommonScenarios(t *testing.T) {
	t.Run("typical user account scenarios", func(t *testing.T) {
		scenarios := []struct {
			name     string
			uac      UAC
			expected uint32
			enabled  bool
		}{
			{
				name: "enabled normal user",
				uac: UAC{
					NormalAccount: true,
				},
				expected: 512, // 0x200
				enabled:  true,
			},
			{
				name: "disabled normal user",
				uac: UAC{
					NormalAccount:   true,
					AccountDisabled: true,
				},
				expected: 514, // 0x202
				enabled:  false,
			},
			{
				name: "enabled computer account",
				uac: UAC{
					WorkstationTrustAccount: true,
				},
				expected: 4096, // 0x1000
				enabled:  true,
			},
			{
				name: "disabled computer account",
				uac: UAC{
					WorkstationTrustAccount: true,
					AccountDisabled:         true,
				},
				expected: 4098, // 0x1002
				enabled:  false,
			},
			{
				name: "user with password never expires",
				uac: UAC{
					NormalAccount:        true,
					NoPasswordExpiration: true,
				},
				expected: 66048, // 0x10200
				enabled:  true,
			},
		}

		for _, scenario := range scenarios {
			t.Run(scenario.name, func(t *testing.T) {
				// Test UAC to uint32 conversion
				value := scenario.uac.Uint32()
				assert.Equal(t, scenario.expected, value)

				// Test uint32 to UAC conversion
				reconstructed := UACFromUint32(scenario.expected)
				assert.Equal(t, scenario.uac, reconstructed)

				// Test enabled/disabled logic
				isEnabled := !scenario.uac.AccountDisabled
				assert.Equal(t, scenario.enabled, isEnabled)
			})
		}
	})
}

func TestUACFlagCombinations(t *testing.T) {
	t.Run("flag combination effects", func(t *testing.T) {
		// Test that multiple flags can be combined correctly
		uac := UAC{
			NormalAccount:                      true,
			NoPasswordExpiration:               true,
			SmartCardRequired:                  true,
			TrustedToAuthenticateForDelegation: true,
		}

		expectedValue := uint32(0x200 | 0x10000 | 0x40000 | 0x1000000) // 0x1050200

		actualValue := uac.Uint32()
		assert.Equal(t, expectedValue, actualValue)

		// Test string representation includes all flags
		stringRep := uac.String()
		assert.Contains(t, stringRep, "NormalAccount")
		assert.Contains(t, stringRep, "NoPasswordExpiration")
		assert.Contains(t, stringRep, "SmartCardRequired")
		assert.Contains(t, stringRep, "TrustedToAuthenticateForDelegation")

		// Test round-trip conversion
		reconstructed := UACFromUint32(actualValue)
		assert.Equal(t, uac, reconstructed)
	})
}

// Benchmark UAC operations
func BenchmarkUACFromUint32(b *testing.B) {
	value := uint32(0x10200) // Normal account with no password expiration

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = UACFromUint32(value)
	}
}

func BenchmarkUACUint32(b *testing.B) {
	uac := UAC{
		NormalAccount:        true,
		NoPasswordExpiration: true,
		SmartCardRequired:    true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uac.Uint32()
	}
}

func BenchmarkUACString(b *testing.B) {
	uac := UAC{
		NormalAccount:        true,
		NoPasswordExpiration: true,
		SmartCardRequired:    true,
		AccountDisabled:      true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uac.String()
	}
}
