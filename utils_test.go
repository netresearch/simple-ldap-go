package ldap

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseObjectEnabled(t *testing.T) {
	tests := []struct {
		name               string
		userAccountControl string
		expectedEnabled    bool
		expectedError      bool
	}{
		{
			name:               "enabled normal user account",
			userAccountControl: "512", // 0x200 - ADS_UF_NORMAL_ACCOUNT
			expectedEnabled:    true,
			expectedError:      false,
		},
		{
			name:               "disabled normal user account",
			userAccountControl: "514", // 0x202 - ADS_UF_NORMAL_ACCOUNT | ADS_UF_ACCOUNTDISABLE
			expectedEnabled:    false,
			expectedError:      false,
		},
		{
			name:               "enabled workstation trust account",
			userAccountControl: "4096", // 0x1000 - ADS_UF_WORKSTATION_TRUST_ACCOUNT
			expectedEnabled:    true,
			expectedError:      false,
		},
		{
			name:               "disabled workstation trust account",
			userAccountControl: "4098", // 0x1002 - ADS_UF_WORKSTATION_TRUST_ACCOUNT | ADS_UF_ACCOUNTDISABLE
			expectedEnabled:    false,
			expectedError:      false,
		},
		{
			name:               "user with multiple flags but enabled",
			userAccountControl: "66048", // 0x10200 - ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD
			expectedEnabled:    true,
			expectedError:      false,
		},
		{
			name:               "user with multiple flags but disabled",
			userAccountControl: "66050", // 0x10202 - ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD | ADS_UF_ACCOUNTDISABLE
			expectedEnabled:    false,
			expectedError:      false,
		},
		{
			name:               "zero value (should be enabled)",
			userAccountControl: "0",
			expectedEnabled:    true,
			expectedError:      false,
		},
		{
			name:               "only disabled flag set",
			userAccountControl: "2", // 0x2 - ADS_UF_ACCOUNTDISABLE
			expectedEnabled:    false,
			expectedError:      false,
		},
		{
			name:               "invalid string",
			userAccountControl: "invalid",
			expectedEnabled:    false,
			expectedError:      true,
		},
		{
			name:               "empty string",
			userAccountControl: "",
			expectedEnabled:    false,
			expectedError:      true,
		},
		{
			name:               "negative number",
			userAccountControl: "-1",
			expectedEnabled:    false, // -1 in binary has all bits set (including bit 1), so disabled
			expectedError:      false, // parseObjectEnabled accepts negative numbers
		},
		{
			name:               "number too large for int32",
			userAccountControl: "4294967296", // 2^32
			expectedEnabled:    false,
			expectedError:      true,
		},
		{
			name:               "hexadecimal string",
			userAccountControl: "0x200",
			expectedEnabled:    false,
			expectedError:      true, // parseObjectEnabled expects decimal strings
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, err := parseObjectEnabled(tt.userAccountControl)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedEnabled, enabled)
			}
		})
	}
}

func TestParseObjectEnabledBitwise(t *testing.T) {
	// Test specific bit combinations to ensure proper bitwise operations
	t.Run("bitwise flag combinations", func(t *testing.T) {
		testCases := []struct {
			flags   []uint32
			enabled bool
		}{
			{[]uint32{}, true},                     // No flags = enabled
			{[]uint32{0x1}, true},                  // Logon script = enabled
			{[]uint32{0x2}, false},                 // Account disabled = disabled
			{[]uint32{0x1, 0x2}, false},            // Logon script + disabled = disabled
			{[]uint32{0x200}, true},                // Normal account = enabled
			{[]uint32{0x200, 0x2}, false},          // Normal account + disabled = disabled
			{[]uint32{0x200, 0x10000}, true},       // Normal + no pwd expiry = enabled
			{[]uint32{0x200, 0x10000, 0x2}, false}, // Normal + no pwd expiry + disabled = disabled
			{[]uint32{0x1000}, true},               // Workstation trust = enabled
			{[]uint32{0x1000, 0x2}, false},         // Workstation trust + disabled = disabled
		}

		for i, tc := range testCases {
			t.Run(fmt.Sprintf("combination_%d", i), func(t *testing.T) {
				var combined uint32
				for _, flag := range tc.flags {
					combined |= flag
				}

				enabled, err := parseObjectEnabled(strconv.Itoa(int(combined)))
				assert.NoError(t, err)
				assert.Equal(t, tc.enabled, enabled,
					"Combined flags 0x%X should result in enabled=%v", combined, tc.enabled)
			})
		}
	})
}

func TestConvertAccountExpires(t *testing.T) {
	tests := []struct {
		name     string
		target   *time.Time
		validate func(*testing.T, string)
	}{
		{
			name:   "nil target (never expires)",
			target: nil,
			validate: func(t *testing.T, result string) {
				expected := fmt.Sprintf("%d", accountExpiresNever)
				assert.Equal(t, expected, result)
			},
		},
		{
			name:   "epoch time (January 1, 1970)",
			target: &time.Time{}, // Zero value is January 1, year 1
			validate: func(t *testing.T, result string) {
				// Should be negative since it's before 1601
				assert.NotEmpty(t, result)
				// Parsing should not error
				_, err := strconv.ParseInt(result, 10, 64)
				assert.NoError(t, err)
			},
		},
		{
			name:   "AD base time (January 1, 1601)",
			target: &accountExpiresBase,
			validate: func(t *testing.T, result string) {
				assert.Equal(t, "0", result)
			},
		},
		{
			name:   "time after AD base",
			target: func() *time.Time { t := accountExpiresBase.Add(24 * time.Hour); return &t }(),
			validate: func(t *testing.T, result string) {
				// Should be positive
				value, err := strconv.ParseInt(result, 10, 64)
				assert.NoError(t, err)
				assert.Greater(t, value, int64(0))

				// Should represent 24 hours in 100-nanosecond intervals
				expected := 24 * 60 * 60 * 1000 * 1000 * 10 // 24 hours in 100ns intervals
				assert.Equal(t, int64(expected), value)
			},
		},
		{
			name:   "time before AD base",
			target: func() *time.Time { t := accountExpiresBase.Add(-24 * time.Hour); return &t }(),
			validate: func(t *testing.T, result string) {
				// Should be negative
				value, err := strconv.ParseInt(result, 10, 64)
				assert.NoError(t, err)
				assert.Less(t, value, int64(0))
			},
		},
		{
			name:   "modern time (year 2024)",
			target: func() *time.Time { t := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC); return &t }(),
			validate: func(t *testing.T, result string) {
				// Should be a very large positive number
				value, err := strconv.ParseInt(result, 10, 64)
				assert.NoError(t, err)
				assert.Greater(t, value, int64(1000000000)) // Should be very large
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertAccountExpires(tt.target)
			assert.NotEmpty(t, result)
			tt.validate(t, result)
		})
	}
}

func TestConvertAccountExpiresConstants(t *testing.T) {
	t.Run("accountExpiresNever constant", func(t *testing.T) {
		// Verify the constant value matches Microsoft documentation
		assert.Equal(t, uint64(0x7FFFFFFFFFFFFFFF), accountExpiresNever)
		assert.Equal(t, uint64(9223372036854775807), accountExpiresNever)
	})

	t.Run("accountExpiresBase constant", func(t *testing.T) {
		// Verify base date is January 1, 1601 UTC
		expected := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
		assert.Equal(t, expected, accountExpiresBase)
	})
}

func TestConvertAccountExpiresNanosecondConversion(t *testing.T) {
	t.Run("nanosecond to 100-nanosecond conversion", func(t *testing.T) {
		// Test the division by 100 for nanosecond conversion
		baseTime := accountExpiresBase

		// Add exactly 1 second
		oneSecondLater := baseTime.Add(1 * time.Second)
		result := convertAccountExpires(&oneSecondLater)

		value, err := strconv.ParseInt(result, 10, 64)
		assert.NoError(t, err)

		// 1 second = 1,000,000,000 nanoseconds
		// 1,000,000,000 nanoseconds / 100 = 10,000,000 intervals of 100 nanoseconds
		assert.Equal(t, int64(10000000), value)
	})
}

func TestConvertAccountExpiresEdgeCases(t *testing.T) {
	t.Run("very far future", func(t *testing.T) {
		// Test with a date far in the future
		farFuture := time.Date(3000, 12, 31, 23, 59, 59, 0, time.UTC)
		result := convertAccountExpires(&farFuture)

		// Should not error and should be a valid string representation of a large number
		value, err := strconv.ParseInt(result, 10, 64)
		assert.NoError(t, err)
		assert.Greater(t, value, int64(0))
	})

	t.Run("very far past", func(t *testing.T) {
		// Test with a date far in the past (before 1601)
		farPast := time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)
		result := convertAccountExpires(&farPast)

		// Should not error and should be a valid string representation of a negative number
		value, err := strconv.ParseInt(result, 10, 64)
		assert.NoError(t, err)
		assert.Less(t, value, int64(0))
	})
}

func TestUtilsErrorHandling(t *testing.T) {
	t.Run("parseObjectEnabled error propagation", func(t *testing.T) {
		invalidInputs := []string{
			"not-a-number",
			"",
			"123.456",
			"123abc",
			"abc123",
			"  123  ", // Leading/trailing spaces might cause issues
		}

		for _, input := range invalidInputs {
			t.Run("invalid_input_"+input, func(t *testing.T) {
				_, err := parseObjectEnabled(input)
				assert.Error(t, err, "Should error for input: %q", input)
			})
		}
	})
}

func TestUtilsIntegrationWithUAC(t *testing.T) {
	// Test integration between utils functions and UAC functionality
	t.Run("parseObjectEnabled with UAC values", func(t *testing.T) {
		// Test common UAC combinations
		commonUACValues := []struct {
			uac     UAC
			enabled bool
		}{
			{UAC{NormalAccount: true}, true},
			{UAC{NormalAccount: true, AccountDisabled: true}, false},
			{UAC{WorkstationTrustAccount: true}, true},
			{UAC{WorkstationTrustAccount: true, AccountDisabled: true}, false},
			{UAC{ServerTrustAccount: true}, true},
			{UAC{ServerTrustAccount: true, AccountDisabled: true}, false},
		}

		for i, tc := range commonUACValues {
			t.Run(fmt.Sprintf("uac_integration_%d", i), func(t *testing.T) {
				// Convert UAC to uint32, then to string for parseObjectEnabled
				uacValue := tc.uac.Uint32()
				uacString := strconv.FormatUint(uint64(uacValue), 10)

				enabled, err := parseObjectEnabled(uacString)
				assert.NoError(t, err)
				assert.Equal(t, tc.enabled, enabled)
			})
		}
	})
}

func TestUtilsDocumentationExamples(t *testing.T) {
	// Test examples that would be in documentation
	t.Run("documentation examples", func(t *testing.T) {
		// Example 1: Normal enabled user
		enabled, err := parseObjectEnabled("512") // ADS_UF_NORMAL_ACCOUNT
		assert.NoError(t, err)
		assert.True(t, enabled)

		// Example 2: Disabled user
		disabled, err := parseObjectEnabled("514") // ADS_UF_NORMAL_ACCOUNT | ADS_UF_ACCOUNTDISABLE
		assert.NoError(t, err)
		assert.False(t, disabled)

		// Example 3: Never expires
		neverExpires := convertAccountExpires(nil)
		assert.Equal(t, "9223372036854775807", neverExpires)

		// Example 4: Specific expiration
		expirationDate := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
		expires := convertAccountExpires(&expirationDate)
		assert.NotEmpty(t, expires)
		assert.NotEqual(t, "9223372036854775807", expires)
	})
}

// Benchmark utility functions
func BenchmarkParseObjectEnabled(b *testing.B) {
	testValue := "514" // Disabled normal account

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parseObjectEnabled(testValue)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConvertAccountExpires(b *testing.B) {
	expirationDate := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertAccountExpires(&expirationDate)
	}
}

func BenchmarkConvertAccountExpiresNil(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertAccountExpires(nil)
	}
}
