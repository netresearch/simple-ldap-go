package ldap

import "testing"

// TestParseFileTimeSeconds covers the alias used for pwdLastSet and
// lockoutTime. Since it delegates to parseLastLogonTimestamp, this is
// mostly a smoke test: empty/zero/garbage all yield 0, a known AD
// FILETIME yields the expected Unix seconds.
func TestParseFileTimeSeconds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  int64
	}{
		{"empty", "", 0},
		{"zero", "0", 0},
		{"garbage", "not-a-number", 0},
		// 133253376000000000 is 2023-04-07 12:00:00 UTC in AD FILETIME
		// (= 116444736000000000 + 1680864000 × 10_000_000).
		{"known_ad_filetime", "133253376000000000", 1680864000},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := parseFileTimeSeconds(tc.input); got != tc.want {
				t.Fatalf("parseFileTimeSeconds(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestParseAccountExpires verifies the three-way interpretation:
// 0/empty → 0; AD sentinel "never" → -1; otherwise timestamp.
func TestParseAccountExpires(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  int64
	}{
		{"empty", "", 0},
		{"zero", "0", 0},
		{"never_sentinel", "9223372036854775807", -1},
		{"garbage", "abc", 0},
		// Real expiry timestamp: 2030-01-01 00:00:00 UTC.
		// FILETIME for that date is 135379296000000000 (= 116444736000000000
		// [1601→1970 gap] + 1893456000 * 10_000_000 [unix seconds × 100 ns]).
		{"real_expiry", "135379296000000000", 1893456000},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := parseAccountExpires(tc.input); got != tc.want {
				t.Fatalf("parseAccountExpires(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestParseGeneralizedTime covers the common AD variants.
func TestParseGeneralizedTime(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  int64
	}{
		{"empty", "", 0},
		{"garbage", "2024-01-01", 0},
		{"without_frac", "20230101120000Z", 1672574400},
		{"with_frac_short", "20230101120000.0Z", 1672574400},
		{"with_frac_long", "20230101120000.000Z", 1672574400},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := parseGeneralizedTime(tc.input); got != tc.want {
				t.Fatalf("parseGeneralizedTime(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
