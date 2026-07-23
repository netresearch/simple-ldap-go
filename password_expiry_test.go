package ldap

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestPasswordExpiryStatus_String(t *testing.T) {
	tests := []struct {
		status PasswordExpiryStatus
		want   string
	}{
		{PasswordExpiryUnknown, "unknown"},
		{PasswordNeverExpires, "never-expires"},
		{PasswordExpires, "expires"},
		{PasswordMustChange, "must-change"},
		{PasswordExpiryStatus(99), "invalid"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("PasswordExpiryStatus(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestPasswordExpiry_Expired(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		in   PasswordExpiry
		want bool
	}{
		{
			name: "deadline in the future",
			in:   PasswordExpiry{Status: PasswordExpires, At: now.Add(time.Hour)},
			want: false,
		},
		{
			name: "deadline in the past",
			in:   PasswordExpiry{Status: PasswordExpires, At: now.Add(-time.Hour)},
			want: true,
		},
		{
			// The deadline is the moment access stops, so reaching it exactly
			// counts as expired rather than as the last usable instant.
			name: "deadline exactly now",
			in:   PasswordExpiry{Status: PasswordExpires, At: now},
			want: true,
		},
		{
			name: "must change at next sign-in",
			in:   PasswordExpiry{Status: PasswordMustChange},
			want: true,
		},
		{
			name: "never expires",
			in:   PasswordExpiry{Status: PasswordNeverExpires},
			want: false,
		},
		{
			// Unknown must never be reported as expired: a caller acting on it
			// would lock out or mail every account the directory is quiet about.
			name: "unknown",
			in:   PasswordExpiry{Status: PasswordExpiryUnknown},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.Expired(now); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActiveDirectoryExpiry(t *testing.T) {
	const expiryUnix = int64(1785600000)

	tests := []struct {
		name       string
		user       User
		wantStatus PasswordExpiryStatus
		wantAt     time.Time
	}{
		{
			// pwdLastSet=0 outranks any deadline: the account cannot sign in
			// until the password is replaced.
			name:       "must change wins over a concrete deadline",
			user:       User{MustChangePassword: true, PasswordExpiresAt: expiryUnix},
			wantStatus: PasswordMustChange,
		},
		{
			name:       "never expires sentinel",
			user:       User{PasswordExpiresAt: -1},
			wantStatus: PasswordNeverExpires,
		},
		{
			name:       "attribute absent",
			user:       User{},
			wantStatus: PasswordExpiryUnknown,
		},
		{
			name:       "concrete deadline",
			user:       User{PasswordExpiresAt: expiryUnix},
			wantStatus: PasswordExpires,
			wantAt:     time.Unix(expiryUnix, 0).UTC(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := activeDirectoryExpiry(&tt.user)

			if got.Status != tt.wantStatus {
				t.Errorf("Status = %v, want %v", got.Status, tt.wantStatus)
			}
			if !tt.wantAt.IsZero() && !got.At.Equal(tt.wantAt) {
				t.Errorf("At = %v, want %v", got.At, tt.wantAt)
			}
		})
	}
}

func TestParsePwdMaxAge(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"absent", "", 0},
		{"zero means no ageing", "0", 0},
		{"negative is nonsense", "-1", 0},
		{"not a number", "ninety days", 0},
		{"ninety days in seconds", "7776000", 90 * 24 * time.Hour},
		{"one hour", "3600", time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parsePwdMaxAge(tt.value); got != tt.want {
				t.Errorf("parsePwdMaxAge(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// Without ppolicy state or a policy DN the answer must be "unknown". Guessing
// here would make a notifier mail an entire directory.
func TestPpolicyExpiry_UnknownWithoutEnoughInformation(t *testing.T) {
	tests := []struct {
		name   string
		user   User
		config Config
	}{
		{
			name: "no pwdChangedTime on the entry",
			user: User{PasswordPolicyDN: "cn=default,ou=policies,dc=example,dc=com"},
		},
		{
			name: "pwdChangedTime but no policy anywhere",
			user: User{PwdChangedAt: 1750000000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config
			client := &LDAP{config: &cfg}

			got, err := client.ppolicyExpiry(t.Context(), &tt.user)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != PasswordExpiryUnknown {
				t.Errorf("Status = %v, want %v", got.Status, PasswordExpiryUnknown)
			}
		})
	}
}

// A cached policy is enough to answer, so no connection is attempted — which
// is what makes this testable without a server, and what keeps a directory
// scan from issuing one policy read per user.
func TestPpolicyExpiry_UsesTheCachedPolicy(t *testing.T) {
	const policyDN = "cn=default,ou=policies,dc=example,dc=com"

	changed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := Config{}
	client := &LDAP{config: &cfg, policies: newPolicyCache()}
	client.policies.put(policyDN, 90*24*time.Hour)

	user := User{PwdChangedAt: changed.Unix(), PasswordPolicyDN: policyDN}

	got, err := client.ppolicyExpiry(t.Context(), &user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != PasswordExpires {
		t.Fatalf("Status = %v, want %v", got.Status, PasswordExpires)
	}
	if want := changed.Add(90 * 24 * time.Hour); !got.At.Equal(want) {
		t.Errorf("At = %v, want %v", got.At, want)
	}
}

// A policy with pwdMaxAge 0 disables ageing; it must not be reported as an
// immediate expiry.
func TestPpolicyExpiry_ZeroMaxAgeNeverExpires(t *testing.T) {
	const policyDN = "cn=nolapse,ou=policies,dc=example,dc=com"

	cfg := Config{PasswordPolicyDN: policyDN}
	client := &LDAP{config: &cfg, policies: newPolicyCache()}
	client.policies.put(policyDN, 0)

	got, err := client.ppolicyExpiry(t.Context(), &User{PwdChangedAt: 1750000000})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != PasswordNeverExpires {
		t.Errorf("Status = %v, want %v", got.Status, PasswordNeverExpires)
	}
}

// The per-user pwdPolicySubentry must win over the client-wide default.
func TestPpolicyExpiry_EntryPolicyOverridesTheDefault(t *testing.T) {
	const (
		defaultDN = "cn=default,ou=policies,dc=example,dc=com"
		strictDN  = "cn=strict,ou=policies,dc=example,dc=com"
	)

	changed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := Config{PasswordPolicyDN: defaultDN}
	client := &LDAP{config: &cfg, policies: newPolicyCache()}
	client.policies.put(defaultDN, 365*24*time.Hour)
	client.policies.put(strictDN, 30*24*time.Hour)

	user := User{PwdChangedAt: changed.Unix(), PasswordPolicyDN: strictDN}

	got, err := client.ppolicyExpiry(t.Context(), &user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := changed.Add(30 * 24 * time.Hour); !got.At.Equal(want) {
		t.Errorf("At = %v, want %v — the entry's own policy should win", got.At, want)
	}
}

func TestPasswordExpiryFor_NilUser(t *testing.T) {
	cfg := Config{}
	client := &LDAP{config: &cfg}

	if _, err := client.PasswordExpiryFor(t.Context(), nil); err == nil {
		t.Fatal("expected an error for a nil user")
	}
}

// A client assembled without the constructor has no cache; lookups must miss
// rather than panic.
func TestPolicyCache_NilReceiverIsSafe(t *testing.T) {
	var c *policyCache

	if _, ok := c.get("cn=whatever"); ok {
		t.Error("a nil cache must not report a hit")
	}
	c.put("cn=whatever", time.Hour)
}

func TestSortExpiringUsers(t *testing.T) {
	base := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	users := []ExpiringUser{
		{User: &User{SAMAccountName: "late"}, Expiry: PasswordExpiry{Status: PasswordExpires, At: base.Add(48 * time.Hour)}},
		{User: &User{SAMAccountName: "blocked"}, Expiry: PasswordExpiry{Status: PasswordMustChange}},
		{User: &User{SAMAccountName: "soon"}, Expiry: PasswordExpiry{Status: PasswordExpires, At: base.Add(time.Hour)}},
	}

	sortExpiringUsers(users)

	want := []string{"blocked", "soon", "late"}
	for i, name := range want {
		if users[i].User.SAMAccountName != name {
			t.Errorf("position %d = %q, want %q", i, users[i].User.SAMAccountName, name)
		}
	}
}

// The Active Directory branch answers from the entry alone, so it is reachable
// without a server — unlike the ppolicy branch, which needs a policy read.
func TestPasswordExpiryFor_ActiveDirectoryBranch(t *testing.T) {
	const expiryUnix = int64(1785600000)

	cfg := Config{IsActiveDirectory: true}
	client := &LDAP{config: &cfg}

	got, err := client.PasswordExpiryFor(t.Context(), &User{PasswordExpiresAt: expiryUnix})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != PasswordExpires {
		t.Fatalf("Status = %v, want %v", got.Status, PasswordExpires)
	}
	if want := time.Unix(expiryUnix, 0).UTC(); !got.At.Equal(want) {
		t.Errorf("At = %v, want %v", got.At, want)
	}

	// The ppolicy attributes must be ignored on Active Directory: pwdChangedTime
	// is not what governs expiry there, and honouring it would produce a second,
	// contradictory answer.
	mixed, err := client.PasswordExpiryFor(t.Context(), &User{
		PasswordExpiresAt: -1,
		PwdChangedAt:      1750000000,
		PasswordPolicyDN:  "cn=default,dc=example,dc=com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mixed.Status != PasswordNeverExpires {
		t.Errorf("Status = %v, want %v — ppolicy attributes must not override AD", mixed.Status, PasswordNeverExpires)
	}
}

// An out-of-range status must never read as expired; the zero value of a future
// enum addition would otherwise lock people out.
func TestPasswordExpiry_ExpiredRejectsUnknownStatus(t *testing.T) {
	e := PasswordExpiry{Status: PasswordExpiryStatus(99), At: time.Unix(0, 0)}
	if e.Expired(time.Now()) {
		t.Error("an unrecognised status must not be reported as expired")
	}
}

// unreachableClient is assembled directly, without New's eager connect, so it
// dials only when a method reaches the network — pointing at a closed port
// then exercises the error paths a happy-path test cannot reach. It matches
// the direct-construction pattern the auth tests use for the same purpose.
func unreachableClient(t *testing.T) *LDAP {
	t.Helper()

	return &LDAP{
		config:   &Config{Server: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org"},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		policies: newPolicyCache(),
	}
}

// A policy read that cannot connect must propagate the error rather than
// resolve to a deadline. The policy is not cached, so passwordMaxAge dials.
func TestPpolicyExpiry_ConnectionErrorPropagates(t *testing.T) {
	client := unreachableClient(t)
	client.config.PasswordPolicyDN = "cn=default,dc=example,dc=org"

	_, err := client.PasswordExpiryFor(t.Context(), &User{PwdChangedAt: 1750000000})
	if err == nil {
		t.Fatal("expected a connection error to propagate from the policy read")
	}
}

// The directory scan must surface a failure to enumerate users rather than
// return a partial, misleading list.
func TestUsersWithExpiringPasswords_EnumerationErrorPropagates(t *testing.T) {
	client := unreachableClient(t)

	if _, err := client.UsersWithExpiringPasswords(t.Context(), 30*24*time.Hour); err == nil {
		t.Fatal("expected the user enumeration error to propagate")
	}
}

func TestClassifyExpiring(t *testing.T) {
	deadline := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		expiry PasswordExpiry
		wantOK bool
	}{
		{
			name:   "must change is always included",
			expiry: PasswordExpiry{Status: PasswordMustChange},
			wantOK: true,
		},
		{
			name:   "expires within the window",
			expiry: PasswordExpiry{Status: PasswordExpires, At: deadline.Add(-time.Hour)},
			wantOK: true,
		},
		{
			name:   "expires exactly on the window edge",
			expiry: PasswordExpiry{Status: PasswordExpires, At: deadline},
			wantOK: true,
		},
		{
			name:   "expires after the window",
			expiry: PasswordExpiry{Status: PasswordExpires, At: deadline.Add(time.Hour)},
			wantOK: false,
		},
		{
			name:   "unknown is excluded",
			expiry: PasswordExpiry{Status: PasswordExpiryUnknown},
			wantOK: false,
		},
		{
			name:   "never expires is excluded",
			expiry: PasswordExpiry{Status: PasswordNeverExpires},
			wantOK: false,
		},
		{
			name:   "unrecognised status is excluded",
			expiry: PasswordExpiry{Status: PasswordExpiryStatus(99)},
			wantOK: false,
		},
	}

	user := &User{SAMAccountName: "sample"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, ok := classifyExpiring(user, tt.expiry, deadline)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && entry.User != user {
				t.Error("an included entry should carry the user it was built from")
			}
		})
	}
}

func TestCollectExpiring(t *testing.T) {
	deadline := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	resolve := func(u *User) (PasswordExpiry, error) {
		// The name encodes the expiry so the fake needs no state.
		switch u.SAMAccountName {
		case "soon":
			return PasswordExpiry{Status: PasswordExpires, At: deadline.Add(-time.Hour)}, nil
		case "later":
			return PasswordExpiry{Status: PasswordExpires, At: deadline.Add(time.Hour)}, nil
		case "blocked":
			return PasswordExpiry{Status: PasswordMustChange}, nil
		default:
			return PasswordExpiry{Status: PasswordExpiryUnknown}, nil
		}
	}

	users := []User{
		{SAMAccountName: "soon", Enabled: true},
		{SAMAccountName: "later", Enabled: true},
		{SAMAccountName: "blocked", Enabled: true},
		// Disabled but soon-to-expire: it must be skipped before the resolver
		// is even asked.
		{SAMAccountName: "soon", Enabled: false},
	}

	got, err := collectExpiring(users, deadline, resolve)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// blocked (must-change, sorts first) then soon; later is outside the window,
	// the disabled one is skipped.
	want := []string{"blocked", "soon"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i].User.SAMAccountName != name {
			t.Errorf("position %d = %q, want %q", i, got[i].User.SAMAccountName, name)
		}
	}
}

// An error from the resolver aborts the scan rather than yielding a partial
// list a caller might act on as if complete.
func TestCollectExpiring_ResolverErrorPropagates(t *testing.T) {
	sentinel := errors.New("resolver failed")
	resolve := func(*User) (PasswordExpiry, error) { return PasswordExpiry{}, sentinel }

	_, err := collectExpiring([]User{{SAMAccountName: "x", Enabled: true}}, time.Now(), resolve)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the resolver error", err)
	}
}

// A disabled user must be skipped before the resolver runs — the resolver here
// fails the test if it is ever called.
func TestCollectExpiring_DisabledUserSkipsTheResolver(t *testing.T) {
	resolve := func(*User) (PasswordExpiry, error) {
		t.Fatal("resolver must not be called for a disabled user")

		return PasswordExpiry{}, nil
	}

	got, err := collectExpiring([]User{{SAMAccountName: "off", Enabled: false}}, time.Now(), resolve)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want none", len(got))
	}
}
