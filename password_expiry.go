package ldap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrPasswordPolicyNotFound is returned when the ppolicy entry a user (or the
// client configuration) points at cannot be read.
var ErrPasswordPolicyNotFound = errors.New("password policy not found")

// PasswordExpiryStatus classifies what a directory reports about a password's
// remaining lifetime.
type PasswordExpiryStatus int

const (
	// PasswordExpiryUnknown means the directory did not supply enough
	// information to decide. On Active Directory this is unusual; on
	// OpenLDAP it is the normal answer when no password policy applies or
	// none could be resolved.
	PasswordExpiryUnknown PasswordExpiryStatus = iota

	// PasswordNeverExpires means expiry is disabled for this account —
	// the DONT_EXPIRE_PASSWORD flag on Active Directory, or a policy with
	// pwdMaxAge of 0 under ppolicy.
	PasswordNeverExpires

	// PasswordExpires means the password has a concrete expiry moment,
	// carried in PasswordExpiry.At. The moment may already be in the past.
	PasswordExpires

	// PasswordMustChange means the account must change its password at the
	// next sign-in regardless of any deadline. Active Directory encodes this
	// as pwdLastSet=0.
	PasswordMustChange
)

// String renders the status for logs and error messages.
func (s PasswordExpiryStatus) String() string {
	switch s {
	case PasswordNeverExpires:
		return "never-expires"
	case PasswordExpires:
		return "expires"
	case PasswordMustChange:
		return "must-change"
	case PasswordExpiryUnknown:
		return "unknown"
	default:
		return "invalid"
	}
}

// PasswordExpiry describes when a user's password expires.
type PasswordExpiry struct {
	// Status classifies the result. Read it before using At.
	Status PasswordExpiryStatus

	// At is the moment the password expires. It is only meaningful when
	// Status is PasswordExpires; it is the zero time otherwise.
	At time.Time
}

// Expired reports whether the deadline has already passed at the given time.
// A must-change account counts as expired: it cannot be used to sign in until
// the password is replaced.
func (e PasswordExpiry) Expired(now time.Time) bool {
	switch e.Status {
	case PasswordMustChange:
		return true
	case PasswordExpires:
		return !e.At.After(now)
	case PasswordExpiryUnknown, PasswordNeverExpires:
		return false
	default:
		return false
	}
}

// ExpiringUser pairs a user with their resolved password expiry.
type ExpiringUser struct {
	User   *User
	Expiry PasswordExpiry
}

// policyCache memoises pwdMaxAge per policy DN so that scanning a directory
// costs one lookup per distinct policy rather than one per user.
type policyCache struct {
	mu     sync.Mutex
	maxAge map[string]time.Duration
}

func newPolicyCache() *policyCache {
	return &policyCache{maxAge: make(map[string]time.Duration)}
}

// PasswordExpiryFor reports when the given user's password expires.
//
// Active Directory answers from the entry alone: the constructed attribute
// msDS-UserPasswordExpiryTimeComputed already folds in the domain policy and
// any Password Settings Object, so no privileged read of the Password
// Settings Container is required.
//
// OpenLDAP needs the ppolicy overlay: expiry is pwdChangedTime plus the
// pwdMaxAge of the governing policy. The policy is taken from the entry's
// pwdPolicySubentry, falling back to Config.PasswordPolicyDN. Without either,
// the result is PasswordExpiryUnknown rather than a guess.
func (l *LDAP) PasswordExpiryFor(ctx context.Context, user *User) (PasswordExpiry, error) {
	if user == nil {
		return PasswordExpiry{}, fmt.Errorf("password expiry: %w", ErrUserNotFound)
	}

	if l.config.IsActiveDirectory {
		return activeDirectoryExpiry(user), nil
	}

	return l.ppolicyExpiry(ctx, user)
}

// activeDirectoryExpiry derives the result from attributes already on the
// entry.
func activeDirectoryExpiry(user *User) PasswordExpiry {
	if user.MustChangePassword {
		return PasswordExpiry{Status: PasswordMustChange}
	}

	switch user.PasswordExpiresAt {
	case 0:
		return PasswordExpiry{Status: PasswordExpiryUnknown}
	case -1:
		return PasswordExpiry{Status: PasswordNeverExpires}
	default:
		return PasswordExpiry{
			Status: PasswordExpires,
			At:     time.Unix(user.PasswordExpiresAt, 0).UTC(),
		}
	}
}

// ppolicyExpiry resolves expiry from pwdChangedTime and the governing policy.
func (l *LDAP) ppolicyExpiry(ctx context.Context, user *User) (PasswordExpiry, error) {
	if user.PwdChangedAt == 0 {
		// No ppolicy state on the entry: either the overlay is absent or the
		// password predates it. Reporting "unknown" is the honest answer —
		// treating it as expiring would mail every account in the directory.
		return PasswordExpiry{Status: PasswordExpiryUnknown}, nil
	}

	policyDN := user.PasswordPolicyDN
	if policyDN == "" {
		policyDN = l.config.PasswordPolicyDN
	}
	if policyDN == "" {
		return PasswordExpiry{Status: PasswordExpiryUnknown}, nil
	}

	maxAge, err := l.passwordMaxAge(ctx, policyDN)
	if err != nil {
		return PasswordExpiry{}, err
	}
	if maxAge <= 0 {
		// pwdMaxAge absent or 0 means passwords under this policy do not age out.
		return PasswordExpiry{Status: PasswordNeverExpires}, nil
	}

	return PasswordExpiry{
		Status: PasswordExpires,
		At:     time.Unix(user.PwdChangedAt, 0).UTC().Add(maxAge),
	}, nil
}

// passwordMaxAge reads pwdMaxAge from a ppolicy entry, caching the result.
func (l *LDAP) passwordMaxAge(ctx context.Context, policyDN string) (time.Duration, error) {
	if cached, ok := l.policies.get(policyDN); ok {
		return cached, nil
	}

	conn, err := l.GetConnectionContext(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()

	req := ldap.NewSearchRequest(
		policyDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"pwdMaxAge"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		// A base-scoped search on a DN that does not exist fails with "No Such
		// Object" rather than returning an empty result set, so translate that
		// one code into the sentinel; anything else is a real transport or
		// server error and is wrapped as-is.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return 0, fmt.Errorf("read password policy %q: %w", policyDN, ErrPasswordPolicyNotFound)
		}

		return 0, fmt.Errorf("read password policy %q: %w", policyDN, err)
	}

	// A base-scoped search either errors (handled above) or returns exactly the
	// one entry, so res.Entries[0] is safe without a length guard.
	maxAge := parsePwdMaxAge(res.Entries[0].GetAttributeValue("pwdMaxAge"))
	l.policies.put(policyDN, maxAge)

	return maxAge, nil
}

// parsePwdMaxAge converts the ppolicy pwdMaxAge attribute, expressed in
// seconds, into a duration. An absent, malformed or zero value yields 0,
// which callers read as "passwords do not expire".
func parsePwdMaxAge(value string) time.Duration {
	if value == "" {
		return 0
	}

	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}

	return time.Duration(seconds) * time.Second
}

// get is nil-safe: a client assembled directly (as several tests do) has no
// cache, and a lookup should simply miss rather than panic.
func (c *policyCache) get(dn string) (time.Duration, bool) {
	if c == nil {
		return 0, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.maxAge[dn]

	return d, ok
}

func (c *policyCache) put(dn string, d time.Duration) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxAge[dn] = d
}

// UsersWithExpiringPasswords returns the enabled users whose password expires
// within the given window, oldest deadline first.
//
// Accounts that cannot receive a warning, or for which one would be wrong, are
// left out: disabled accounts, passwords that never expire, and entries the
// directory reports nothing about. Accounts that must change at next sign-in
// are included with status PasswordMustChange, since they are the ones already
// locked out.
//
// The disabled filter relies on User.Enabled, which is derived from
// userAccountControl. OpenLDAP has no such attribute, so every OpenLDAP user
// reads as enabled: a caller that must exclude deactivated OpenLDAP accounts
// has to do so by its own criterion (an ou, a group, a ppolicy lock) before
// notifying.
//
// Already-expired accounts are included: a caller warning about expiry
// generally also wants to know who is past the deadline. Filter on
// Expiry.Expired if that is not wanted.
func (l *LDAP) UsersWithExpiringPasswords(ctx context.Context, within time.Duration) ([]ExpiringUser, error) {
	users, err := l.FindUsersContext(ctx)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().UTC().Add(within)

	resolve := func(u *User) (PasswordExpiry, error) { return l.PasswordExpiryFor(ctx, u) }

	return collectExpiring(users, deadline, resolve)
}

// collectExpiring is the loop half of UsersWithExpiringPasswords, split from
// the enumeration so the disabled-skip and error-propagation paths are
// testable with a fake resolver instead of a faulting directory. resolve is
// called only for enabled users, in order.
func collectExpiring(
	users []User,
	deadline time.Time,
	resolve func(*User) (PasswordExpiry, error),
) ([]ExpiringUser, error) {
	expiring := make([]ExpiringUser, 0, len(users))

	for i := range users {
		user := &users[i]
		if !user.Enabled {
			continue
		}

		expiry, err := resolve(user)
		if err != nil {
			return nil, err
		}

		if entry, ok := classifyExpiring(user, expiry, deadline); ok {
			expiring = append(expiring, entry)
		}
	}

	sortExpiringUsers(expiring)

	return expiring, nil
}

// classifyExpiring decides whether a resolved expiry belongs in the
// within-window result, and returns the entry to add when it does. It is the
// pure half of UsersWithExpiringPasswords, split out so every inclusion rule
// is testable without a directory.
//
// A must-change account is always included: it is already blocked, so the
// deadline is irrelevant. An expiring account is included only when its
// deadline falls on or before the window's edge. Unknown and never-expires are
// never included — acting on them is what would mail an entire directory.
func classifyExpiring(user *User, expiry PasswordExpiry, deadline time.Time) (ExpiringUser, bool) {
	switch expiry.Status {
	case PasswordMustChange:
		return ExpiringUser{User: user, Expiry: expiry}, true
	case PasswordExpires:
		if !expiry.At.After(deadline) {
			return ExpiringUser{User: user, Expiry: expiry}, true
		}

		return ExpiringUser{}, false
	case PasswordExpiryUnknown, PasswordNeverExpires:
		return ExpiringUser{}, false
	default:
		return ExpiringUser{}, false
	}
}

// sortExpiringUsers orders by deadline, must-change first since those accounts
// are already blocked.
func sortExpiringUsers(users []ExpiringUser) {
	slices.SortFunc(users, func(a, b ExpiringUser) int {
		if a.Expiry.Status != b.Expiry.Status {
			if a.Expiry.Status == PasswordMustChange {
				return -1
			}
			if b.Expiry.Status == PasswordMustChange {
				return 1
			}
		}

		return a.Expiry.At.Compare(b.Expiry.At)
	})
}
