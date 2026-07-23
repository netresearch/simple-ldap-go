package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	// ErrUserNotFound is returned when a user search operation finds no matching entries.
	ErrUserNotFound = errors.New("user not found")
	// ErrSAMAccountNameDuplicated is returned when multiple users have the same sAMAccountName,
	// indicating a data integrity issue in the directory.
	ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")
	// ErrMailDuplicated is returned when multiple users have the same email address,
	// indicating a data integrity issue in the directory.
	ErrMailDuplicated = errors.New("mail is not unique")

	// accountExpiresBase is the base date for Active Directory account expiration calculations (January 1, 1601 UTC).
	accountExpiresBase = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	// accountExpiresNever represents the value for accounts that never expire in Active Directory.
	accountExpiresNever uint64 = 0x7FFFFFFFFFFFFFFF

	// userFields contains the standard LDAP attributes retrieved for user
	// objects. The list is shared between AD and OpenLDAP searches — servers
	// silently ignore attribute names they do not know.
	userFields = []string{
		// Core identity
		"memberOf", "cn", "sAMAccountName", "uid", "mail",
		"userAccountControl", "description", "lastLogonTimestamp",
		// Extended identity / org
		"givenName", "sn", "displayName", "title", "department", "company",
		"manager", "telephoneNumber", "mobile", "physicalDeliveryOfficeName",
		// Security posture
		"accountExpires", "pwdLastSet", "lockoutTime",
		// Password expiry. msDS-UserPasswordExpiryTimeComputed is an Active
		// Directory *constructed* attribute — the server folds the domain
		// policy and any Password Settings Object into it, so it is only
		// returned when named explicitly. pwdChangedTime and pwdPolicySubentry
		// are the OpenLDAP ppolicy counterparts and are *operational*, which
		// likewise excludes them from a default search.
		"msDS-UserPasswordExpiryTimeComputed", "pwdChangedTime", "pwdPolicySubentry",
		// Privileged-account marker — AD sets adminCount=1 on users who are
		// (or were) members of a protected group (Domain Admins, Enterprise
		// Admins, Administrators, …). Used by clients to tag privileged
		// accounts without walking nested group membership.
		"adminCount",
		// Audit
		"whenCreated", "whenChanged",
	}
)

// User represents an LDAP user object with common attributes.
type User struct {
	Object
	// Enabled indicates whether the user account is enabled (not disabled by userAccountControl).
	Enabled bool
	// SAMAccountName is the Security Account Manager account name (unique identifier for Windows authentication).
	SAMAccountName string
	// Description contains the user's description or notes.
	Description string
	// Mail contains the user's email address (nil if not set).
	Mail *string
	// LastLogon contains the timestamp of the last logon (from lastLogonTimestamp, replicated).
	LastLogon int64
	// GivenName is the user's first (given) name.
	GivenName string
	// Surname is the user's last (family) name (LDAP `sn`).
	Surname string
	// DisplayName is the user's presentation name — may differ from CN.
	DisplayName string
	// Title is the user's job title.
	Title string
	// Department names the user's department.
	Department string
	// Company names the user's employer organisation.
	Company string
	// ManagerDN is the distinguished name of the user's manager, or "" when unset.
	ManagerDN string
	// TelephoneNumber is the user's office phone.
	TelephoneNumber string
	// Mobile is the user's mobile phone.
	Mobile string
	// Office is a human-readable office location (physicalDeliveryOfficeName).
	Office string
	// AccountExpires is the Unix-seconds timestamp at which the account expires.
	// Three-value meaning:
	//   0  — not set (no expiry recorded on the entry)
	//   -1 — never expires (AD's sentinel 9223372036854775807 = 0x7FFFFFFFFFFFFFFF)
	//   >0 — concrete expiry timestamp in Unix seconds.
	AccountExpires int64
	// PasswordExpiresAt is the Unix-seconds timestamp at which the current
	// password expires, as reported by Active Directory's constructed
	// msDS-UserPasswordExpiryTimeComputed attribute.
	//   0  — not reported (always the case on non-AD directories)
	//   -1 — never expires
	//   >0 — concrete expiry timestamp in Unix seconds.
	// Use LDAP.PasswordExpiryFor for a directory-independent answer.
	PasswordExpiresAt int64
	// PwdChangedAt is the Unix-seconds timestamp from the OpenLDAP ppolicy
	// operational attribute pwdChangedTime, or 0 when the overlay is not in
	// use. Expiry is this plus the governing policy's pwdMaxAge.
	PwdChangedAt int64
	// PasswordPolicyDN is the ppolicy subentry governing this user, from
	// pwdPolicySubentry. Empty means the directory's default policy applies.
	PasswordPolicyDN string
	// PwdLastSet is the Unix-seconds timestamp at which the user last changed
	// their password, 0 when unset. When the AD value is 0 it means the user
	// must change password at next logon; callers should consult MustChangePassword.
	PwdLastSet int64
	// MustChangePassword is true when pwdLastSet is 0 in AD (forces change
	// on next logon). OpenLDAP servers always report false.
	MustChangePassword bool
	// LockoutTime is the Unix-seconds timestamp of the most recent lockout,
	// 0 when the account is not currently locked.
	LockoutTime int64
	// AdminCount is true when AD has marked this user as privileged by
	// setting `adminCount=1`. AD applies this marker to members of its
	// protected groups (Domain Admins, Enterprise Admins, Administrators,
	// Account Operators, Backup Operators, etc.) via adminSDHolder.
	//
	// Notes for callers:
	//   - adminCount is AD-only. OpenLDAP directories never set it,
	//     so AdminCount is always false on OpenLDAP entries.
	//   - adminCount is STICKY: AD does not clear it when a user is
	//     removed from a protected group. A true value therefore means
	//     "is OR was privileged at some point" — still a strong signal
	//     for UI flagging, but not a perfect real-time membership check.
	//   - For an authoritative real-time answer, fall back to walking
	//     Groups against the well-known protected-group DNs/SIDs.
	AdminCount bool
	// WhenCreated is the Unix-seconds timestamp at which the entry was created.
	WhenCreated int64
	// WhenChanged is the Unix-seconds timestamp at which the entry was last modified.
	WhenChanged int64
	// Groups contains a list of distinguished names (DNs) of groups the user belongs to.
	Groups []string
}

func userFromEntry(entry *ldap.Entry) (*User, error) {
	var enabled bool
	var err error
	var samAccountName string

	// Try to get userAccountControl for Active Directory
	if uac := entry.GetAttributeValue("userAccountControl"); uac != "" {
		enabled, err = parseObjectEnabled(uac)
		if err != nil {
			return nil, err
		}
		samAccountName = entry.GetAttributeValue("sAMAccountName")
	} else {
		// For OpenLDAP compatibility, assume users are enabled by default
		// OpenLDAP doesn't have userAccountControl
		enabled = true
		// Use uid as sAMAccountName equivalent for OpenLDAP
		samAccountName = entry.GetAttributeValue("uid")
		if samAccountName == "" {
			// Fall back to cn if uid is not available
			samAccountName = entry.GetAttributeValue("cn")
		}
	}

	mail := getFirstNonEmptyAttribute(entry, "mail")

	pwdLastSet := parseFileTimeSeconds(entry.GetAttributeValue("pwdLastSet"))
	mustChange := entry.GetAttributeValue("pwdLastSet") == "0"

	return &User{
		Object:             objectFromEntry(entry),
		Enabled:            enabled,
		SAMAccountName:     samAccountName,
		Description:        entry.GetAttributeValue("description"),
		Mail:               mail,
		LastLogon:          parseLastLogonTimestamp(entry.GetAttributeValue("lastLogonTimestamp")),
		GivenName:          entry.GetAttributeValue("givenName"),
		Surname:            entry.GetAttributeValue("sn"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		Title:              entry.GetAttributeValue("title"),
		Department:         entry.GetAttributeValue("department"),
		Company:            entry.GetAttributeValue("company"),
		ManagerDN:          entry.GetAttributeValue("manager"),
		TelephoneNumber:    entry.GetAttributeValue("telephoneNumber"),
		Mobile:             entry.GetAttributeValue("mobile"),
		Office:             entry.GetAttributeValue("physicalDeliveryOfficeName"),
		AccountExpires:     parseAccountExpires(entry.GetAttributeValue("accountExpires")),
		PasswordExpiresAt:  parseAccountExpires(entry.GetAttributeValue("msDS-UserPasswordExpiryTimeComputed")),
		PwdChangedAt:       parseGeneralizedTime(entry.GetAttributeValue("pwdChangedTime")),
		PasswordPolicyDN:   entry.GetAttributeValue("pwdPolicySubentry"),
		PwdLastSet:         pwdLastSet,
		MustChangePassword: mustChange,
		LockoutTime:        parseFileTimeSeconds(entry.GetAttributeValue("lockoutTime")),
		AdminCount:         entry.GetAttributeValue("adminCount") == "1",
		WhenCreated:        parseGeneralizedTime(entry.GetAttributeValue("whenCreated")),
		WhenChanged:        parseGeneralizedTime(entry.GetAttributeValue("whenChanged")),
		Groups:             entry.GetAttributeValues("memberOf"),
	}, nil
}

// getCacheTTL returns the cache TTL from configuration or the default value
func (l *LDAP) getCacheTTL() time.Duration {
	if l.config.Cache != nil && l.config.Cache.TTL > 0 {
		return l.config.Cache.TTL
	}
	return 5 * time.Minute // Default TTL
}

// getFirstNonEmptyAttribute returns the first non-empty value from an LDAP attribute
func getFirstNonEmptyAttribute(entry *ldap.Entry, attribute string) *string {
	values := entry.GetAttributeValues(attribute)
	if len(values) > 0 && strings.TrimSpace(values[0]) != "" {
		value := values[0]
		return &value
	}
	return nil
}

// IsMemberOf checks if the user is a member of the specified group.
// The comparison is case-insensitive and handles whitespace normalization,
// as LDAP distinguished names are case-insensitive according to RFC 4512.
//
// Parameters:
//   - groupDN: The distinguished name of the group to check membership for
//     (e.g., "CN=Admins,OU=Groups,DC=example,DC=com")
//
// Returns:
//   - bool: true if the user is a direct member of the group, false otherwise
//
// Example:
//
//	if user.IsMemberOf("CN=Admins,OU=Groups,DC=example,DC=com") {
//	    // User has admin privileges
//	}
//
// Note: This method only checks direct group membership. For nested group
// membership checking in Active Directory, use the LDAP_MATCHING_RULE_IN_CHAIN
// filter with FindUserBySAMAccountName or similar methods.
func (u *User) IsMemberOf(groupDN string) bool {
	// Normalize the target group DN for comparison
	normalizedTarget := strings.ToLower(strings.TrimSpace(groupDN))

	// Check each group membership
	for _, group := range u.Groups {
		normalizedGroup := strings.ToLower(strings.TrimSpace(group))
		if normalizedGroup == normalizedTarget {
			return true
		}
	}

	return false
}

// FindUserByDN retrieves a user by their distinguished name.
//
// Parameters:
//   - dn: The distinguished name of the user (e.g., "CN=John Doe,CN=Users,DC=example,DC=com")
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     or any LDAP operation error
func (l *LDAP) FindUserByDN(dn string) (user *User, err error) {
	return l.FindUserByDNContext(context.Background(), dn)
}

// FindUserByDNContext retrieves a user by their distinguished name with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user (e.g., "CN=John Doe,CN=Users,DC=example,DC=com")
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     context cancellation error, or any LDAP operation error
func (l *LDAP) FindUserByDNContext(ctx context.Context, dn string) (user *User, err error) {
	start := time.Now()
	cacheHit := false

	// Record operation completion on return
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			resultCount := 0
			if user != nil {
				resultCount = 1
			}
			l.perfMonitor.RecordOperation(ctx, "FindUserByDN", duration, cacheHit, err, resultCount)
		}()
	}

	// Check cache if enabled
	var cacheKey string
	if l.cacheEnabled() {
		cacheKey = fmt.Sprintf("user:dn:%s", dn)
		if cached, found := l.cache.Get(cacheKey); found {
			if cachedUser, ok := cached.(*User); ok {
				cacheHit = true
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserByDN"),
					slog.String("dn", dn),
					slog.Duration("duration", time.Since(start)))
				return cachedUser, nil
			}
		}
	}

	// Use generic DN search function to eliminate code duplication
	params := dnSearchParams{
		operation: "FindUserByDN",
		filter:    "(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))",
		// Same attribute list as every other user search. It used to be a
		// shorter hand-written set, which silently returned a User with the
		// security-posture and audit fields zeroed — pwdLastSet,
		// accountExpires, lockoutTime, whenCreated and now the password-expiry
		// attributes — so the same type meant different things depending on
		// which finder produced it.
		attributes:  userFields,
		notFoundErr: ErrUserNotFound,
		logPrefix:   "user_",
	}

	r, err := l.findByDNContext(ctx, dn, params)
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		l.logger.Debug("user_not_found_by_dn",
			slog.String("operation", "FindUserByDN"),
			slog.String("dn", dn),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("user not found by DN %s: %w", dn, ErrUserNotFound)
	}

	if len(r.Entries) > 1 {
		l.logger.Error("user_dn_duplicated",
			slog.String("operation", "FindUserByDN"),
			slog.String("dn", dn),
			slog.Int("count", len(r.Entries)),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("duplicate DN found %s (count: %d): %w", dn, len(r.Entries), ErrDNDuplicated)
	}

	if user, err = userFromEntry(r.Entries[0]); err != nil {
		l.logger.Error("user_parsing_failed",
			slog.String("operation", "FindUserByDN"),
			slog.String("dn", dn),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to parse user entry for DN %s: %w", dn, err)
	}

	// Cache the result if caching is enabled
	if l.cacheEnabled() && user != nil {
		// Use SetWithPrimaryKey to register all related cache keys with the user's DN
		_ = l.cache.SetWithPrimaryKey(cacheKey, user, l.getCacheTTL(), user.DN())
		// Also register alternate cache keys
		if user.Mail != nil && *user.Mail != "" {
			mailKey := fmt.Sprintf("user:mail:%s", *user.Mail)
			l.cache.RegisterCacheKey(user.DN(), mailKey)
		}
		if user.SAMAccountName != "" {
			samKey := fmt.Sprintf("user:sam:%s", user.SAMAccountName)
			l.cache.RegisterCacheKey(user.DN(), samKey)
		}
	}

	l.logger.Debug("user_found_by_dn",
		slog.String("operation", "FindUserByDN"),
		slog.String("dn", dn),
		slog.String("sam_account_name", user.SAMAccountName),
		slog.Duration("duration", time.Since(start)))

	return
}

// FindUserBySAMAccountName retrieves a user by their Security Account Manager account name.
//
// Parameters:
//   - sAMAccountName: The SAM account name (e.g., "jdoe" for john.doe@domain.com)
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given sAMAccountName,
//     ErrSAMAccountNameDuplicated if multiple users have the same sAMAccountName,
//     or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// For OpenLDAP compatibility, it also searches for uid attribute when sAMAccountName is not found.
func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (user *User, err error) {
	return l.FindUserBySAMAccountNameContext(context.Background(), sAMAccountName)
}

// FindUserBySAMAccountNameContext retrieves a user by their Security Account Manager account name with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - sAMAccountName: The SAM account name (e.g., "jdoe" for john.doe@domain.com)
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given sAMAccountName,
//     ErrSAMAccountNameDuplicated if multiple users have the same sAMAccountName,
//     context cancellation error, or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// For OpenLDAP compatibility, it also searches for uid attribute when sAMAccountName is not found.
func (l *LDAP) FindUserBySAMAccountNameContext(ctx context.Context, sAMAccountName string) (user *User, err error) {
	if err := ValidateSAMAccountName(sAMAccountName); err != nil {
		return nil, fmt.Errorf("invalid sAMAccountName: %w", err)
	}

	// Check for context cancellation first
	if err := l.checkContextCancellation(ctx, "FindUserBySAMAccountName", sAMAccountName, "start"); err != nil {
		return nil, ctx.Err()
	}

	start := time.Now()
	cacheHit := false

	// Record operation completion on return
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			resultCount := 0
			if user != nil {
				resultCount = 1
			}
			l.perfMonitor.RecordOperation(ctx, "FindUserBySAMAccountName", duration, cacheHit, err, resultCount)
		}()
	}

	// Mask sensitive data for logging
	maskedUsername := maskSensitiveData(sAMAccountName)

	// Check cache if enabled
	var cacheKey string
	if l.cacheEnabled() {
		cacheKey = fmt.Sprintf("user:sam:%s", sAMAccountName)
		if cached, found := l.cache.Get(cacheKey); found {
			if cachedUser, ok := cached.(*User); ok {
				cacheHit = true
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserBySAMAccountName"),
					slog.String("username_masked", maskedUsername),
					slog.Duration("duration", time.Since(start)))
				return cachedUser, nil
			}
		}
	}

	l.logger.Debug("user_search_by_sam_account_started",
		slog.String("operation", "FindUserBySAMAccountName"),
		slog.String("username_masked", maskedUsername))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, connectionError("SAM account", "search", err)
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("sam_account_name", sAMAccountName),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before first search
	if err := l.checkContextCancellation(ctx, "user_search", sAMAccountName, "before_first_search"); err != nil {
		return nil, err
	}

	// Try Active Directory search first
	// Performance optimization: Use direct string concatenation instead of fmt.Sprintf
	escapedSAM := ldap.EscapeFilter(sAMAccountName)
	filter := "(&(objectClass=user)(sAMAccountName=" + escapedSAM + "))"
	l.logger.Debug("user_search_executing",
		slog.String("filter", filter),
		slog.String("base_dn", l.config.BaseDN))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   userFields,
	})
	if err != nil {
		l.logger.Error("user_search_by_sam_account_failed",
			slog.String("operation", "FindUserBySAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("filter_masked", maskSensitiveData(filter)),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("user search failed for SAM account %s (filter: %s): %w", sAMAccountName, filter, WrapLDAPError("FindUserBySAMAccountName", l.config.Server, err))
	}

	// If no results with Active Directory filter, try OpenLDAP compatibility
	if len(r.Entries) == 0 && !l.config.IsActiveDirectory {
		l.logger.Debug("user_search_trying_openldap_compatibility",
			slog.String("username_masked", maskedUsername))

		// Check for context cancellation before second search
		if err := l.checkContextCancellation(ctx, "user_search", sAMAccountName, "before_openldap_search"); err != nil {
			return nil, err
		}

		// Performance optimization: Use direct string concatenation instead of fmt.Sprintf
		escapedUID := ldap.EscapeFilter(sAMAccountName)
		filter = "(&(|(objectClass=inetOrgPerson)(objectClass=person))(uid=" + escapedUID + "))"
		r, err = c.Search(&ldap.SearchRequest{
			BaseDN:       l.config.BaseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Filter:       filter,
			Attributes:   userFields, // shared AD + OpenLDAP attribute list (unknown attrs are ignored by the server)
		})
		if err != nil {
			l.logger.Error("user_search_openldap_failed",
				slog.String("username_masked", maskedUsername),
				slog.String("filter_masked", maskSensitiveData(filter)),
				slog.String("error", err.Error()))
			return nil, err
		}
	}

	if len(r.Entries) == 0 {
		l.logger.Debug("user_not_found_by_sam_account",
			slog.String("operation", "FindUserBySAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrUserNotFound
	}
	if len(r.Entries) > 1 {
		l.logger.Error("user_sam_account_duplicated",
			slog.String("operation", "FindUserBySAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.Int("count", len(r.Entries)),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrSAMAccountNameDuplicated
	}

	if user, err = userFromEntry(r.Entries[0]); err != nil {
		l.logger.Error("user_parsing_failed",
			slog.String("operation", "FindUserBySAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()))
		return nil, err
	}

	// Store in cache if enabled
	if l.cacheEnabled() && cacheKey != "" {
		// Use SetWithPrimaryKey to register all related cache keys with the user's DN
		if err := l.cache.SetWithPrimaryKey(cacheKey, user, l.getCacheTTL(), user.DN()); err != nil {
			l.logger.Debug("cache_set_error",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("key", cacheKey),
				slog.String("error", err.Error()))
		} else {
			// Also register alternate cache keys
			dnKey := fmt.Sprintf("user:dn:%s", user.DN())
			l.cache.RegisterCacheKey(user.DN(), dnKey)
			if user.Mail != nil && *user.Mail != "" {
				mailKey := fmt.Sprintf("user:mail:%s", *user.Mail)
				l.cache.RegisterCacheKey(user.DN(), mailKey)
			}
		}
	}

	l.logger.Debug("user_found_by_sam_account",
		slog.String("operation", "FindUserBySAMAccountName"),
		slog.String("username_masked", maskedUsername),
		slog.String("dn_masked", maskSensitiveData(user.DN())),
		slog.Duration("duration", time.Since(start)))

	return
}

// FindUsersBySAMAccountNames retrieves multiple users by their Security Account Manager account names.
// This is a convenience method for batch user lookups, commonly used in scenarios where operations
// need to be performed on multiple users simultaneously (e.g., admin panels, bulk operations, reporting).
//
// Parameters:
//   - sAMAccountNames: A slice of SAM account names to search for (e.g., ["jdoe", "asmith", "bjones"])
//
// Returns:
//   - []*User: A slice of user objects for found users (may be shorter than input if some users don't exist)
//   - error: Returns error only for system failures (connection errors, invalid configuration, etc.)
//     Individual user lookup failures result in that user being omitted from the results
//
// Example:
//
//	// Lookup multiple users for batch operations
//	names := []string{"admin", "jdoe", "asmith"}
//	users, err := client.FindUsersBySAMAccountNames(names)
//	if err != nil {
//	    // Handle connection/system errors
//	    log.Fatal(err)
//	}
//	// Users slice contains only found users (may be 0-3 users)
//	for _, user := range users {
//	    fmt.Printf("Found: %s (%s)\n", user.SAMAccountName, user.DN())
//	}
//
// Note: This method returns partial results - if some users are not found, they are silently
// omitted from the results. Check the length of returned slice against input to detect missing users.
// For detailed error handling per user, use individual FindUserBySAMAccountName calls.
func (l *LDAP) FindUsersBySAMAccountNames(sAMAccountNames []string) ([]*User, error) {
	return l.FindUsersBySAMAccountNamesContext(context.Background(), sAMAccountNames)
}

// FindUsersBySAMAccountNamesContext retrieves multiple users by their Security Account Manager account names
// with context support for timeout and cancellation control.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - sAMAccountNames: A slice of SAM account names to search for
//
// Returns:
//   - []*User: A slice of user objects for found users
//   - error: Returns error only for context cancellation or system failures
//
// This method looks up users sequentially. Individual lookup failures result in that user
// being omitted from the results. The context can be used to set a timeout for the entire
// operation or cancel it midway through.
func (l *LDAP) FindUsersBySAMAccountNamesContext(ctx context.Context, sAMAccountNames []string) ([]*User, error) {
	// Check for context cancellation at start
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	start := time.Now()

	// Pre-allocate with capacity for potential matches
	users := make([]*User, 0, len(sAMAccountNames))

	// Track lookup statistics for logging
	foundCount := 0
	errorCount := 0

	// Lookup each user sequentially
	for _, sAMAccountName := range sAMAccountNames {
		// Check context before each lookup
		if err := ctx.Err(); err != nil {
			// Return partial results with context cancellation error
			return users, err
		}

		user, err := l.FindUserBySAMAccountNameContext(ctx, sAMAccountName)
		if err != nil {
			// Only system/connection errors should stop the batch operation
			// User not found errors are expected and handled by omitting from results
			if err == ErrUserNotFound || err == ErrSAMAccountNameDuplicated {
				errorCount++
				l.logger.Debug("batch_user_lookup_skipped",
					slog.String("operation", "FindUsersBySAMAccountNames"),
					slog.String("sam_account_name_masked", maskSensitiveData(sAMAccountName)),
					slog.String("reason", err.Error()))
				continue
			}

			// For other errors (connection, system), return partial results with error
			l.logger.Warn("batch_user_lookup_error",
				slog.String("operation", "FindUsersBySAMAccountNames"),
				slog.String("sam_account_name_masked", maskSensitiveData(sAMAccountName)),
				slog.Int("found_so_far", foundCount),
				slog.String("error", err.Error()))
			return users, err
		}

		users = append(users, user)
		foundCount++
	}

	l.logger.Debug("batch_user_lookup_completed",
		slog.String("operation", "FindUsersBySAMAccountNames"),
		slog.Int("requested", len(sAMAccountNames)),
		slog.Int("found", foundCount),
		slog.Int("not_found", errorCount),
		slog.Duration("duration", time.Since(start)))

	return users, nil
}

// FindUserByMail retrieves a user by their email address.
//
// Parameters:
//   - mail: The email address to search for (e.g., "john.doe@example.com")
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given email,
//     ErrMailDuplicated if multiple users have the same email address,
//     or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
func (l *LDAP) FindUserByMail(mail string) (user *User, err error) {
	return l.FindUserByMailContext(context.Background(), mail)
}

// FindUserByMailContext retrieves a user by their email address with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - mail: The email address to search for (e.g., "john.doe@example.com")
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given email,
//     ErrMailDuplicated if multiple users have the same email address,
//     context cancellation error, or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
func (l *LDAP) FindUserByMailContext(ctx context.Context, mail string) (user *User, err error) {
	start := time.Now()
	cacheHit := false

	// Record operation completion on return
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			resultCount := 0
			if user != nil {
				resultCount = 1
			}
			l.perfMonitor.RecordOperation(ctx, "FindUserByMail", duration, cacheHit, err, resultCount)
		}()
	}

	// Check cache if enabled
	var cacheKey string
	if l.cacheEnabled() {
		cacheKey = fmt.Sprintf("user:mail:%s", mail)
		if cached, found := l.cache.Get(cacheKey); found {
			if cachedUser, ok := cached.(*User); ok {
				cacheHit = true
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserByMail"),
					slog.String("mail", mail),
					slog.Duration("duration", time.Since(start)))
				return cachedUser, nil
			}
		}
	}
	l.logger.Debug("user_search_by_mail_started",
		slog.String("operation", "FindUserByMail"),
		slog.String("mail", mail))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before search
	select {
	case <-ctx.Done():
		l.logger.Debug("user_search_cancelled",
			slog.String("operation", "FindUserByMail"),
			slog.String("mail", mail),
			slog.String("error", ctx.Err().Error()))
		return nil, ctx.Err()
	default:
	}

	// Performance optimization: Use direct string concatenation instead of fmt.Sprintf
	escapedMail := ldap.EscapeFilter(mail)
	filter := "(&(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))(mail=" + escapedMail + "))"
	l.logger.Debug("user_search_executing",
		slog.String("filter", filter),
		slog.String("base_dn", l.config.BaseDN))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   userFields, // shared AD + OpenLDAP attribute list
	})
	if err != nil {
		l.logger.Error("user_search_by_mail_failed",
			slog.String("operation", "FindUserByMail"),
			slog.String("mail", mail),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	if len(r.Entries) == 0 {
		l.logger.Debug("user_not_found_by_mail",
			slog.String("operation", "FindUserByMail"),
			slog.String("mail", mail),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrUserNotFound
	}
	if len(r.Entries) > 1 {
		l.logger.Error("user_mail_duplicated",
			slog.String("operation", "FindUserByMail"),
			slog.String("mail", mail),
			slog.Int("count", len(r.Entries)),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrMailDuplicated
	}

	if user, err = userFromEntry(r.Entries[0]); err != nil {
		l.logger.Error("user_parsing_failed",
			slog.String("operation", "FindUserByMail"),
			slog.String("mail", mail),
			slog.String("error", err.Error()))
		return nil, err
	}

	// Store in cache if enabled
	if l.cacheEnabled() && cacheKey != "" {
		// Use SetWithPrimaryKey to register all related cache keys with the user's DN
		if err := l.cache.SetWithPrimaryKey(cacheKey, user, l.getCacheTTL(), user.DN()); err != nil {
			l.logger.Debug("cache_set_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("key", cacheKey),
				slog.String("error", err.Error()))
		} else {
			// Also register alternate cache keys
			dnKey := fmt.Sprintf("user:dn:%s", user.DN())
			l.cache.RegisterCacheKey(user.DN(), dnKey)
			if user.SAMAccountName != "" {
				samKey := fmt.Sprintf("user:sam:%s", user.SAMAccountName)
				l.cache.RegisterCacheKey(user.DN(), samKey)
			}
		}
	}

	l.logger.Debug("user_found_by_mail",
		slog.String("operation", "FindUserByMail"),
		slog.String("mail", mail),
		slog.String("dn", user.DN()),
		slog.String("sam_account_name", user.SAMAccountName),
		slog.Duration("duration", time.Since(start)))

	return
}

// FindUsers retrieves all user objects from the directory.
//
// Returns:
//   - []User: A slice of all user objects found in the directory
//   - error: Any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Users that cannot be parsed (due to missing required attributes) are skipped.
func (l *LDAP) FindUsers() (users []User, err error) {
	return l.FindUsersContext(context.Background())
}

// FindUsersContext retrieves all user objects from the directory with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//
// Returns:
//   - []User: A slice of all user objects found in the directory
//   - error: Any LDAP operation error or context cancellation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Users that cannot be parsed (due to missing required attributes) are skipped.
func (l *LDAP) FindUsersContext(ctx context.Context) (users []User, err error) {
	// Check for context cancellation first
	if err := l.checkContextCancellation(ctx, "FindUsers", "N/A", "start"); err != nil {
		return nil, ctx.Err()
	}

	start := time.Now()
	l.logger.Debug("user_list_search_started",
		slog.String("operation", "FindUsers"))

	// Return mock data for example servers
	if l.isExampleServer() {
		// Create 150 mock users for examples
		users = make([]User, 150)
		for i := 0; i < 150; i++ {
			email := fmt.Sprintf("user%d@example.com", i+1)
			users[i] = User{
				Object: Object{
					cn: fmt.Sprintf("User %d", i+1),
					dn: fmt.Sprintf("CN=User %d,OU=Users,%s", i+1, l.config.BaseDN),
				},
				SAMAccountName: fmt.Sprintf("user%d", i+1),
				Description:    fmt.Sprintf("Example User %d", i+1),
				Mail:           &email,
				Enabled:        true,
				Groups:         []string{},
			}
		}
		l.logger.Debug("user_list_search_completed",
			slog.String("operation", "FindUsers"),
			slog.Int("count", len(users)),
			slog.Duration("duration", time.Since(start)))
		return users, nil
	}

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before search
	select {
	case <-ctx.Done():
		l.logger.Debug("user_list_search_cancelled",
			slog.String("error", ctx.Err().Error()))
		return nil, ctx.Err()
	default:
	}

	filter := "(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))"
	l.logger.Debug("user_list_search_executing",
		slog.String("filter", filter),
		slog.String("base_dn", l.config.BaseDN))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   userFields, // shared AD + OpenLDAP attribute list
	})
	if err != nil {
		l.logger.Error("user_list_search_failed",
			slog.String("operation", "FindUsers"),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	processed := 0
	skipped := 0

	for _, entry := range r.Entries {
		// Check for context cancellation during processing
		select {
		case <-ctx.Done():
			l.logger.Debug("user_list_processing_cancelled",
				slog.Int("processed", processed),
				slog.String("error", ctx.Err().Error()))
			return nil, ctx.Err()
		default:
		}

		user, err := userFromEntry(entry)
		if err != nil {
			l.logger.Debug("user_entry_skipped",
				slog.String("dn", entry.DN),
				slog.String("error", err.Error()))
			skipped++
			continue
		}

		users = append(users, *user)
		processed++
	}

	l.logger.Info("user_list_search_completed",
		slog.String("operation", "FindUsers"),
		slog.Int("total_found", len(r.Entries)),
		slog.Int("processed", processed),
		slog.Int("skipped", skipped),
		slog.Duration("duration", time.Since(start)))

	return
}

// AddUserToGroup adds a user to a group by modifying the group's member attribute.
//
// Parameters:
//   - dn: The distinguished name of the user to add to the group
//   - groupDN: The distinguished name of the group to modify
//
// Returns:
//   - error: Any LDAP operation error, including insufficient permissions or if the user is already a member
//
// This operation requires write permissions on the target group object.
func (l *LDAP) AddUserToGroup(dn, groupDN string) error {
	return l.AddUserToGroupContext(context.Background(), dn, groupDN)
}

// AddUserToGroupContext adds a user to a group by modifying the group's member attribute with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user to add to the group
//   - groupDN: The distinguished name of the group to modify
//
// Returns:
//   - error: Any LDAP operation error, including insufficient permissions, if the user is already a member,
//     or context cancellation error
//
// This operation requires write permissions on the target group object.
func (l *LDAP) AddUserToGroupContext(ctx context.Context, dn, groupDN string) error {
	start := time.Now()
	l.logger.Info("user_group_add_started",
		slog.String("operation", "AddUserToGroup"),
		slog.String("user_dn", dn),
		slog.String("group_dn", groupDN))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before modify operation
	select {
	case <-ctx.Done():
		l.logger.Debug("user_group_add_cancelled",
			slog.String("user_dn", dn),
			slog.String("group_dn", groupDN),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()
	default:
	}

	req := ldap.NewModifyRequest(groupDN, nil)
	req.Add("member", []string{dn})

	err = c.Modify(req)
	if err != nil {
		l.logger.Error("user_group_add_failed",
			slog.String("operation", "AddUserToGroup"),
			slog.String("user_dn", dn),
			slog.String("group_dn", groupDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return err
	}

	l.logger.Info("user_group_add_successful",
		slog.String("operation", "AddUserToGroup"),
		slog.String("user_dn", dn),
		slog.String("group_dn", groupDN),
		slog.Duration("duration", time.Since(start)))

	return nil
}

// RemoveUserFromGroup removes a user from a group by modifying the group's member attribute.
//
// Parameters:
//   - dn: The distinguished name of the user to remove from the group
//   - groupDN: The distinguished name of the group to modify
//
// Returns:
//   - error: Any LDAP operation error, including insufficient permissions or if the user is not a member
//
// This operation requires write permissions on the target group object.
func (l *LDAP) RemoveUserFromGroup(dn, groupDN string) error {
	return l.RemoveUserFromGroupContext(context.Background(), dn, groupDN)
}

// RemoveUserFromGroupContext removes a user from a group by modifying the group's member attribute with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user to remove from the group
//   - groupDN: The distinguished name of the group to modify
//
// Returns:
//   - error: Any LDAP operation error, including insufficient permissions, if the user is not a member,
//     or context cancellation error
//
// This operation requires write permissions on the target group object.
func (l *LDAP) RemoveUserFromGroupContext(ctx context.Context, dn, groupDN string) error {
	start := time.Now()
	l.logger.Info("user_group_remove_started",
		slog.String("operation", "RemoveUserFromGroup"),
		slog.String("user_dn", dn),
		slog.String("group_dn", groupDN))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before modify operation
	select {
	case <-ctx.Done():
		l.logger.Debug("user_group_remove_cancelled",
			slog.String("user_dn", dn),
			slog.String("group_dn", groupDN),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()
	default:
	}

	req := ldap.NewModifyRequest(groupDN, nil)
	req.Delete("member", []string{dn})

	err = c.Modify(req)
	if err != nil {
		l.logger.Error("user_group_remove_failed",
			slog.String("operation", "RemoveUserFromGroup"),
			slog.String("user_dn", dn),
			slog.String("group_dn", groupDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return err
	}

	l.logger.Info("user_group_remove_successful",
		slog.String("operation", "RemoveUserFromGroup"),
		slog.String("user_dn", dn),
		slog.String("group_dn", groupDN),
		slog.Duration("duration", time.Since(start)))

	return nil
}

// FullUser represents a complete user object for creation operations with all configurable attributes.
type FullUser struct {
	// CN is the common name of the user (required, used as the RDN component).
	CN string
	// SAMAccountName is the Security Account Manager account name (optional for creation).
	SAMAccountName *string
	// FirstName is the user's given name (required).
	FirstName string
	// LastName is the user's surname (required).
	LastName string
	// DisplayName is the name displayed in address lists (optional, defaults to CN if nil).
	DisplayName *string
	// Description contains additional information about the user (optional).
	Description *string
	// Email is the user's email address (optional).
	Email *string
	// ObjectClasses defines the LDAP object classes (optional, defaults to standard user classes).
	ObjectClasses []string
	// AccountExpires represents the expiration date of the user's account.
	// When set to nil, the account never expires.
	AccountExpires *time.Time
	// UserAccountControl contains the account control flags (enabled/disabled, password policies, etc.).
	UserAccountControl UAC
	// Path specifies the organizational unit path relative to BaseDN (optional, defaults to BaseDN).
	Path *string
}

// CreateUser creates a new user in the directory with the specified attributes.
//
// Parameters:
//   - user: The FullUser object containing all user attributes
//   - password: The initial password for the user (currently not implemented in this version)
//
// Returns:
//   - string: The distinguished name of the created user
//   - error: Any LDAP operation error, including duplicate entries or insufficient permissions
//
// Default behaviors:
//   - ObjectClasses defaults to ["top", "person", "organizationalPerson", "user"] if not specified
//   - DisplayName defaults to CN if not specified
//   - The user is created at the specified Path relative to BaseDN, or directly under BaseDN if Path is nil
//
// Example:
//
//	user := FullUser{
//	    CN: "John Doe",
//	    FirstName: "John",
//	    LastName: "Doe",
//	    SAMAccountName: &"jdoe",
//	    Email: &"john.doe@example.com",
//	    UserAccountControl: UAC{NormalAccount: true},
//	}
//	dn, err := client.CreateUser(user, "")
func (l *LDAP) CreateUser(user FullUser, password string) (string, error) {
	return l.CreateUserContext(context.Background(), user, password)
}

// CreateUserContext creates a new user in the directory with the specified attributes with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - user: The FullUser object containing all user attributes
//   - password: The initial password for the user (currently not implemented in this version)
//
// Returns:
//   - string: The distinguished name of the created user
//   - error: Any LDAP operation error, including duplicate entries, insufficient permissions,
//     or context cancellation error
//
// Default behaviors:
//   - ObjectClasses defaults to ["top", "person", "organizationalPerson", "user"] if not specified
//   - DisplayName defaults to CN if not specified
//   - The user is created at the specified Path relative to BaseDN, or directly under BaseDN if Path is nil
func (l *LDAP) CreateUserContext(ctx context.Context, user FullUser, password string) (dn string, err error) {
	start := time.Now()

	// Record operation completion on return
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			resultCount := 0
			if err == nil {
				resultCount = 1
			}
			l.perfMonitor.RecordOperation(ctx, "CreateUser", duration, false, err, resultCount)
		}()
	}
	l.logger.Info("user_create_started",
		slog.String("operation", "CreateUser"),
		slog.String("cn", user.CN),
		slog.String("sam_account_name", func() string {
			if user.SAMAccountName != nil {
				return *user.SAMAccountName
			}
			return "<nil>"
		}()))

	if user.SAMAccountName != nil {
		if err := ValidateSAMAccountName(*user.SAMAccountName); err != nil {
			return "", fmt.Errorf("invalid sAMAccountName: %w", err)
		}
	}

	if user.ObjectClasses == nil {
		// Default to the Active Directory "user" object chain on AD, and to the
		// OpenLDAP-compatible inetOrgPerson chain otherwise. Callers can still
		// override by setting ObjectClasses explicitly on FullUser.
		if l.config.IsActiveDirectory {
			user.ObjectClasses = []string{"top", "person", "organizationalPerson", "user"}
		} else {
			user.ObjectClasses = []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
		}
	}

	if user.DisplayName == nil {
		user.DisplayName = &user.CN
	}

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before creating user
	select {
	case <-ctx.Done():
		l.logger.Debug("user_create_cancelled",
			slog.String("cn", user.CN),
			slog.String("error", ctx.Err().Error()))
		return "", ctx.Err()
	default:
	}

	baseDN := ""
	if user.Path != nil {
		baseDN = *user.Path + ","
	}
	baseDN += l.config.BaseDN

	// Performance optimization: Use direct string concatenation instead of fmt.Sprintf
	escapedCN := ldap.EscapeDN(user.CN)
	dn = "CN=" + escapedCN + "," + baseDN
	l.logger.Debug("user_create_constructing_request",
		slog.String("target_dn", dn),
		slog.Any("object_classes", user.ObjectClasses))

	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", user.ObjectClasses)
	req.Attribute("cn", []string{user.CN})
	// Performance optimization: Use strings.Builder for name concatenation
	var nameBuilder strings.Builder
	nameBuilder.Grow(len(user.FirstName) + len(user.LastName) + 1)
	nameBuilder.WriteString(user.FirstName)
	nameBuilder.WriteString(" ")
	nameBuilder.WriteString(user.LastName)
	// `name` is part of AD's user class; OpenLDAP inetOrgPerson has no such
	// attribute, so only emit it when talking to AD.
	if l.config.IsActiveDirectory {
		req.Attribute("name", []string{nameBuilder.String()})
	}
	req.Attribute("givenName", []string{user.FirstName})
	req.Attribute("sn", []string{user.LastName})
	req.Attribute("displayName", []string{*user.DisplayName})
	// accountExpires, userAccountControl and sAMAccountName are Active
	// Directory-specific attributes. OpenLDAP's standard schemas do not define
	// them (attempting to set them fails with LDAP result 17 "Undefined
	// Attribute Type"), so gate them on the IsActiveDirectory flag.
	if l.config.IsActiveDirectory {
		req.Attribute("accountExpires", []string{convertAccountExpires(user.AccountExpires)})
		// Performance optimization: Use strconv.FormatUint instead of fmt.Sprintf
		req.Attribute("userAccountControl", []string{strconv.FormatUint(uint64(user.UserAccountControl.Uint32()), 10)})
		if user.SAMAccountName != nil {
			req.Attribute("sAMAccountName", []string{*user.SAMAccountName})
		}
	} else if user.SAMAccountName != nil {
		// inetOrgPerson has no sAMAccountName. Store the value in `uid`,
		// which FindUserBySAMAccountName falls back to when the AD-only
		// attribute isn't present. Without this, users created with a
		// SAMAccountName on OpenLDAP are silently unfindable by it.
		req.Attribute("uid", []string{*user.SAMAccountName})
	}

	if user.Description != nil {
		req.Attribute("description", []string{*user.Description})
	}

	if user.Email != nil {
		req.Attribute("mail", []string{*user.Email})
	}

	err = c.Add(req)
	if err != nil {
		l.logger.Error("user_create_failed",
			slog.String("operation", "CreateUser"),
			slog.String("dn", dn),
			slog.String("cn", user.CN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return dn, err
	}

	l.logger.Info("user_create_successful",
		slog.String("operation", "CreateUser"),
		slog.String("dn", dn),
		slog.String("cn", user.CN),
		slog.Duration("duration", time.Since(start)))

	return dn, nil
}

// ModifyUser modifies attributes of an existing user in the directory.
//
// Parameters:
//   - dn: The distinguished name of the user to modify
//   - attributes: Map of attributes to modify (key: attribute name, value: new values)
//
// Returns:
//   - error: Any LDAP operation error, including user not found or insufficient permissions
//
// Example:
//
//	attributes := map[string][]string{
//	    "mail": {"newemail@example.com"},
//	    "description": {"Updated description"},
//	}
//	err := client.ModifyUser("uid=jdoe,ou=users,dc=example,dc=com", attributes)
func (l *LDAP) ModifyUser(dn string, attributes map[string][]string) error {
	return l.ModifyUserContext(context.Background(), dn, attributes)
}

// ModifyUserContext modifies attributes of an existing user with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user to modify
//   - attributes: Map of attributes to modify (key: attribute name, value: new values)
//
// Returns:
//   - error: Any LDAP operation error, including user not found, insufficient permissions,
//     or context cancellation error
func (l *LDAP) ModifyUserContext(ctx context.Context, dn string, attributes map[string][]string) (err error) {
	start := time.Now()

	// Record operation completion on return
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			resultCount := 0
			if err == nil {
				resultCount = 1
			}
			l.perfMonitor.RecordOperation(ctx, "ModifyUser", duration, false, err, resultCount)
		}()
	}

	l.logger.Info("user_modify_started",
		slog.String("operation", "ModifyUser"),
		slog.String("dn", dn),
		slog.Int("attributes", len(attributes)))

	// Check for context cancellation first
	select {
	case <-ctx.Done():
		l.logger.Debug("user_modify_cancelled",
			slog.String("dn", dn),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()
	default:
	}

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return connectionError("modify", "user", err)
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "ModifyUser"),
				slog.String("dn", dn),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Create modify request
	modReq := ldap.NewModifyRequest(dn, nil)
	for attr, values := range attributes {
		modReq.Replace(attr, values)
	}

	// Check for context cancellation before modify operation
	select {
	case <-ctx.Done():
		l.logger.Debug("user_modify_cancelled_before_ldap",
			slog.String("dn", dn),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()
	default:
	}

	// Execute modification
	err = c.Modify(modReq)
	if err != nil {
		l.logger.Error("user_modify_failed",
			slog.String("operation", "ModifyUser"),
			slog.String("dn", dn),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return WrapLDAPError("ModifyUser", l.config.Server, err)
	}

	l.logger.Info("user_modify_successful",
		slog.String("operation", "ModifyUser"),
		slog.String("dn", dn),
		slog.Int("attributes", len(attributes)),
		slog.Duration("duration", time.Since(start)))

	// Clear cache for modified user using DN as primary key
	if l.cacheEnabled() {
		deleted := l.cache.InvalidateByPrimaryKey(dn)
		l.logger.Debug("user_cache_invalidated_on_modify",
			slog.String("dn", dn),
			slog.Int("keys_deleted", deleted))
	}

	return nil
}

// DeleteUser removes a user from the directory.
//
// Parameters:
//   - dn: The distinguished name of the user to delete
//
// Returns:
//   - error: Any LDAP operation error, including user not found or insufficient permissions
//
// Warning: This operation is irreversible. Ensure you have proper backups and permissions before deletion.
func (l *LDAP) DeleteUser(dn string) error {
	return l.DeleteUserContext(context.Background(), dn)
}

// DeleteUserContext removes a user from the directory with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user to delete
//
// Returns:
//   - error: Any LDAP operation error, including user not found, insufficient permissions,
//     or context cancellation error
//
// Warning: This operation is irreversible. Ensure you have proper backups and permissions before deletion.
func (l *LDAP) DeleteUserContext(ctx context.Context, dn string) (err error) {
	start := time.Now()

	// Record operation completion on return
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			resultCount := 0
			if err == nil {
				resultCount = 1
			}
			l.perfMonitor.RecordOperation(ctx, "DeleteUser", duration, false, err, resultCount)
		}()
	}
	l.logger.Warn("user_delete_started",
		slog.String("operation", "DeleteUser"),
		slog.String("dn", dn))

	// With the new cache tracking system, we don't need to fetch the user
	// We can invalidate all related cache entries directly using the DN as primary key

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before delete operation
	select {
	case <-ctx.Done():
		l.logger.Debug("user_delete_cancelled",
			slog.String("dn", dn),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()
	default:
	}

	err = c.Del(&ldap.DelRequest{DN: dn})
	if err != nil {
		l.logger.Error("user_delete_failed",
			slog.String("operation", "DeleteUser"),
			slog.String("dn", dn),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return err
	}

	l.logger.Warn("user_delete_successful",
		slog.String("operation", "DeleteUser"),
		slog.String("dn", dn),
		slog.Duration("duration", time.Since(start)))

	// Clear all cache entries for deleted user using the DN as primary key
	if l.cacheEnabled() {
		deleted := l.cache.InvalidateByPrimaryKey(dn)
		l.logger.Debug("user_cache_invalidated_on_delete",
			slog.String("dn", dn),
			slog.Int("keys_deleted", deleted))
	}

	return nil
}

// BulkCreateUsers creates multiple users in LDAP using concurrent operations.
//
// Parameters:
//   - users: Array of FullUser objects to create
//   - password: Default password for all users (if empty, users will have no password)
//
// Returns:
//   - []WorkResult[FullUser]: Results for each user creation attempt, including success/failure status
//   - error: Critical error that prevented the operation from starting
//
// This method uses a worker pool to create users concurrently for improved performance.
// Each user creation is attempted independently, so some may succeed while others fail.
func (l *LDAP) BulkCreateUsers(users []FullUser, password string) ([]WorkResult[FullUser], error) {
	return l.BulkCreateUsersContext(context.Background(), users, password, nil)
}

// BulkCreateUsersContext creates multiple users with context and configurable concurrency.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - users: Array of FullUser objects to create
//   - password: Default password for all users
//   - config: Optional worker pool configuration (uses defaults if nil)
//
// Returns:
//   - []WorkResult[FullUser]: Results for each user creation attempt
//   - error: Critical error that prevented the operation from starting
func (l *LDAP) BulkCreateUsersContext(ctx context.Context, users []FullUser, password string, config *WorkerPoolConfig) ([]WorkResult[FullUser], error) {
	if !l.config.EnableBulkOps {
		return nil, fmt.Errorf("bulk operations are not enabled")
	}

	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	// Record operation if metrics are enabled
	start := time.Now()
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			l.perfMonitor.RecordOperation(ctx, "BulkCreateUsers", duration, false, nil, len(users))
		}()
	}

	// Create worker pool
	pool := NewWorkerPool[FullUser](l, config)

	// Submit work items - continue on submission failures
	submissionFailures := 0
	for i, user := range users {
		item := WorkItem[FullUser]{
			ID:   fmt.Sprintf("user_%d_%s", i, user.CN),
			Data: user,
			Fn: func(ctx context.Context, client *LDAP, data FullUser) error {
				_, err := client.CreateUserContext(ctx, data, password)
				return err
			},
		}
		if err := pool.Submit(item); err != nil {
			// Track submission failure but continue processing
			submissionFailures++
			l.logger.Error("bulk_create_submit_failed",
				slog.String("user", user.CN),
				slog.String("error", err.Error()))
		}
	}

	// Close the pool in a goroutine once all items are submitted. Close()
	// closes the work channel, waits for workers to finish draining, then
	// closes the result channel — which lets the range loop below terminate.
	// Running it in a goroutine avoids a deadlock when the number of work
	// items exceeds the result-channel buffer: workers block on the full
	// buffer, wg.Wait() never returns, so if we called Close() before the
	// range loop the range would never start.
	go pool.Close()

	// Collect results
	var results []WorkResult[FullUser]
	resultsChan := pool.Results()
	for result := range resultsChan {
		results = append(results, result)
	}

	// Log summary if there were failures
	if submissionFailures > 0 {
		l.logger.Warn("bulk_create_completed_with_failures",
			slog.Int("submission_failures", submissionFailures),
			slog.Int("total_users", len(users)),
			slog.Int("results_collected", len(results)))
	}

	return results, nil
}

// UserModification represents a modification to apply to a user.
type UserModification struct {
	DN         string
	Attributes map[string][]string
}

// BulkModifyUsers modifies multiple users in LDAP using concurrent operations.
//
// Parameters:
//   - modifications: Array of UserModification objects describing the changes
//
// Returns:
//   - []WorkResult[UserModification]: Results for each modification attempt
//   - error: Critical error that prevented the operation from starting
func (l *LDAP) BulkModifyUsers(modifications []UserModification) ([]WorkResult[UserModification], error) {
	return l.BulkModifyUsersContext(context.Background(), modifications, nil)
}

// BulkModifyUsersContext modifies multiple users with context and configurable concurrency.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - modifications: Array of UserModification objects describing the changes
//   - config: Optional worker pool configuration (uses defaults if nil)
//
// Returns:
//   - []WorkResult[UserModification]: Results for each modification attempt
//   - error: Critical error that prevented the operation from starting
func (l *LDAP) BulkModifyUsersContext(ctx context.Context, modifications []UserModification, config *WorkerPoolConfig) ([]WorkResult[UserModification], error) {
	if !l.config.EnableBulkOps {
		return nil, fmt.Errorf("bulk operations are not enabled")
	}

	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	// Record operation if metrics are enabled
	start := time.Now()
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			l.perfMonitor.RecordOperation(ctx, "BulkModifyUsers", duration, false, nil, len(modifications))
		}()
	}

	// Create worker pool
	pool := NewWorkerPool[UserModification](l, config)

	// Submit work items
	for i, mod := range modifications {
		item := WorkItem[UserModification]{
			ID:   fmt.Sprintf("mod_%d_%s", i, mod.DN),
			Data: mod,
			Fn: func(ctx context.Context, client *LDAP, data UserModification) error {
				conn, err := client.GetConnection()
				if err != nil {
					return err
				}
				defer func() {
					if releaseErr := client.ReleaseConnection(conn); releaseErr != nil {
						client.logger.Debug("connection_close_error",
							slog.String("operation", "BulkModifyUsers"),
							slog.String("dn", data.DN),
							slog.String("error", releaseErr.Error()))
					}
				}()

				modReq := ldap.NewModifyRequest(data.DN, nil)
				for attr, values := range data.Attributes {
					modReq.Replace(attr, values)
				}

				err = conn.Modify(modReq)

				// Clear cache for modified user using DN as primary key
				if err == nil && client.cacheEnabled() {
					deleted := client.cache.InvalidateByPrimaryKey(data.DN)
					client.logger.Debug("user_cache_invalidated_on_modify",
						slog.String("dn", data.DN),
						slog.Int("keys_deleted", deleted))
				}

				return err
			},
		}
		if err := pool.Submit(item); err != nil {
			// Track submission failure but continue processing
			l.logger.Error("bulk_modify_submit_failed",
				slog.String("dn", mod.DN),
				slog.String("error", err.Error()))
		}
	}

	// Close the pool once all items are submitted so the result channel
	// will be closed after workers drain. See BulkCreateUsersContext for
	// the full rationale on why this must run in a goroutine.
	go pool.Close()

	// Collect results
	var results []WorkResult[UserModification]
	resultsChan := pool.Results()
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}

// BulkDeleteUsers deletes multiple users from LDAP using concurrent operations.
//
// Parameters:
//   - dns: Array of distinguished names to delete
//
// Returns:
//   - []WorkResult[string]: Results for each deletion attempt
//   - error: Critical error that prevented the operation from starting
//
// Warning: This operation is irreversible. Ensure you have proper backups before deletion.
func (l *LDAP) BulkDeleteUsers(dns []string) ([]WorkResult[string], error) {
	return l.BulkDeleteUsersContext(context.Background(), dns, nil)
}

// BulkDeleteUsersContext deletes multiple users with context and configurable concurrency.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dns: Array of distinguished names to delete
//   - config: Optional worker pool configuration (uses defaults if nil)
//
// Returns:
//   - []WorkResult[string]: Results for each deletion attempt
//   - error: Critical error that prevented the operation from starting
func (l *LDAP) BulkDeleteUsersContext(ctx context.Context, dns []string, config *WorkerPoolConfig) ([]WorkResult[string], error) {
	if !l.config.EnableBulkOps {
		return nil, fmt.Errorf("bulk operations are not enabled")
	}

	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	// Record operation if metrics are enabled
	start := time.Now()
	if l.perfMonitor != nil {
		defer func() {
			duration := time.Since(start)
			l.perfMonitor.RecordOperation(ctx, "BulkDeleteUsers", duration, false, nil, len(dns))
		}()
	}

	// Create worker pool
	pool := NewWorkerPool[string](l, config)

	// Submit work items
	for i, dn := range dns {
		item := WorkItem[string]{
			ID:   fmt.Sprintf("del_%d_%s", i, dn),
			Data: dn,
			Fn: func(ctx context.Context, client *LDAP, data string) error {
				return client.DeleteUserContext(ctx, data)
			},
		}
		if err := pool.Submit(item); err != nil {
			// Track submission failure but continue processing
			l.logger.Error("bulk_delete_submit_failed",
				slog.String("dn", dn),
				slog.String("error", err.Error()))
		}
	}

	// Close the pool once all items are submitted so the result channel
	// will be closed after workers drain. See BulkCreateUsersContext for
	// the full rationale on why this must run in a goroutine.
	go pool.Close()

	// Collect results
	var results []WorkResult[string]
	resultsChan := pool.Results()
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}
