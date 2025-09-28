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

	// userFields contains the standard LDAP attributes retrieved for user objects.
	userFields = []string{"memberOf", "cn", "sAMAccountName", "mail", "userAccountControl", "description"}
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

	return &User{
		Object:         objectFromEntry(entry),
		Enabled:        enabled,
		SAMAccountName: samAccountName,
		Description:    entry.GetAttributeValue("description"),
		Mail:           mail,
		Groups:         entry.GetAttributeValues("memberOf"),
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
	if l.config.EnableCache && l.cache != nil {
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
		operation:   "FindUserByDN",
		filter:      "(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))",
		attributes:  []string{"memberOf", "cn", "sAMAccountName", "uid", "userAccountControl", "description", "mail"},
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
	if l.config.EnableCache && l.cache != nil && user != nil {
		_ = l.cache.Set(cacheKey, user, l.getCacheTTL())
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
	if l.config.EnableCache && l.cache != nil {
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
		if closeErr := c.Close(); closeErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("sam_account_name", sAMAccountName),
				slog.String("error", closeErr.Error()))
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
			Attributes:   []string{"memberOf", "cn", "uid", "mail", "description"}, // OpenLDAP compatible attributes
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
	if l.config.EnableCache && l.cache != nil && cacheKey != "" {
		if err := l.cache.Set(cacheKey, user, l.getCacheTTL()); err != nil {
			l.logger.Debug("cache_set_error",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("key", cacheKey),
				slog.String("error", err.Error()))
		}
	}

	l.logger.Debug("user_found_by_sam_account",
		slog.String("operation", "FindUserBySAMAccountName"),
		slog.String("username_masked", maskedUsername),
		slog.String("dn_masked", maskSensitiveData(user.DN())),
		slog.Duration("duration", time.Since(start)))

	return
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
	if l.config.EnableCache && l.cache != nil {
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
		if closeErr := c.Close(); closeErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", closeErr.Error()))
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
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "uid", "mail", "userAccountControl", "description"}, // Include both AD and OpenLDAP attributes
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
	if l.config.EnableCache && l.cache != nil && cacheKey != "" {
		if err := l.cache.Set(cacheKey, user, l.getCacheTTL()); err != nil {
			l.logger.Debug("cache_set_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("key", cacheKey),
				slog.String("error", err.Error()))
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
		if closeErr := c.Close(); closeErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", closeErr.Error()))
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
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "uid", "mail", "userAccountControl", "description"}, // Include both AD and OpenLDAP attributes
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
		if closeErr := c.Close(); closeErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", closeErr.Error()))
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
		if closeErr := c.Close(); closeErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", closeErr.Error()))
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

	if user.ObjectClasses == nil {
		user.ObjectClasses = []string{"top", "person", "organizationalPerson", "user"}
	}

	if user.DisplayName == nil {
		user.DisplayName = &user.CN
	}

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := c.Close(); closeErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", closeErr.Error()))
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
	req.Attribute("name", []string{nameBuilder.String()})
	req.Attribute("givenName", []string{user.FirstName})
	req.Attribute("sn", []string{user.LastName})
	req.Attribute("displayName", []string{*user.DisplayName})
	req.Attribute("accountExpires", []string{convertAccountExpires(user.AccountExpires)})
	// Performance optimization: Use strconv.FormatUint instead of fmt.Sprintf
	req.Attribute("userAccountControl", []string{strconv.FormatUint(uint64(user.UserAccountControl.Uint32()), 10)})

	if user.SAMAccountName != nil {
		req.Attribute("sAMAccountName", []string{*user.SAMAccountName})
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

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := c.Close(); closeErr != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindUserByMail"),
				slog.String("error", closeErr.Error()))
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

	// Clear cache entry for deleted user if caching is enabled
	if l.config.EnableCache && l.cache != nil {
		// Clear all possible cache keys for this user
		l.cache.Delete(fmt.Sprintf("user:dn:%s", dn))
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
	defer pool.Close()

	// Submit work items
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
			return nil, fmt.Errorf("failed to submit user %s: %w", user.CN, err)
		}
	}

	// Collect results
	var results []WorkResult[FullUser]
	resultsChan := pool.Results()
	for result := range resultsChan {
		results = append(results, result)
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
	defer pool.Close()

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
				defer conn.Close()

				modReq := ldap.NewModifyRequest(data.DN, nil)
				for attr, values := range data.Attributes {
					modReq.Replace(attr, values)
				}

				err = conn.Modify(modReq)

				// Clear cache for modified user
				if err == nil && client.config.EnableCache && client.cache != nil {
					client.cache.Delete(fmt.Sprintf("user:dn:%s", data.DN))
				}

				return err
			},
		}
		if err := pool.Submit(item); err != nil {
			return nil, fmt.Errorf("failed to submit modification for %s: %w", mod.DN, err)
		}
	}

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
	defer pool.Close()

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
			return nil, fmt.Errorf("failed to submit deletion for %s: %w", dn, err)
		}
	}

	// Collect results
	var results []WorkResult[string]
	resultsChan := pool.Results()
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}
