package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// FindUserByDNOptimized retrieves a user by their distinguished name with caching and performance monitoring.
// This method replaces FindUserByDNContext when caching is enabled.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given DN, or any LDAP operation error
func (l *LDAP) FindUserByDNOptimized(ctx context.Context, dn string, options *SearchOptions) (user *User, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "FindUserByDN")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() {
		recordFunc(cacheHit, err, func() int {
			if user != nil {
				return 1
			} else {
				return 0
			}
		}())
	}()

	// Generate cache key
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("user:dn", dn)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedUser, ok := cached.(*User); ok {
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserByDN"),
					slog.String("dn", dn),
					slog.String("cache_key", cacheKey))
				return cachedUser, nil
			}
			// Handle negative cache
			if cached == nil {
				l.logger.Debug("user_negative_cache_hit",
					slog.String("operation", "FindUserByDN"),
					slog.String("dn", dn))
				return nil, ErrUserNotFound
			}
		}
	}

	// Cache miss - fetch from LDAP
	l.logger.Debug("user_cache_miss_fetching",
		slog.String("operation", "FindUserByDN"),
		slog.String("dn", dn))

	start := time.Now()
	user, err = l.findUserByDNDirect(ctx, dn, options)
	duration := time.Since(start)

	// Cache the result
	if l.cache != nil && err == nil && user != nil {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		if cacheErr := l.cache.SetContext(ctx, cacheKey, user, cacheTTL); cacheErr != nil {
			l.logger.Debug("user_cache_set_failed",
				slog.String("error", cacheErr.Error()),
				slog.String("cache_key", cacheKey))
		} else {
			l.logger.Debug("user_cached",
				slog.String("operation", "FindUserByDN"),
				slog.String("dn", dn),
				slog.String("cache_key", cacheKey),
				slog.Duration("ttl", cacheTTL))
		}
	} else if l.cache != nil && err == ErrUserNotFound && options.UseNegativeCache {
		// Cache negative result
		negativeTTL := l.config.Cache.NegativeCacheTTL
		if negativeTTL > 0 {
			l.cache.SetNegative(cacheKey, negativeTTL)
			l.logger.Debug("user_negative_cached",
				slog.String("operation", "FindUserByDN"),
				slog.String("dn", dn),
				slog.Duration("ttl", negativeTTL))
		}
	}

	l.logger.Debug("user_search_by_dn_completed",
		slog.String("operation", "FindUserByDN"),
		slog.String("dn", dn),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit),
		slog.Bool("found", user != nil))

	return user, err
}

// FindUserBySAMAccountNameOptimized retrieves a user by their SAM account name with caching and performance monitoring.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - samAccountName: The SAM account name
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists, or any LDAP operation error
func (l *LDAP) FindUserBySAMAccountNameOptimized(ctx context.Context, samAccountName string, options *SearchOptions) (user *User, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "FindUserBySAMAccountName")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() {
		recordFunc(cacheHit, err, func() int {
			if user != nil {
				return 1
			} else {
				return 0
			}
		}())
	}()

	// Generate cache key
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("user:sam", samAccountName)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedUser, ok := cached.(*User); ok {
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserBySAMAccountName"),
					slog.String("sam_account_name", samAccountName),
					slog.String("cache_key", cacheKey))
				return cachedUser, nil
			}
			// Handle negative cache
			if cached == nil {
				return nil, ErrUserNotFound
			}
		}
	}

	// Cache miss - fetch from LDAP
	start := time.Now()
	user, err = l.findUserBySAMAccountNameDirect(ctx, samAccountName, options)
	duration := time.Since(start)

	// Cache the result
	if l.cache != nil && err == nil && user != nil {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		// Cache by SAM account name
		if cacheErr := l.cache.SetContext(ctx, cacheKey, user, cacheTTL); cacheErr == nil {
			l.logger.Debug("user_cached",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("sam_account_name", samAccountName),
				slog.String("cache_key", cacheKey))
		}

		// Also cache by DN for DN lookups
		dnCacheKey := GenerateCacheKey("user:dn", user.DN())
		l.cache.SetContext(ctx, dnCacheKey, user, cacheTTL)

		// Cache by email if available
		if user.Mail != nil {
			emailCacheKey := GenerateCacheKey("user:mail", *user.Mail)
			l.cache.SetContext(ctx, emailCacheKey, user, cacheTTL)
		}
	} else if l.cache != nil && err == ErrUserNotFound && options.UseNegativeCache {
		// Cache negative result
		if negativeTTL := l.config.Cache.NegativeCacheTTL; negativeTTL > 0 {
			l.cache.SetNegative(cacheKey, negativeTTL)
		}
	}

	l.logger.Debug("user_search_by_sam_account_completed",
		slog.String("operation", "FindUserBySAMAccountName"),
		slog.String("sam_account_name", samAccountName),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit))

	return user, err
}

// FindUserByMailOptimized retrieves a user by their email address with caching and performance monitoring.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - mail: The email address to search for
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists, or any LDAP operation error
func (l *LDAP) FindUserByMailOptimized(ctx context.Context, mail string, options *SearchOptions) (user *User, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "FindUserByMail")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() {
		recordFunc(cacheHit, err, func() int {
			if user != nil {
				return 1
			} else {
				return 0
			}
		}())
	}()

	// Generate cache key
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("user:mail", mail)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedUser, ok := cached.(*User); ok {
				return cachedUser, nil
			}
			// Handle negative cache
			if cached == nil {
				return nil, ErrUserNotFound
			}
		}
	}

	// Cache miss - fetch from LDAP
	start := time.Now()
	user, err = l.findUserByMailDirect(ctx, mail, options)
	duration := time.Since(start)

	// Cache the result with multi-key strategy
	if l.cache != nil && err == nil && user != nil {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		// Cache by email
		l.cache.SetContext(ctx, cacheKey, user, cacheTTL)

		// Also cache by DN and SAM account name
		dnCacheKey := GenerateCacheKey("user:dn", user.DN())
		l.cache.SetContext(ctx, dnCacheKey, user, cacheTTL)

		samCacheKey := GenerateCacheKey("user:sam", user.SAMAccountName)
		l.cache.SetContext(ctx, samCacheKey, user, cacheTTL)
	} else if l.cache != nil && err == ErrUserNotFound && options.UseNegativeCache {
		// Cache negative result
		if negativeTTL := l.config.Cache.NegativeCacheTTL; negativeTTL > 0 {
			l.cache.SetNegative(cacheKey, negativeTTL)
		}
	}

	l.logger.Debug("user_search_by_mail_completed",
		slog.String("operation", "FindUserByMail"),
		slog.String("mail", mail),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit))

	return user, err
}

// FindUsersOptimized retrieves all users with intelligent caching and batch processing.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - []User: A slice of all user objects found
//   - error: Any LDAP operation error
func (l *LDAP) FindUsersOptimized(ctx context.Context, options *SearchOptions) (users []User, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "FindUsers")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() { recordFunc(cacheHit, err, len(users)) }()

	// Generate cache key for all users list
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("users:all", l.config.BaseDN)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedUsers, ok := cached.([]User); ok {
				l.logger.Debug("users_cache_hit",
					slog.String("operation", "FindUsers"),
					slog.Int("user_count", len(cachedUsers)))
				return cachedUsers, nil
			}
		}
	}

	// Cache miss - fetch from LDAP
	start := time.Now()
	users, err = l.findUsersDirect(ctx, options)
	duration := time.Since(start)

	// Cache the result
	if l.cache != nil && err == nil && len(users) > 0 {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		// Cache the full user list
		if cacheErr := l.cache.SetContext(ctx, cacheKey, users, cacheTTL); cacheErr != nil {
			l.logger.Debug("users_cache_set_failed",
				slog.String("error", cacheErr.Error()))
		}

		// Also cache individual users for faster lookups
		go l.cacheIndividualUsers(users, cacheTTL)
	}

	l.logger.Debug("users_search_completed",
		slog.String("operation", "FindUsers"),
		slog.Int("user_count", len(users)),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit))

	return users, err
}

// BulkFindUsersBySAMAccountName performs bulk user lookups with batching and caching.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - samAccountNames: List of SAM account names to search for
//   - options: Optional bulk search options
//
// Returns:
//   - map[string]*User: Map of SAM account name to User object (nil if not found)
//   - error: Any critical error that stopped the bulk operation
func (l *LDAP) BulkFindUsersBySAMAccountName(ctx context.Context, samAccountNames []string, options *BulkSearchOptions) (map[string]*User, error) {
	if options == nil {
		options = DefaultBulkSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "BulkFindUsersBySAMAccountName")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	defer func() { recordFunc(false, nil, len(samAccountNames)) }() // Bulk operations don't use cache hit tracking

	result := make(map[string]*User, len(samAccountNames))
	var remaining []string

	// Check cache for each user first
	if l.cache != nil && options.UseCache {
		for _, samAccountName := range samAccountNames {
			cacheKey := GenerateCacheKey("user:sam", samAccountName)
			if cached, found := l.cache.GetContext(ctx, cacheKey); found {
				if cachedUser, ok := cached.(*User); ok {
					result[samAccountName] = cachedUser
				} else {
					result[samAccountName] = nil // Negative cache hit
				}
			} else {
				remaining = append(remaining, samAccountName)
			}
		}

		l.logger.Debug("bulk_user_cache_check",
			slog.Int("total_requested", len(samAccountNames)),
			slog.Int("cache_hits", len(samAccountNames)-len(remaining)),
			slog.Int("cache_misses", len(remaining)))
	} else {
		remaining = samAccountNames
	}

	// Process remaining users in batches
	if len(remaining) > 0 {
		if err := l.processBulkUserSearch(ctx, remaining, result, options); err != nil && !options.ContinueOnError {
			return result, err
		}
	}

	l.logger.Info("bulk_user_search_completed",
		slog.Int("total_requested", len(samAccountNames)),
		slog.Int("found", l.countFoundUsers(result)),
		slog.Int("not_found", l.countNotFoundUsers(result)))

	return result, nil
}

// Helper methods for direct LDAP operations (without caching)

// findUserByDNDirect performs direct LDAP lookup without caching
func (l *LDAP) findUserByDNDirect(ctx context.Context, dn string, options *SearchOptions) (*User, error) {
	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection for user DN search: %w", err)
	}
	defer c.Close()

	// Apply timeout if specified in options
	searchCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		searchCtx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Check for context cancellation before search
	select {
	case <-searchCtx.Done():
		return nil, fmt.Errorf("user search cancelled for DN %s: %w", dn, WrapLDAPError("FindUserByDN", l.config.Server, searchCtx.Err()))
	default:
	}

	attributes := userFields
	if options.AttributeFilter != nil {
		attributes = options.AttributeFilter
	}

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))",
		Attributes:   attributes,
	})
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("user search failed for DN %s: %w", dn, WrapLDAPError("FindUserByDN", l.config.Server, err))
	}

	if len(r.Entries) == 0 {
		return nil, ErrUserNotFound
	}

	if len(r.Entries) > 1 {
		return nil, fmt.Errorf("duplicate DN found %s (count: %d): %w", dn, len(r.Entries), ErrDNDuplicated)
	}

	return userFromEntry(r.Entries[0])
}

// findUserBySAMAccountNameDirect performs direct LDAP lookup without caching
func (l *LDAP) findUserBySAMAccountNameDirect(ctx context.Context, samAccountName string, options *SearchOptions) (*User, error) {
	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection for SAM account search: %w", err)
	}
	defer c.Close()

	// Apply timeout if specified in options
	searchCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		searchCtx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Check for context cancellation
	select {
	case <-searchCtx.Done():
		return nil, fmt.Errorf("user search cancelled for SAM account %s: %w", samAccountName, WrapLDAPError("FindUserBySAMAccountName", l.config.Server, searchCtx.Err()))
	default:
	}

	attributes := userFields
	if options.AttributeFilter != nil {
		attributes = options.AttributeFilter
	}

	// Try Active Directory search first
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(samAccountName))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   attributes,
		SizeLimit:    options.MaxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("user search failed for SAM account %s: %w", samAccountName, WrapLDAPError("FindUserBySAMAccountName", l.config.Server, err))
	}

	// If no results with Active Directory filter, try OpenLDAP compatibility
	if len(r.Entries) == 0 && !l.config.IsActiveDirectory {
		filter = fmt.Sprintf("(&(|(objectClass=inetOrgPerson)(objectClass=person))(uid=%s))", ldap.EscapeFilter(samAccountName))
		r, err = c.Search(&ldap.SearchRequest{
			BaseDN:       l.config.BaseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Filter:       filter,
			Attributes:   []string{"memberOf", "cn", "uid", "mail", "description"},
			SizeLimit:    options.MaxResults,
		})
		if err != nil {
			return nil, err
		}
	}

	if len(r.Entries) == 0 {
		return nil, ErrUserNotFound
	}
	if len(r.Entries) > 1 {
		return nil, ErrSAMAccountNameDuplicated
	}

	return userFromEntry(r.Entries[0])
}

// findUserByMailDirect performs direct LDAP lookup without caching
func (l *LDAP) findUserByMailDirect(ctx context.Context, mail string, options *SearchOptions) (*User, error) {
	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// Apply timeout if specified in options
	searchCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		searchCtx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	select {
	case <-searchCtx.Done():
		return nil, searchCtx.Err()
	default:
	}

	attributes := userFields
	if options.AttributeFilter != nil {
		attributes = options.AttributeFilter
	}

	filter := fmt.Sprintf("(&(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))(mail=%s))", ldap.EscapeFilter(mail))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   attributes,
		SizeLimit:    options.MaxResults,
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrUserNotFound
	}
	if len(r.Entries) > 1 {
		return nil, ErrMailDuplicated
	}

	return userFromEntry(r.Entries[0])
}

// findUsersDirect performs direct LDAP lookup for all users without caching
func (l *LDAP) findUsersDirect(ctx context.Context, options *SearchOptions) ([]User, error) {
	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// Apply timeout if specified in options
	searchCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		searchCtx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	select {
	case <-searchCtx.Done():
		return nil, searchCtx.Err()
	default:
	}

	attributes := userFields
	if options.AttributeFilter != nil {
		attributes = options.AttributeFilter
	}

	filter := "(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))"

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   attributes,
		SizeLimit:    options.MaxResults,
	})
	if err != nil {
		return nil, err
	}

	var users []User
	for _, entry := range r.Entries {
		// Check for context cancellation during processing
		select {
		case <-searchCtx.Done():
			return nil, searchCtx.Err()
		default:
		}

		user, err := userFromEntry(entry)
		if err != nil {
			l.logger.Debug("user_entry_skipped",
				slog.String("dn", entry.DN),
				slog.String("error", err.Error()))
			continue
		}

		users = append(users, *user)
	}

	return users, nil
}

// Helper methods for bulk operations

// processBulkUserSearch processes remaining users from bulk search in batches
func (l *LDAP) processBulkUserSearch(ctx context.Context, remaining []string, result map[string]*User, options *BulkSearchOptions) error {
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = 10
	}

	// Process in batches
	for i := 0; i < len(remaining); i += batchSize {
		end := i + batchSize
		if end > len(remaining) {
			end = len(remaining)
		}

		batch := remaining[i:end]
		if err := l.processBatch(ctx, batch, result, options); err != nil {
			if !options.ContinueOnError {
				return err
			}
			l.logger.Warn("bulk_user_batch_failed",
				slog.String("error", err.Error()),
				slog.Int("batch_start", i),
				slog.Int("batch_size", len(batch)))
		}

		// Check for context cancellation between batches
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	return nil
}

// processBatch processes a single batch of user searches
func (l *LDAP) processBatch(ctx context.Context, batch []string, result map[string]*User, options *BulkSearchOptions) error {
	// Apply batch timeout
	batchCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		batchCtx, cancel = context.WithTimeout(ctx, options.Timeout/time.Duration(len(batch)/options.BatchSize+1))
		defer cancel()
	}

	for _, samAccountName := range batch {
		searchOptions := DefaultSearchOptions()
		searchOptions.UseNegativeCache = options.UseCache

		user, err := l.findUserBySAMAccountNameDirect(batchCtx, samAccountName, searchOptions)
		if err != nil {
			if err == ErrUserNotFound {
				result[samAccountName] = nil
			} else if !options.ContinueOnError {
				return err
			} else {
				l.logger.Warn("bulk_user_search_item_failed",
					slog.String("sam_account_name", samAccountName),
					slog.String("error", err.Error()))
				result[samAccountName] = nil
			}
		} else {
			result[samAccountName] = user

			// Cache the result if caching is enabled
			if l.cache != nil && options.UseCache {
				cacheKey := GenerateCacheKey("user:sam", samAccountName)
				cacheTTL := l.config.Cache.TTL
				if cacheTTL > 0 {
					l.cache.SetContext(batchCtx, cacheKey, user, cacheTTL)
				}
			}
		}

		// Check for context cancellation
		select {
		case <-batchCtx.Done():
			return batchCtx.Err()
		default:
		}
	}

	return nil
}

// cacheIndividualUsers caches individual users from a user list in the background
func (l *LDAP) cacheIndividualUsers(users []User, cacheTTL time.Duration) {
	for _, user := range users {
		// Cache by DN
		dnCacheKey := GenerateCacheKey("user:dn", user.DN())
		l.cache.Set(dnCacheKey, &user, cacheTTL)

		// Cache by SAM account name
		samCacheKey := GenerateCacheKey("user:sam", user.SAMAccountName)
		l.cache.Set(samCacheKey, &user, cacheTTL)

		// Cache by email if available
		if user.Mail != nil {
			emailCacheKey := GenerateCacheKey("user:mail", *user.Mail)
			l.cache.Set(emailCacheKey, &user, cacheTTL)
		}
	}

	l.logger.Debug("individual_users_cached",
		slog.Int("user_count", len(users)),
		slog.Duration("ttl", cacheTTL))
}

// countFoundUsers counts non-nil users in a bulk result
func (l *LDAP) countFoundUsers(result map[string]*User) int {
	count := 0
	for _, user := range result {
		if user != nil {
			count++
		}
	}
	return count
}

// countNotFoundUsers counts nil users in a bulk result
func (l *LDAP) countNotFoundUsers(result map[string]*User) int {
	count := 0
	for _, user := range result {
		if user == nil {
			count++
		}
	}
	return count
}
