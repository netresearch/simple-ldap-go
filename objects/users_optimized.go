package objects

import (
	"context"
	"log/slog"
	"time"
)

// FindUserByDNOptimized retrieves a user by their distinguished name with caching and performance monitoring.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists, or any LDAP operation error
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
	cacheKey := GenerateCacheKey("user:dn", dn)
	start := time.Now()

	defer func() {
		recordFunc(cacheHit, err, countUsers(user))
	}()

	// Try cache first if enabled
	if l.cache != nil && options.UseCache {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			if cachedUser, ok := cached.(*User); ok {
				cacheHit = true
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserByDN"),
					slog.String("dn", dn),
					slog.String("cache_key", cacheKey))
				return cachedUser, nil
			}
		}
	}

	// Cache miss - perform LDAP lookup
	user, err = l.FindUserByDNContext(ctx, dn)
	duration := time.Since(start)

	// Cache the result if successful and caching is enabled
	if err == nil && user != nil && l.cache != nil && options.UseCache {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		if cacheErr := l.cache.SetContext(ctx, cacheKey, user, cacheTTL); cacheErr != nil {
			l.logger.Warn("user_cache_set_failed",
				slog.String("operation", "FindUserByDN"),
				slog.String("dn", dn),
				slog.String("cache_key", cacheKey),
				slog.String("error", cacheErr.Error()))
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
			if negErr := l.cache.SetNegative(cacheKey, negativeTTL); negErr != nil {
				l.logger.Warn("negative_cache_set_failed",
					slog.String("operation", "FindUserByDN"),
					slog.String("dn", dn),
					slog.String("cache_key", cacheKey),
					slog.String("error", negErr.Error()))
			} else {
				l.logger.Debug("user_negative_cached",
					slog.String("operation", "FindUserByDN"),
					slog.String("dn", dn),
					slog.Duration("ttl", negativeTTL))
			}
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
		recordFunc(cacheHit, err, countUsers(user))
	}()

	cacheKey := GenerateCacheKey("user:sam", samAccountName)
	start := time.Now()

	// Try cache first if enabled
	if l.cache != nil && options.UseCache {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			if cachedUser, ok := cached.(*User); ok {
				cacheHit = true
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserBySAMAccountName"),
					slog.String("sam_account_name", samAccountName),
					slog.String("cache_key", cacheKey))
				return cachedUser, nil
			}
		}
	}

	// Cache miss - perform LDAP lookup
	user, err = l.FindUserBySAMAccountNameContext(ctx, samAccountName)
	duration := time.Since(start)

	// Cache the result if successful and caching is enabled
	if err == nil && user != nil && l.cache != nil && options.UseCache {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		if cacheErr := l.cache.SetContext(ctx, cacheKey, user, cacheTTL); cacheErr != nil {
			l.logger.Warn("user_cache_set_failed",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("sam_account_name", samAccountName),
				slog.String("cache_key", cacheKey),
				slog.String("error", cacheErr.Error()))
		} else {
			l.logger.Debug("user_cached",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("sam_account_name", samAccountName),
				slog.String("cache_key", cacheKey))
		}

		// Also cache by DN for DN lookups
		dnCacheKey := GenerateCacheKey("user:dn", user.DN())
		if cacheErr := l.cache.SetContext(ctx, dnCacheKey, user, cacheTTL); cacheErr != nil {
			l.logger.Warn("user_dn_cache_set_failed",
				slog.String("operation", "FindUserBySAMAccountName"),
				slog.String("dn", user.DN()),
				slog.String("cache_key", dnCacheKey),
				slog.String("error", cacheErr.Error()))
		}

		// Cache by email if available
		if user.Mail != nil {
			emailCacheKey := GenerateCacheKey("user:mail", *user.Mail)
			if cacheErr := l.cache.SetContext(ctx, emailCacheKey, user, cacheTTL); cacheErr != nil {
				l.logger.Warn("user_email_cache_set_failed",
					slog.String("operation", "FindUserBySAMAccountName"),
					slog.String("email", *user.Mail),
					slog.String("cache_key", emailCacheKey),
					slog.String("error", cacheErr.Error()))
			}
		}
	} else if l.cache != nil && err == ErrUserNotFound && options.UseNegativeCache {
		// Cache negative result
		if negativeTTL := l.config.Cache.NegativeCacheTTL; negativeTTL > 0 {
			if negErr := l.cache.SetNegative(cacheKey, negativeTTL); negErr != nil {
				l.logger.Warn("negative_cache_set_failed",
					slog.String("operation", "FindUserBySAMAccountName"),
					slog.String("sam_account_name", samAccountName),
					slog.String("cache_key", cacheKey),
					slog.String("error", negErr.Error()))
			}
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
		recordFunc(cacheHit, err, countUsers(user))
	}()

	cacheKey := GenerateCacheKey("user:mail", mail)
	start := time.Now()

	// Try cache first if enabled
	if l.cache != nil && options.UseCache {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			if cachedUser, ok := cached.(*User); ok {
				cacheHit = true
				l.logger.Debug("user_cache_hit",
					slog.String("operation", "FindUserByMail"),
					slog.String("mail", mail),
					slog.String("cache_key", cacheKey))
				return cachedUser, nil
			}
		}
	}

	// Cache miss - perform LDAP lookup
	user, err = l.FindUserByMailContext(ctx, mail)
	duration := time.Since(start)

	// Cache the result if successful and caching is enabled
	if err == nil && user != nil && l.cache != nil && options.UseCache {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		// Cache by email
		if cacheErr := l.cache.SetContext(ctx, cacheKey, user, cacheTTL); cacheErr != nil {
			l.logger.Warn("user_cache_set_failed",
				slog.String("operation", "FindUserByMail"),
				slog.String("mail", mail),
				slog.String("cache_key", cacheKey),
				slog.String("error", cacheErr.Error()))
		}

		// Also cache by DN and SAM account name
		dnCacheKey := GenerateCacheKey("user:dn", user.DN())
		if cacheErr := l.cache.SetContext(ctx, dnCacheKey, user, cacheTTL); cacheErr != nil {
			l.logger.Warn("user_dn_cache_set_failed",
				slog.String("operation", "FindUserByMail"),
				slog.String("dn", user.DN()),
				slog.String("cache_key", dnCacheKey),
				slog.String("error", cacheErr.Error()))
		}

		samCacheKey := GenerateCacheKey("user:sam", user.SAMAccountName)
		if cacheErr := l.cache.SetContext(ctx, samCacheKey, user, cacheTTL); cacheErr != nil {
			l.logger.Warn("user_sam_cache_set_failed",
				slog.String("operation", "FindUserByMail"),
				slog.String("sam_account_name", user.SAMAccountName),
				slog.String("cache_key", samCacheKey),
				slog.String("error", cacheErr.Error()))
		}
	} else if l.cache != nil && err == ErrUserNotFound && options.UseNegativeCache {
		// Cache negative result
		if negativeTTL := l.config.Cache.NegativeCacheTTL; negativeTTL > 0 {
			if negErr := l.cache.SetNegative(cacheKey, negativeTTL); negErr != nil {
				l.logger.Warn("negative_cache_set_failed",
					slog.String("operation", "FindUserByMail"),
					slog.String("mail", mail),
					slog.String("cache_key", cacheKey),
					slog.String("error", negErr.Error()))
			}
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
	defer func() {
		recordFunc(cacheHit, err, len(users))
	}()

	cacheKey := GenerateCacheKey("users:all")
	start := time.Now()

	// Try cache first if enabled
	if l.cache != nil && options.UseCache {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			if cachedUsers, ok := cached.([]User); ok {
				cacheHit = true
				l.logger.Debug("users_cache_hit",
					slog.String("operation", "FindUsers"),
					slog.String("cache_key", cacheKey),
					slog.Int("user_count", len(cachedUsers)))
				return cachedUsers, nil
			}
		}
	}

	// Cache miss - perform LDAP lookup
	users, err = l.FindUsersContext(ctx)
	duration := time.Since(start)

	// Cache the result if successful and caching is enabled
	if err == nil && l.cache != nil && options.UseCache && len(users) > 0 {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		// Cache the full list
		if cacheErr := l.cache.SetContext(ctx, cacheKey, users, cacheTTL); cacheErr != nil {
			l.logger.Warn("users_cache_set_failed",
				slog.String("operation", "FindUsers"),
				slog.String("cache_key", cacheKey),
				slog.String("error", cacheErr.Error()))
		} else {
			l.logger.Debug("users_cached",
				slog.String("operation", "FindUsers"),
				slog.String("cache_key", cacheKey),
				slog.Int("user_count", len(users)),
				slog.Duration("ttl", cacheTTL))
		}

		// Also cache individual users for faster single-user lookups
		l.cacheIndividualUsers(users, cacheTTL)
	}

	l.logger.Debug("users_search_completed",
		slog.String("operation", "FindUsers"),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit),
		slog.Int("user_count", len(users)))

	return users, err
}

// FindUsersBulkOptimized performs optimized bulk user lookups with intelligent caching and batch processing.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - identifiers: Map of identifier types to values (e.g., "dn" -> []string{...}, "sam" -> []string{...})
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - map[string]*User: Map of identifiers to user objects (nil for not found)
//   - error: Any LDAP operation error
//
// This method optimizes bulk lookups by:
//   - Checking cache for each identifier first
//   - Batching uncached lookups into single LDAP operations
//   - Cross-caching results by all available identifiers
//   - Providing detailed performance metrics
func (l *LDAP) FindUsersBulkOptimized(ctx context.Context, identifiers map[string][]string, options *SearchOptions) (map[string]*User, error) {
	if options == nil {
		options = DefaultSearchOptions()
	}

	start := time.Now()
	result := make(map[string]*User)
	totalRequested := 0

	// Count total identifiers for metrics
	for _, idList := range identifiers {
		totalRequested += len(idList)
	}

	l.logger.Debug("bulk_user_search_started",
		slog.String("operation", "FindUsersBulkOptimized"),
		slog.Int("total_identifiers", totalRequested))

	// Process each identifier type
	var cacheHits, cacheMisses int
	uncachedDNs := make([]string, 0)
	uncachedSAMs := make([]string, 0)
	uncachedMails := make([]string, 0)

	// Check cache for all identifiers first
	if l.cache != nil && options.UseCache {
		cacheHits, cacheMisses = l.checkBulkCache(ctx, identifiers, result)

		// Collect uncached identifiers for batch lookup
		for idType, idList := range identifiers {
			for _, id := range idList {
				if _, found := result[id]; !found {
					switch idType {
					case "dn":
						uncachedDNs = append(uncachedDNs, id)
					case "sam":
						uncachedSAMs = append(uncachedSAMs, id)
					case "mail":
						uncachedMails = append(uncachedMails, id)
					}
				}
			}
		}
	} else {
		// No caching - prepare all for lookup
		if dns, ok := identifiers["dn"]; ok {
			uncachedDNs = dns
		}
		if sams, ok := identifiers["sam"]; ok {
			uncachedSAMs = sams
		}
		if mails, ok := identifiers["mail"]; ok {
			uncachedMails = mails
		}
	}

	// Perform batch lookups for uncached identifiers
	if len(uncachedDNs) > 0 {
		l.batchLookupByDN(ctx, uncachedDNs, result, options)
	}
	if len(uncachedSAMs) > 0 {
		l.batchLookupBySAM(ctx, uncachedSAMs, result, options)
	}
	if len(uncachedMails) > 0 {
		l.batchLookupByMail(ctx, uncachedMails, result, options)
	}

	// Cache new results if caching is enabled
	if l.cache != nil && options.UseCache {
		l.cacheBulkResults(ctx, result, options)
	}

	// Performance monitoring
	duration := time.Since(start)
	found := l.countFoundUsers(result)
	notFound := l.countNotFoundUsers(result)

	if l.perfMonitor != nil {
		l.perfMonitor.RecordOperation(ctx, "FindUsersBulkOptimized", duration, cacheHits > 0, nil, found)
	}

	l.logger.Info("bulk_user_search_completed",
		slog.String("operation", "FindUsersBulkOptimized"),
		slog.Duration("duration", duration),
		slog.Int("total_requested", totalRequested),
		slog.Int("found", found),
		slog.Int("not_found", notFound),
		slog.Int("cache_hits", cacheHits),
		slog.Int("cache_misses", cacheMisses))

	return result, nil
}

// checkBulkCache checks cache for all identifiers and populates initial results
func (l *LDAP) checkBulkCache(ctx context.Context, identifiers map[string][]string, result map[string]*User) (cacheHits, cacheMisses int) {
	for idType, idList := range identifiers {
		for _, id := range idList {
			cacheKey := GenerateCacheKey("user:"+idType, id)
			if cached, found := l.cache.GetContext(ctx, cacheKey); found {
				if user, ok := cached.(*User); ok {
					result[id] = user
					cacheHits++
					continue
				}
			}
			cacheMisses++
		}
	}
	return cacheHits, cacheMisses
}

// batchLookupByDN performs batch DN lookups
func (l *LDAP) batchLookupByDN(ctx context.Context, dns []string, result map[string]*User, options *SearchOptions) {
	for _, dn := range dns {
		user, err := l.FindUserByDNContext(ctx, dn)
		if err == nil && user != nil {
			result[dn] = user
		} else {
			result[dn] = nil // Explicitly mark as not found
		}
	}
}

// batchLookupBySAM performs batch SAM account name lookups
func (l *LDAP) batchLookupBySAM(ctx context.Context, sams []string, result map[string]*User, options *SearchOptions) {
	for _, sam := range sams {
		user, err := l.FindUserBySAMAccountNameContext(ctx, sam)
		if err == nil && user != nil {
			result[sam] = user
		} else {
			result[sam] = nil // Explicitly mark as not found
		}
	}
}

// batchLookupByMail performs batch email lookups
func (l *LDAP) batchLookupByMail(ctx context.Context, mails []string, result map[string]*User, options *SearchOptions) {
	for _, mail := range mails {
		user, err := l.FindUserByMailContext(ctx, mail)
		if err == nil && user != nil {
			result[mail] = user
		} else {
			result[mail] = nil // Explicitly mark as not found
		}
	}
}

// cacheBulkResults caches the results from bulk operations
func (l *LDAP) cacheBulkResults(ctx context.Context, result map[string]*User, options *SearchOptions) {
	cacheTTL := options.TTL
	if cacheTTL == 0 {
		cacheTTL = l.config.Cache.TTL
	}

	for identifier, user := range result {
		if user != nil {
			// Cache by the identifier used to find the user
			cacheKey := GenerateCacheKey("user:auto", identifier)
			if cacheErr := l.cache.SetContext(ctx, cacheKey, user, cacheTTL); cacheErr != nil {
				l.logger.Warn("bulk_cache_set_failed",
					slog.String("identifier", identifier),
					slog.String("cache_key", cacheKey),
					slog.String("error", cacheErr.Error()))
			}

			// Also cache by DN, SAM, and email for cross-referencing
			dnKey := GenerateCacheKey("user:dn", user.DN())
			if cacheErr := l.cache.SetContext(ctx, dnKey, user, cacheTTL); cacheErr != nil {
				l.logger.Warn("bulk_dn_cache_set_failed",
					slog.String("dn", user.DN()),
					slog.String("cache_key", dnKey),
					slog.String("error", cacheErr.Error()))
			}

			samKey := GenerateCacheKey("user:sam", user.SAMAccountName)
			if cacheErr := l.cache.SetContext(ctx, samKey, user, cacheTTL); cacheErr != nil {
				l.logger.Warn("bulk_sam_cache_set_failed",
					slog.String("sam_account_name", user.SAMAccountName),
					slog.String("cache_key", samKey),
					slog.String("error", cacheErr.Error()))
			}

			if user.Mail != nil {
				mailKey := GenerateCacheKey("user:mail", *user.Mail)
				if cacheErr := l.cache.SetContext(ctx, mailKey, user, cacheTTL); cacheErr != nil {
					l.logger.Warn("bulk_mail_cache_set_failed",
						slog.String("mail", *user.Mail),
						slog.String("cache_key", mailKey),
						slog.String("error", cacheErr.Error()))
				}
			}
		}
	}
}

// cacheIndividualUsers caches each user individually for single-user lookups
func (l *LDAP) cacheIndividualUsers(users []User, cacheTTL time.Duration) {
	for _, user := range users {
		// Cache by DN
		dnCacheKey := GenerateCacheKey("user:dn", user.DN())
		if cacheErr := l.cache.Set(dnCacheKey, &user, cacheTTL); cacheErr != nil {
			l.logger.Warn("individual_dn_cache_set_failed",
				slog.String("dn", user.DN()),
				slog.String("cache_key", dnCacheKey),
				slog.String("error", cacheErr.Error()))
		}

		// Cache by SAM account name
		samCacheKey := GenerateCacheKey("user:sam", user.SAMAccountName)
		if cacheErr := l.cache.Set(samCacheKey, &user, cacheTTL); cacheErr != nil {
			l.logger.Warn("individual_sam_cache_set_failed",
				slog.String("sam_account_name", user.SAMAccountName),
				slog.String("cache_key", samCacheKey),
				slog.String("error", cacheErr.Error()))
		}

		// Cache by email if available
		if user.Mail != nil {
			emailCacheKey := GenerateCacheKey("user:mail", *user.Mail)
			if cacheErr := l.cache.Set(emailCacheKey, &user, cacheTTL); cacheErr != nil {
				l.logger.Warn("individual_mail_cache_set_failed",
					slog.String("mail", *user.Mail),
					slog.String("cache_key", emailCacheKey),
					slog.String("error", cacheErr.Error()))
			}
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

// countUsers counts users for performance monitoring (handles both single user and slice)
func countUsers(user interface{}) int {
	if user == nil {
		return 0
	}
	switch v := user.(type) {
	case *User:
		if v == nil {
			return 0
		}
		return 1
	case []User:
		return len(v)
	default:
		return 1
	}
}