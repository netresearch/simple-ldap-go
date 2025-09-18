package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// FindGroupByDNOptimized retrieves a group by its distinguished name with caching and performance monitoring.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the group
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - *Group: The group object if found
//   - error: ErrGroupNotFound if no group exists with the given DN, or any LDAP operation error
func (l *LDAP) FindGroupByDNOptimized(ctx context.Context, dn string, options *SearchOptions) (group *Group, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "FindGroupByDN")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() {
		recordFunc(cacheHit, err, func() int {
			if group != nil {
				return 1
			} else {
				return 0
			}
		}())
	}()

	// Generate cache key
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("group:dn", dn)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedGroup, ok := cached.(*Group); ok {
				l.logger.Debug("group_cache_hit",
					slog.String("operation", "FindGroupByDN"),
					slog.String("dn", dn),
					slog.String("cache_key", cacheKey))
				return cachedGroup, nil
			}
			// Handle negative cache
			if cached == nil {
				l.logger.Debug("group_negative_cache_hit",
					slog.String("operation", "FindGroupByDN"),
					slog.String("dn", dn))
				return nil, ErrGroupNotFound
			}
		}
	}

	// Cache miss - fetch from LDAP
	l.logger.Debug("group_cache_miss_fetching",
		slog.String("operation", "FindGroupByDN"),
		slog.String("dn", dn))

	start := time.Now()
	group, err = l.findGroupByDNDirect(ctx, dn, options)
	duration := time.Since(start)

	// Cache the result
	if l.cache != nil && err == nil && group != nil {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		if cacheErr := l.cache.SetContext(ctx, cacheKey, group, cacheTTL); cacheErr != nil {
			l.logger.Debug("group_cache_set_failed",
				slog.String("error", cacheErr.Error()),
				slog.String("cache_key", cacheKey))
		} else {
			l.logger.Debug("group_cached",
				slog.String("operation", "FindGroupByDN"),
				slog.String("dn", dn),
				slog.String("cache_key", cacheKey),
				slog.Duration("ttl", cacheTTL))
		}

		// Cache group membership information for faster user group lookups
		go l.cacheGroupMembers(group, cacheTTL)

	} else if l.cache != nil && err == ErrGroupNotFound && options.UseNegativeCache {
		// Cache negative result
		negativeTTL := l.config.Cache.NegativeCacheTTL
		if negativeTTL > 0 {
			_ = l.cache.SetNegative(cacheKey, negativeTTL)
			l.logger.Debug("group_negative_cached",
				slog.String("operation", "FindGroupByDN"),
				slog.String("dn", dn),
				slog.Duration("ttl", negativeTTL))
		}
	}

	l.logger.Debug("group_search_by_dn_completed",
		slog.String("operation", "FindGroupByDN"),
		slog.String("dn", dn),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit),
		slog.Bool("found", group != nil))

	return group, err
}

// FindGroupsOptimized retrieves all groups with intelligent caching and batch processing.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - []Group: A slice of all group objects found
//   - error: Any LDAP operation error
func (l *LDAP) FindGroupsOptimized(ctx context.Context, options *SearchOptions) (groups []Group, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "FindGroups")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() { recordFunc(cacheHit, err, len(groups)) }()

	// Generate cache key for all groups list
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("groups:all", l.config.BaseDN)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedGroups, ok := cached.([]Group); ok {
				l.logger.Debug("groups_cache_hit",
					slog.String("operation", "FindGroups"),
					slog.Int("group_count", len(cachedGroups)))
				return cachedGroups, nil
			}
		}
	}

	// Cache miss - fetch from LDAP
	start := time.Now()
	groups, err = l.findGroupsDirect(ctx, options)
	duration := time.Since(start)

	// Cache the result
	if l.cache != nil && err == nil && len(groups) > 0 {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		// Cache the full groups list
		if cacheErr := l.cache.SetContext(ctx, cacheKey, groups, cacheTTL); cacheErr != nil {
			l.logger.Debug("groups_cache_set_failed",
				slog.String("error", cacheErr.Error()))
		}

		// Also cache individual groups for faster lookups
		go l.cacheIndividualGroups(groups, cacheTTL)
	}

	l.logger.Debug("groups_search_completed",
		slog.String("operation", "FindGroups"),
		slog.Int("group_count", len(groups)),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit))

	return groups, err
}

// GetUserGroupsOptimized retrieves all groups that a user is a member of with caching.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - userDN: The distinguished name of the user
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - []Group: A slice of groups the user belongs to
//   - error: Any LDAP operation error
func (l *LDAP) GetUserGroupsOptimized(ctx context.Context, userDN string, options *SearchOptions) (groups []Group, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "GetUserGroups")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() { recordFunc(cacheHit, err, len(groups)) }()

	// Generate cache key for user's groups
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("user:groups", userDN)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedGroups, ok := cached.([]Group); ok {
				l.logger.Debug("user_groups_cache_hit",
					slog.String("operation", "GetUserGroups"),
					slog.String("user_dn", userDN),
					slog.Int("group_count", len(cachedGroups)))
				return cachedGroups, nil
			}
		}
	}

	// Cache miss - fetch from LDAP
	start := time.Now()
	groups, err = l.getUserGroupsDirect(ctx, userDN, options)
	duration := time.Since(start)

	// Cache the result
	if l.cache != nil && err == nil {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		if cacheErr := l.cache.SetContext(ctx, cacheKey, groups, cacheTTL); cacheErr == nil {
			l.logger.Debug("user_groups_cached",
				slog.String("operation", "GetUserGroups"),
				slog.String("user_dn", userDN),
				slog.Int("group_count", len(groups)),
				slog.Duration("ttl", cacheTTL))
		}
	}

	l.logger.Debug("user_groups_search_completed",
		slog.String("operation", "GetUserGroups"),
		slog.String("user_dn", userDN),
		slog.Int("group_count", len(groups)),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit))

	return groups, err
}

// GetGroupMembersOptimized retrieves all members of a group with caching and lazy loading.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - groupDN: The distinguished name of the group
//   - options: Optional search options for cache and performance tuning
//
// Returns:
//   - []User: A slice of users who are members of the group
//   - error: Any LDAP operation error
func (l *LDAP) GetGroupMembersOptimized(ctx context.Context, groupDN string, options *SearchOptions) (members []User, err error) {
	// Use defaults if no options provided
	if options == nil {
		options = DefaultSearchOptions()
	}

	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "GetGroupMembers")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	cacheHit := false
	defer func() { recordFunc(cacheHit, err, len(members)) }()

	// Generate cache key for group members
	cacheKey := options.CacheKey
	if cacheKey == "" {
		cacheKey = GenerateCacheKey("group:members", groupDN)
	}

	// Try cache first if enabled
	if l.cache != nil {
		if cached, found := l.cache.GetContext(ctx, cacheKey); found {
			cacheHit = true
			if cachedMembers, ok := cached.([]User); ok {
				l.logger.Debug("group_members_cache_hit",
					slog.String("operation", "GetGroupMembers"),
					slog.String("group_dn", groupDN),
					slog.Int("member_count", len(cachedMembers)))
				return cachedMembers, nil
			}
		}
	}

	// Cache miss - fetch from LDAP
	start := time.Now()
	members, err = l.getGroupMembersDirect(ctx, groupDN, options)
	duration := time.Since(start)

	// Cache the result
	if l.cache != nil && err == nil {
		cacheTTL := options.TTL
		if cacheTTL == 0 {
			cacheTTL = l.config.Cache.TTL
		}

		if cacheErr := l.cache.SetContext(ctx, cacheKey, members, cacheTTL); cacheErr == nil {
			l.logger.Debug("group_members_cached",
				slog.String("operation", "GetGroupMembers"),
				slog.String("group_dn", groupDN),
				slog.Int("member_count", len(members)),
				slog.Duration("ttl", cacheTTL))
		}

		// Also cache individual members
		go l.cacheIndividualUsers(members, cacheTTL)
	}

	l.logger.Debug("group_members_search_completed",
		slog.String("operation", "GetGroupMembers"),
		slog.String("group_dn", groupDN),
		slog.Int("member_count", len(members)),
		slog.Duration("duration", duration),
		slog.Bool("cache_hit", cacheHit))

	return members, err
}

// AddUserToGroupOptimized adds a user to a group with cache invalidation.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - userDN: The distinguished name of the user to add
//   - groupDN: The distinguished name of the group
//
// Returns:
//   - error: Any LDAP operation error
func (l *LDAP) AddUserToGroupOptimized(ctx context.Context, userDN, groupDN string) error {
	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "AddUserToGroup")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	defer func() { recordFunc(false, nil, 1) }() // Write operations don't use cache

	start := time.Now()
	l.logger.Info("user_group_add_started",
		slog.String("operation", "AddUserToGroup"),
		slog.String("user_dn", userDN),
		slog.String("group_dn", groupDN))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer c.Close()

	// Check for context cancellation before modify operation
	select {
	case <-ctx.Done():
		l.logger.Debug("user_group_add_cancelled",
			slog.String("user_dn", userDN),
			slog.String("group_dn", groupDN),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()
	default:
	}

	req := ldap.NewModifyRequest(groupDN, nil)
	req.Add("member", []string{userDN})

	err = c.Modify(req)
	if err != nil {
		l.logger.Error("user_group_add_failed",
			slog.String("operation", "AddUserToGroup"),
			slog.String("user_dn", userDN),
			slog.String("group_dn", groupDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return err
	}

	// Invalidate relevant cache entries
	if l.cache != nil {
		l.invalidateGroupCache(userDN, groupDN)
	}

	l.logger.Info("user_group_add_successful",
		slog.String("operation", "AddUserToGroup"),
		slog.String("user_dn", userDN),
		slog.String("group_dn", groupDN),
		slog.Duration("duration", time.Since(start)))

	return nil
}

// RemoveUserFromGroupOptimized removes a user from a group with cache invalidation.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - userDN: The distinguished name of the user to remove
//   - groupDN: The distinguished name of the group
//
// Returns:
//   - error: Any LDAP operation error
func (l *LDAP) RemoveUserFromGroupOptimized(ctx context.Context, userDN, groupDN string) error {
	// Start performance monitoring
	var recordFunc func(bool, error, int)
	if l.perfMonitor != nil {
		recordFunc = l.perfMonitor.StartOperation(ctx, "RemoveUserFromGroup")
	} else {
		recordFunc = func(bool, error, int) {} // No-op
	}

	defer func() { recordFunc(false, nil, 1) }() // Write operations don't use cache

	start := time.Now()
	l.logger.Info("user_group_remove_started",
		slog.String("operation", "RemoveUserFromGroup"),
		slog.String("user_dn", userDN),
		slog.String("group_dn", groupDN))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer c.Close()

	// Check for context cancellation before modify operation
	select {
	case <-ctx.Done():
		l.logger.Debug("user_group_remove_cancelled",
			slog.String("user_dn", userDN),
			slog.String("group_dn", groupDN),
			slog.String("error", ctx.Err().Error()))
		return ctx.Err()
	default:
	}

	req := ldap.NewModifyRequest(groupDN, nil)
	req.Delete("member", []string{userDN})

	err = c.Modify(req)
	if err != nil {
		l.logger.Error("user_group_remove_failed",
			slog.String("operation", "RemoveUserFromGroup"),
			slog.String("user_dn", userDN),
			slog.String("group_dn", groupDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return err
	}

	// Invalidate relevant cache entries
	if l.cache != nil {
		l.invalidateGroupCache(userDN, groupDN)
	}

	l.logger.Info("user_group_remove_successful",
		slog.String("operation", "RemoveUserFromGroup"),
		slog.String("user_dn", userDN),
		slog.String("group_dn", groupDN),
		slog.Duration("duration", time.Since(start)))

	return nil
}

// Helper methods for direct LDAP operations (without caching)

// findGroupByDNDirect performs direct LDAP lookup without caching
func (l *LDAP) findGroupByDNDirect(ctx context.Context, dn string, options *SearchOptions) (*Group, error) {
	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection for group DN search: %w", err)
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
		return nil, fmt.Errorf("group search cancelled for DN %s: %w", dn, WrapLDAPError("FindGroupByDN", l.config.Server, searchCtx.Err()))
	default:
	}

	attributes := []string{"cn", "member"}
	if options.AttributeFilter != nil {
		attributes = options.AttributeFilter
	}

	filter := "(|(objectClass=group)(objectClass=groupOfNames))"

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   attributes,
	})
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("group search failed for DN %s: %w", dn, WrapLDAPError("FindGroupByDN", l.config.Server, err))
	}

	if len(r.Entries) == 0 {
		return nil, ErrGroupNotFound
	}

	if len(r.Entries) > 1 {
		return nil, ErrDNDuplicated
	}

	group := &Group{
		Object:  objectFromEntry(r.Entries[0]),
		Members: r.Entries[0].GetAttributeValues("member"),
	}

	return group, nil
}

// findGroupsDirect performs direct LDAP lookup for all groups without caching
func (l *LDAP) findGroupsDirect(ctx context.Context, options *SearchOptions) ([]Group, error) {
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

	// Check for context cancellation before search
	select {
	case <-searchCtx.Done():
		return nil, searchCtx.Err()
	default:
	}

	attributes := []string{"cn", "member"}
	if options.AttributeFilter != nil {
		attributes = options.AttributeFilter
	}

	filter := "(|(objectClass=group)(objectClass=groupOfNames))"

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

	var groups []Group
	for _, entry := range r.Entries {
		// Check for context cancellation during processing
		select {
		case <-searchCtx.Done():
			return nil, searchCtx.Err()
		default:
		}

		members := entry.GetAttributeValues("member")
		group := Group{
			Object:  objectFromEntry(entry),
			Members: members,
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// getUserGroupsDirect performs direct LDAP lookup for user's groups without caching
func (l *LDAP) getUserGroupsDirect(ctx context.Context, userDN string, options *SearchOptions) ([]Group, error) {
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

	attributes := []string{"cn", "member"}
	if options.AttributeFilter != nil {
		attributes = options.AttributeFilter
	}

	// Search for groups that have this user as a member
	filter := fmt.Sprintf("(&(|(objectClass=group)(objectClass=groupOfNames))(member=%s))", ldap.EscapeFilter(userDN))

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

	var groups []Group
	for _, entry := range r.Entries {
		select {
		case <-searchCtx.Done():
			return nil, searchCtx.Err()
		default:
		}

		group := Group{
			Object:  objectFromEntry(entry),
			Members: entry.GetAttributeValues("member"),
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// getGroupMembersDirect performs direct LDAP lookup for group members without caching
func (l *LDAP) getGroupMembersDirect(ctx context.Context, groupDN string, options *SearchOptions) ([]User, error) {
	// First get the group to retrieve member DNs
	group, err := l.findGroupByDNDirect(ctx, groupDN, options)
	if err != nil {
		return nil, err
	}

	if len(group.Members) == 0 {
		return []User{}, nil
	}

	// Now fetch each member user object
	var members []User
	for _, memberDN := range group.Members {
		// Apply batch processing to avoid overwhelming the server
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Try to get from cache first if available
		var user *User
		if l.cache != nil {
			cacheKey := GenerateCacheKey("user:dn", memberDN)
			if cached, found := l.cache.GetContext(ctx, cacheKey); found {
				if cachedUser, ok := cached.(*User); ok {
					user = cachedUser
				}
			}
		}

		// If not in cache, fetch from LDAP
		if user == nil {
			fetchedUser, err := l.FindUserByDNContext(ctx, memberDN)
			if err != nil {
				if err == ErrUserNotFound {
					l.logger.Debug("group_member_not_found",
						slog.String("member_dn", memberDN),
						slog.String("group_dn", groupDN))
					continue
				}
				l.logger.Warn("group_member_fetch_failed",
					slog.String("member_dn", memberDN),
					slog.String("group_dn", groupDN),
					slog.String("error", err.Error()))
				continue
			}
			user = fetchedUser
		}

		members = append(members, *user)
	}

	return members, nil
}

// Helper methods for caching

// cacheIndividualGroups caches individual groups from a group list in the background
func (l *LDAP) cacheIndividualGroups(groups []Group, cacheTTL time.Duration) {
	for _, group := range groups {
		// Cache by DN
		dnCacheKey := GenerateCacheKey("group:dn", group.DN())
		_ = l.cache.Set(dnCacheKey, &group, cacheTTL)

		// Cache group membership information
	}

	l.logger.Debug("individual_groups_cached",
		slog.Int("group_count", len(groups)),
		slog.Duration("ttl", cacheTTL))
}

// cacheGroupMembers caches group membership information for faster user group lookups
func (l *LDAP) cacheGroupMembers(group *Group, cacheTTL time.Duration) {
	if len(group.Members) == 0 {
		return
	}

	// Cache reverse lookup: for each member, cache that they belong to this group
	for _, memberDN := range group.Members {
		membershipKey := GenerateCacheKey("membership", memberDN, group.DN())
		_ = l.cache.Set(membershipKey, true, cacheTTL)
	}

	l.logger.Debug("group_membership_cached",
		slog.String("group_dn", group.DN()),
		slog.Int("member_count", len(group.Members)))
}

// invalidateGroupCache invalidates relevant cache entries after group membership changes
func (l *LDAP) invalidateGroupCache(userDN, groupDN string) {
	// Invalidate user's groups cache
	userGroupsKey := GenerateCacheKey("user:groups", userDN)
	l.cache.Delete(userGroupsKey)

	// Invalidate group members cache
	groupMembersKey := GenerateCacheKey("group:members", groupDN)
	l.cache.Delete(groupMembersKey)

	// Invalidate group object cache (member count may have changed)
	groupDNKey := GenerateCacheKey("group:dn", groupDN)
	l.cache.Delete(groupDNKey)

	// Invalidate all groups cache
	allGroupsKey := GenerateCacheKey("groups:all", l.config.BaseDN)
	l.cache.Delete(allGroupsKey)

	// Invalidate membership cache
	membershipKey := GenerateCacheKey("membership", userDN, groupDN)
	l.cache.Delete(membershipKey)

	l.logger.Debug("group_cache_invalidated",
		slog.String("user_dn", userDN),
		slog.String("group_dn", groupDN))
}
