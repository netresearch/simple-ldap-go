package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrGroupNotFound is returned when a group search operation finds no matching entries.
var ErrGroupNotFound = errors.New("group not found")

// Group represents an LDAP group object with its members.
type Group struct {
	Object
	// Members contains a list of distinguished names (DNs) of group members.
	Members []string
}

// FullGroup represents a complete LDAP group object for creation and modification operations.
type FullGroup struct {
	// CN is the common name of the group (required, used as the RDN component).
	CN string
	// SAMAccountName is the Security Account Manager account name (optional).
	SAMAccountName string
	// Description provides additional information about the group (optional).
	Description string
	// GroupType defines the type and scope of the group (required for Active Directory).
	GroupType uint32
	// Member contains a list of distinguished names (DNs) of group members.
	Member []string
	// MemberOf contains a list of distinguished names (DNs) of parent groups.
	MemberOf []string
	// OtherAttributes contains additional LDAP attributes not covered by the above fields.
	OtherAttributes map[string][]string
}

// FindGroupByDN retrieves a group by its distinguished name.
//
// Parameters:
//   - dn: The distinguished name of the group (e.g., "CN=Administrators,CN=Builtin,DC=example,DC=com")
//
// Returns:
//   - *Group: The group object if found
//   - error: ErrGroupNotFound if no group exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     or any LDAP operation error
func (l *LDAP) FindGroupByDN(dn string) (group *Group, err error) {
	return l.FindGroupByDNContext(context.Background(), dn)
}

// FindGroupByDNContext retrieves a group by its distinguished name with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the group (e.g., "CN=Administrators,CN=Builtin,DC=example,DC=com")
//
// Returns:
//   - *Group: The group object if found
//   - error: ErrGroupNotFound if no group exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     context cancellation error, or any LDAP operation error
func (l *LDAP) FindGroupByDNContext(ctx context.Context, dn string) (group *Group, err error) {
	start := time.Now()

	// Check cache if enabled
	var cacheKey string
	if l.config.EnableCache && l.cache != nil {
		cacheKey = fmt.Sprintf("group:dn:%s", dn)
		if cached, found := l.cache.Get(cacheKey); found {
			if cachedGroup, ok := cached.(*Group); ok {
				l.logger.Debug("group_cache_hit",
					slog.String("operation", "FindGroupByDN"),
					slog.String("dn", dn),
					slog.Duration("duration", time.Since(start)))
				return cachedGroup, nil
			}
		}
	}

	// Use generic DN search function to eliminate code duplication
	params := dnSearchParams{
		operation:   "FindGroupByDN",
		filter:      "(|(objectClass=group)(objectClass=groupOfNames))",
		attributes:  []string{"cn", "member"},
		notFoundErr: ErrGroupNotFound,
		logPrefix:   "group_",
	}

	r, err := l.findByDNContext(ctx, dn, params)
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		l.logger.Debug("group_not_found_by_dn",
			slog.String("operation", "FindGroupByDN"),
			slog.String("dn", dn),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrGroupNotFound
	}

	if len(r.Entries) > 1 {
		l.logger.Error("group_dn_duplicated",
			slog.String("operation", "FindGroupByDN"),
			slog.String("dn", dn),
			slog.Int("count", len(r.Entries)),
			slog.Duration("duration", time.Since(start)))
		return nil, ErrDNDuplicated
	}

	group = &Group{
		Object:  objectFromEntry(r.Entries[0]),
		Members: r.Entries[0].GetAttributeValues("member"),
	}

	// Store in cache if enabled
	if l.config.EnableCache && l.cache != nil && cacheKey != "" {
		if err := l.cache.Set(cacheKey, group, 5*time.Minute); err != nil {
			l.logger.Debug("cache_set_error",
				slog.String("operation", "FindGroupByDN"),
				slog.String("key", cacheKey),
				slog.String("error", err.Error()))
		}
	}

	l.logger.Debug("group_found_by_dn",
		slog.String("operation", "FindGroupByDN"),
		slog.String("dn", dn),
		slog.String("cn", group.CN()),
		slog.Int("member_count", len(group.Members)),
		slog.Duration("duration", time.Since(start)))

	return
}

// FindGroups retrieves all group objects from the directory.
//
// Returns:
//   - []Group: A slice of all group objects found in the directory
//   - error: Any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Groups that cannot be parsed are skipped and not included in the results.
func (l *LDAP) FindGroups() (groups []Group, err error) {
	return l.FindGroupsContext(context.Background())
}

// FindGroupsContext retrieves all group objects from the directory with context support.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//
// Returns:
//   - []Group: A slice of all group objects found in the directory
//   - error: Any LDAP operation error or context cancellation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Groups that cannot be parsed are skipped and not included in the results.
func (l *LDAP) FindGroupsContext(ctx context.Context) (groups []Group, err error) {
	// Check for context cancellation first
	if err := l.checkContextCancellation(ctx, "FindGroups", "N/A", "start"); err != nil {
		return nil, ctx.Err()
	}

	start := time.Now()
	l.logger.Debug("group_list_search_started",
		slog.String("operation", "FindGroups"))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := c.Close(); err != nil {
			l.logger.Debug("connection_close_error",
				slog.String("operation", "FindGroups"),
				slog.String("error", err.Error()))
		}
	}()

	// Check for context cancellation before search
	select {
	case <-ctx.Done():
		l.logger.Debug("group_list_search_cancelled",
			slog.String("error", ctx.Err().Error()))
		return nil, ctx.Err()
	default:
	}

	filter := "(|(objectClass=group)(objectClass=groupOfNames))"
	l.logger.Debug("group_list_search_executing",
		slog.String("filter", filter),
		slog.String("base_dn", l.config.BaseDN))

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   []string{"cn", "member"},
	})
	if err != nil {
		l.logger.Error("group_list_search_failed",
			slog.String("operation", "FindGroups"),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	processed := 0
	totalMembers := 0

	for _, entry := range r.Entries {
		// Check for context cancellation during processing
		select {
		case <-ctx.Done():
			l.logger.Debug("group_list_processing_cancelled",
				slog.Int("processed", processed),
				slog.String("error", ctx.Err().Error()))
			return nil, ctx.Err()
		default:
		}

		members := entry.GetAttributeValues("member")
		group := Group{
			Object:  objectFromEntry(entry),
			Members: members,
		}

		groups = append(groups, group)
		processed++
		totalMembers += len(members)
	}

	l.logger.Info("group_list_search_completed",
		slog.String("operation", "FindGroups"),
		slog.Int("total_found", len(r.Entries)),
		slog.Int("processed", processed),
		slog.Int("total_members", totalMembers),
		slog.Duration("duration", time.Since(start)))

	return
}
