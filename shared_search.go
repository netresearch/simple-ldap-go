package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// dnSearchParams contains parameters for DN-based search operations
// This helps eliminate code duplication between user and group searches
type dnSearchParams struct {
	operation   string   // e.g., "FindUserByDN", "FindGroupByDN"
	filter      string   // LDAP filter to use
	attributes  []string // Attributes to retrieve
	notFoundErr error    // Error to return when object not found
	logPrefix   string   // Prefix for log messages (e.g., "user_", "group_")
}

// findByDNContext is a generic function for DN-based searches
// Eliminates ~50 lines of duplicated code between user and group searches
func (l *LDAP) findByDNContext(ctx context.Context, dn string, params dnSearchParams) (*ldap.SearchResult, error) {
	start := time.Now()
	l.logger.Debug(params.logPrefix+"search_by_dn_started",
		slog.String("operation", params.operation),
		slog.String("dn", dn))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection for %s search: %w", params.logPrefix[:len(params.logPrefix)-1], err)
	}
	defer func() {
		if releaseErr := l.ReleaseConnection(c); releaseErr != nil {
			l.logger.Debug("connection_release_error",
				slog.String("operation", params.logPrefix),
				slog.String("error", releaseErr.Error()))
		}
	}()

	// Check for context cancellation before search
	select {
	case <-ctx.Done():
		l.logger.Debug(params.logPrefix+"search_cancelled",
			slog.String("operation", params.operation),
			slog.String("dn", dn),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("%s search cancelled for DN %s: %w", params.logPrefix[:len(params.logPrefix)-1], dn, WrapLDAPError(params.operation, l.config.Server, ctx.Err()))
	default:
	}

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       params.filter,
		Attributes:   params.attributes,
	})
	if err != nil {
		// If LDAP error indicates object not found, return appropriate error
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			l.logger.Debug(params.logPrefix+"not_found_by_dn",
				slog.String("operation", params.operation),
				slog.String("dn", dn),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("%s not found by DN %s: %w", params.logPrefix[:len(params.logPrefix)-1], dn, params.notFoundErr)
		}
		l.logger.Error(params.logPrefix+"search_by_dn_failed",
			slog.String("operation", params.operation),
			slog.String("dn", dn),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("%s search failed for DN %s: %w", params.logPrefix[:len(params.logPrefix)-1], dn, WrapLDAPError(params.operation, l.config.Server, err))
	}

	return r, nil
}
