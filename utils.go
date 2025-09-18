package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// parseObjectEnabled determines if an LDAP object is enabled based on userAccountControl attribute.
// This function checks the ACCOUNTDISABLE flag (0x2) in the userAccountControl bitmask.
//
// Parameters:
//   - userAccountControl: String representation of the userAccountControl attribute value
//
// Returns:
//   - bool: true if the account is enabled (ACCOUNTDISABLE flag is not set), false if disabled
//   - error: Any error parsing the userAccountControl value
//
// Reference: https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
func parseObjectEnabled(userAccountControl string) (bool, error) {
	raw, err := strconv.ParseInt(userAccountControl, 10, 32)
	if err != nil {
		return false, err
	}

	// https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
	// 2 (0x2) - ACCOUNTDISABLE
	// The user account is disabled.
	if raw&2 != 0 {
		return false, nil
	}

	return true, nil
}

// convertAccountExpires converts a Go time.Time to Active Directory accountExpires format.
// Active Directory stores account expiration as the number of 100-nanosecond intervals
// since January 1, 1601 UTC (Windows FILETIME format).
//
// Parameters:
//   - target: The expiration time, or nil for accounts that never expire
//
// Returns:
//   - string: The accountExpires value formatted for Active Directory
//
// Special values:
//   - nil target returns 0x7FFFFFFFFFFFFFFF (account never expires)
//   - Otherwise returns the calculated 100-nanosecond intervals since 1601-01-01
//
// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/acdfe32c-ce53-4073-b9b4-40d1130038dc
func convertAccountExpires(target *time.Time) string {
	if target == nil {
		return fmt.Sprintf("%d", accountExpiresNever)
	}

	remaining := target.Sub(accountExpiresBase)

	/*
	   This value represents the number of 100-nanosecond intervals since January 1, 1601 (UTC).
	   A value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates that the account never expires.
	*/
	ns := remaining.Nanoseconds() / 100

	return fmt.Sprintf("%d", ns)
}

// checkContextCancellation checks if the context is cancelled and returns an appropriate error.
// This reduces repetitive context cancellation checking patterns across the codebase.
func (l *LDAP) checkContextCancellation(ctx context.Context, operation, identifier, stage string) error {
	select {
	case <-ctx.Done():
		maskedIdentifier := maskSensitiveData(identifier)
		l.logger.Debug(fmt.Sprintf("%s_cancelled_%s", operation, stage),
			slog.String("identifier_masked", maskedIdentifier),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("%s cancelled %s for identifier %s: %w", operation, stage, identifier,
			WrapLDAPError(operation, l.config.Server, ctx.Err()))
	default:
		return nil
	}
}

// encodePasswordPair encodes both old and new passwords for Active Directory operations.
// Returns the encoded passwords or an error if encoding fails.
func (l *LDAP) encodePasswordPair(oldCreds, newCreds *SecureCredential, username string) (oldEncoded, newEncoded string, err error) {
	maskedUsername := maskSensitiveData(username)

	_, oldPassword := oldCreds.GetCredentials()
	oldEncoded, err = encodePassword(oldPassword)
	if err != nil {
		l.logger.Error("password_change_old_password_encoding_failed",
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to encode old password for user %s: %w", username, err)
	}

	_, newPassword := newCreds.GetCredentials()
	newEncoded, err = encodePassword(newPassword)
	if err != nil {
		l.logger.Error("password_change_new_password_encoding_failed",
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to encode new password for user %s: %w", username, err)
	}

	return oldEncoded, newEncoded, nil
}

// maskSensitiveData masks sensitive information for logging while preserving
// some identifying information for debugging purposes
func maskSensitiveData(data string) string {
	if data == "" {
		return ""
	}

	// For usernames, DNs, servers, show first and last character with asterisks in between
	if len(data) <= 2 {
		return "**"
	}

	// Keep first and last character, mask the middle
	masked := string(data[0])
	for i := 1; i < len(data)-1; i++ {
		masked += "*"
	}
	masked += string(data[len(data)-1])

	return masked
}

// extractClientIP attempts to extract the client IP address from the context.
// This is used for security monitoring and rate limiting based on IP patterns.
// Returns an empty string if no IP information is available in the context.
func extractClientIP(ctx context.Context) string {
	// Try to get IP from common context keys used by web frameworks
	if ip := getStringFromContext(ctx, "client_ip"); ip != "" {
		return ip
	}
	if ip := getStringFromContext(ctx, "remote_addr"); ip != "" {
		return ip
	}
	if ip := getStringFromContext(ctx, "x-forwarded-for"); ip != "" {
		return ip
	}
	if ip := getStringFromContext(ctx, "x-real-ip"); ip != "" {
		return ip
	}

	// Return empty string if no IP found - rate limiter will handle this gracefully
	return ""
}

// getStringFromContext safely extracts a string value from context
func getStringFromContext(ctx context.Context, key string) string {
	if value := ctx.Value(key); value != nil {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}
