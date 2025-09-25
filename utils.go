package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// checkContextCancellation checks if the context has been cancelled and logs the appropriate message
func (l *LDAP) checkContextCancellation(ctx context.Context, operation, identifier, stage string) error {
	select {
	case <-ctx.Done():
		maskedIdentifier := maskSensitiveData(identifier)
		l.logger.Debug("context_cancelled",
			slog.String("operation", operation),
			slog.String("identifier_masked", maskedIdentifier),
			slog.String("stage", stage),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("%s cancelled at %s for identifier %s: %w",
			operation, stage, identifier, WrapLDAPError(operation, l.config.Server, ctx.Err()))
	default:
		return nil
	}
}

// encodePasswordPair encodes both old and new passwords for Active Directory password change operations
func (l *LDAP) encodePasswordPair(oldCreds, newCreds *SecureCredential, username string) (oldEncoded, newEncoded string, err error) {
	maskedUsername := maskSensitiveData(username)

	// Get passwords from secure credentials
	_, oldPassword := oldCreds.GetCredentials()
	_, newPassword := newCreds.GetCredentials()

	// Encode old password
	oldEncoded, err = encodePassword(oldPassword)
	if err != nil {
		l.logger.Error("password_change_old_password_encoding_failed",
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to encode old password for user %s: %w", username, err)
	}

	// Encode new password
	newEncoded, err = encodePassword(newPassword)
	if err != nil {
		l.logger.Error("password_change_new_password_encoding_failed",
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to encode new password for user %s: %w", username, err)
	}

	return oldEncoded, newEncoded, nil
}

// parseObjectEnabled determines if an LDAP object is enabled based on userAccountControl attribute.
// This function parses the Active Directory userAccountControl attribute to determine if an account is enabled.
//
// In Active Directory, the userAccountControl attribute is a bitmask where the ADS_UF_ACCOUNTDISABLE flag (0x0002)
// indicates whether an account is disabled. If this bit is NOT set, the account is enabled.
//
// Parameters:
//   - userAccountControl: The userAccountControl attribute value as a string (decimal representation)
//
// Returns:
//   - bool: true if the account is enabled (ADS_UF_ACCOUNTDISABLE bit is not set), false if disabled
//   - error: Any error encountered during parsing (e.g., invalid string format)
//
// Common userAccountControl values:
//   - 512 (0x200): Normal account, enabled
//   - 514 (0x202): Normal account, disabled (512 + 2)
//   - 544 (0x220): Password not required, enabled
//   - 546 (0x222): Password not required, disabled (544 + 2)
//   - 66048 (0x10200): Normal account, password never expires, enabled
//   - 66050 (0x10202): Normal account, password never expires, disabled
func parseObjectEnabled(userAccountControl string) (bool, error) {
	if userAccountControl == "" {
		return false, fmt.Errorf("userAccountControl cannot be empty")
	}

	// Parse the userAccountControl value - accept both positive and negative numbers
	uac, err := strconv.ParseInt(userAccountControl, 10, 32)
	if err != nil {
		return false, fmt.Errorf("failed to parse userAccountControl value '%s': %w", userAccountControl, err)
	}

	// Check if the ADS_UF_ACCOUNTDISABLE bit (0x0002) is set
	// If it's set, the account is disabled; if not set, the account is enabled
	const ADS_UF_ACCOUNTDISABLE = 0x0002
	isDisabled := (uac & ADS_UF_ACCOUNTDISABLE) != 0

	return !isDisabled, nil
}

// convertAccountExpires converts a Go time.Time to Active Directory accountExpires format.
// Active Directory stores accountExpires as the number of 100-nanosecond intervals since January 1, 1601 UTC.
// A nil time represents "never expires" and returns the maximum possible value.
//
// Parameters:
//   - target: The time to convert (nil means never expires)
//
// Returns:
//   - string: The accountExpires value in Active Directory format
func convertAccountExpires(target *time.Time) string {
	// Constants defined in users.go
	const accountExpiresNever uint64 = 0x7FFFFFFFFFFFFFFF
	var accountExpiresBase = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

	if target == nil {
		// Account never expires
		return fmt.Sprintf("%d", accountExpiresNever)
	}

	// Calculate the difference from the base date (January 1, 1601)
	remaining := target.Sub(accountExpiresBase)

	// Convert to 100-nanosecond intervals (Active Directory format)
	// Go's Duration is in nanoseconds, so divide by 100
	intervals := remaining.Nanoseconds() / 100

	return fmt.Sprintf("%d", intervals)
}
