package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
)

var (
	utf16le = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	// ErrActiveDirectoryMustBeLDAPS is returned when attempting to change passwords on Active Directory
	// over an unencrypted connection. Password changes in AD require LDAPS (LDAP over SSL/TLS).
	ErrActiveDirectoryMustBeLDAPS = errors.New("ActiveDirectory servers must be connected to via LDAPS to change passwords")
)

// CheckPasswordForSAMAccountName validates a user's password by attempting to bind with their credentials.
// This method finds the user by their sAMAccountName and then attempts authentication.
//
// Parameters:
//   - sAMAccountName: The Security Account Manager account name (e.g., "jdoe" for john.doe@domain.com)
//   - password: The password to validate
//
// Returns:
//   - *User: The user object if authentication succeeds
//   - error: ErrUserNotFound if the user doesn't exist, or authentication error if credentials are invalid
//
// This is commonly used for login validation in Active Directory environments.
func (l *LDAP) CheckPasswordForSAMAccountName(sAMAccountName, password string) (*User, error) {
	return l.CheckPasswordForSAMAccountNameContext(context.Background(), sAMAccountName, password)
}

// CheckPasswordForSAMAccountNameContext validates a user's password by attempting to bind with their credentials.
// This method finds the user by their sAMAccountName and then attempts authentication.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - sAMAccountName: The Security Account Manager account name (e.g., "jdoe" for john.doe@domain.com)
//   - password: The password to validate
//
// Returns:
//   - *User: The user object if authentication succeeds
//   - error: ErrUserNotFound if the user doesn't exist, authentication error if credentials are invalid,
//     or context cancellation error
//
// This is commonly used for login validation in Active Directory environments.
func (l *LDAP) CheckPasswordForSAMAccountNameContext(ctx context.Context, sAMAccountName, password string) (*User, error) {
	// Check for context cancellation first
	if err := l.checkContextCancellation(ctx, "CheckPasswordForSAMAccountName", sAMAccountName, "start"); err != nil {
		return nil, ctx.Err()
	}

	start := time.Now()

	// Create secure credential for password handling
	creds, err := NewSecureCredentialSimple(sAMAccountName, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure credentials: %w", err)
	}
	defer func() {
		if err := creds.ZeroizeCredentials(); err != nil {
			l.logger.Warn("failed to zeroize credentials", slog.String("error", err.Error()))
		}
	}()

	// Mask sensitive data for logging
	maskedUsername := maskSensitiveData(sAMAccountName)

	// Extract client IP from context for security monitoring
	clientIP := extractClientIP(ctx)

	// Security monitoring: Check rate limiting before authentication attempt
	if l.rateLimiter != nil {
		if !l.rateLimiter.CheckLimit(sAMAccountName) {
			l.logger.Warn("authentication_rate_limited",
				slog.String("operation", "CheckPasswordForSAMAccountName"),
				slog.String("username_masked", maskedUsername),
				slog.String("client_ip_masked", maskSensitiveData(clientIP)),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("authentication blocked by rate limiting for user %s", sAMAccountName)
		}
	}

	l.logger.Debug("authentication_attempt_sam_account",
		slog.String("operation", "CheckPasswordForSAMAccountName"),
		slog.String("username_masked", maskedUsername),
		slog.String("client_ip_masked", maskSensitiveData(clientIP)))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, connectionError("SAM account", "authentication", err)
	}
	defer func() { _ = c.Close() }()

	// Check for context cancellation before user lookup
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_user_lookup",
			slog.String("username_masked", maskedUsername),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled for user %s: %w", sAMAccountName, WrapLDAPError("CheckPasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	// Timing attack mitigation: Always perform both user lookup and bind attempt
	// to ensure constant time behavior regardless of whether user exists
	user, userLookupErr := l.FindUserBySAMAccountNameContext(ctx, sAMAccountName)

	// Check for context cancellation before bind attempt
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_bind",
			slog.String("username_masked", maskedUsername),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled before bind for user %s: %w", sAMAccountName, WrapLDAPError("CheckPasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	_, credPassword := creds.GetCredentials()
	var bindErr error
	var userDN string

	if userLookupErr == nil {
		// User exists - perform real bind
		userDN = user.DN()
		bindErr = c.Bind(userDN, credPassword)
	} else {
		// User doesn't exist - perform dummy bind to maintain constant timing
		// Use a predictable dummy DN that won't exist to ensure bind fails
		dummyDN := fmt.Sprintf("CN=nonexistent-%s,CN=Users,%s", sAMAccountName, l.config.BaseDN)
		_ = c.Bind(dummyDN, credPassword) // Dummy bind for timing, ignore result
		// Override bind error with user lookup error for proper error reporting
		bindErr = userLookupErr
		userDN = dummyDN
	}

	err = bindErr
	if err != nil {
		// Security monitoring: Record authentication failure
		if l.rateLimiter != nil {
			l.rateLimiter.RecordFailure(sAMAccountName)
		}

		// Determine error type for logging
		errorType := "bind_failed"
		if userLookupErr != nil {
			errorType = "user_lookup_failed"
		}

		l.logger.Warn("authentication_failed",
			slog.String("operation", "CheckPasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("client_ip_masked", maskSensitiveData(clientIP)),
			slog.String("error_type", errorType),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))

		ldapErr := NewLDAPError("CheckPasswordForSAMAccountName", l.config.Server, err).
			WithDN(userDN).WithContext("samAccountName", sAMAccountName)

		// Return consistent error message regardless of whether user exists
		return nil, authenticationError("user", sAMAccountName, ldapErr)
	}

	// Security monitoring: Record authentication success
	if l.rateLimiter != nil {
		l.rateLimiter.RecordSuccess(sAMAccountName)
	}

	l.logger.Info("authentication_successful",
		slog.String("operation", "CheckPasswordForSAMAccountName"),
		slog.String("username_masked", maskedUsername),
		slog.String("client_ip_masked", maskSensitiveData(clientIP)),
		slog.Duration("duration", time.Since(start)))

	return user, nil
}

// CheckPasswordForDN validates a user's password by attempting to bind with their credentials.
// This method finds the user by their distinguished name and then attempts authentication.
//
// Parameters:
//   - dn: The distinguished name of the user (e.g., "CN=John Doe,CN=Users,DC=example,DC=com")
//   - password: The password to validate
//
// Returns:
//   - *User: The user object if authentication succeeds
//   - error: ErrUserNotFound if the user doesn't exist, or authentication error if credentials are invalid
//
// This method is useful when you already have the user's DN and want to validate their password.
func (l *LDAP) CheckPasswordForDN(dn, password string) (*User, error) {
	return l.CheckPasswordForDNContext(context.Background(), dn, password)
}

// CheckPasswordForDNContext validates a user's password by attempting to bind with their credentials.
// This method finds the user by their distinguished name and then attempts authentication.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the user (e.g., "CN=John Doe,CN=Users,DC=example,DC=com")
//   - password: The password to validate
//
// Returns:
//   - *User: The user object if authentication succeeds
//   - error: ErrUserNotFound if the user doesn't exist, authentication error if credentials are invalid,
//     or context cancellation error
//
// This method is useful when you already have the user's DN and want to validate their password.
func (l *LDAP) CheckPasswordForDNContext(ctx context.Context, dn, password string) (*User, error) {
	start := time.Now()

	// Create secure credential for password handling
	creds, err := NewSecureCredentialSimple("", password)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure credentials: %w", err)
	}
	defer func() {
		if err := creds.ZeroizeCredentials(); err != nil {
			l.logger.Warn("failed to zeroize credentials", slog.String("error", err.Error()))
		}
	}()

	// Mask sensitive data for logging (DN contains sensitive info)
	maskedDN := maskSensitiveData(dn)

	// Extract client IP from context for security monitoring
	clientIP := extractClientIP(ctx)

	// Security monitoring: Check rate limiting before authentication attempt
	if l.rateLimiter != nil {
		if !l.rateLimiter.CheckLimit(dn) {
			l.logger.Warn("authentication_rate_limited",
				slog.String("operation", "CheckPasswordForDN"),
				slog.String("dn_masked", maskedDN),
				slog.String("client_ip_masked", maskSensitiveData(clientIP)),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("authentication blocked by rate limiting for DN %s", dn)
		}
	}

	l.logger.Debug("authentication_attempt_dn",
		slog.String("operation", "CheckPasswordForDN"),
		slog.String("dn_masked", maskedDN),
		slog.String("client_ip_masked", maskSensitiveData(clientIP)))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, connectionError("DN", "authentication", err)
	}
	defer func() { _ = c.Close() }()

	// Check for context cancellation before user lookup
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_user_lookup",
			slog.String("dn_masked", maskedDN),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled for DN %s: %w", dn, WrapLDAPError("CheckPasswordForDN", l.config.Server, ctx.Err()))
	default:
	}

	user, err := l.FindUserByDNContext(ctx, dn)
	if err != nil {
		l.logger.Error("authentication_user_lookup_failed",
			slog.String("operation", "CheckPasswordForDN"),
			slog.String("dn_masked", maskedDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to find user by DN %s: %w", dn, err)
	}

	// Check for context cancellation before bind attempt
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_bind",
			slog.String("dn_masked", maskedDN),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled before bind for DN %s: %w", dn, WrapLDAPError("CheckPasswordForDN", l.config.Server, ctx.Err()))
	default:
	}

	_, credPassword := creds.GetCredentials()
	err = c.Bind(user.DN(), credPassword)
	if err != nil {
		// Security monitoring: Record authentication failure
		if l.rateLimiter != nil {
			l.rateLimiter.RecordFailure(dn)
		}

		l.logger.Warn("authentication_failed",
			slog.String("operation", "CheckPasswordForDN"),
			slog.String("dn_masked", maskedDN),
			slog.String("client_ip_masked", maskSensitiveData(clientIP)),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		ldapErr := NewLDAPError("CheckPasswordForDN", l.config.Server, err).WithDN(dn)
		return nil, authenticationError("DN", dn, ldapErr)
	}

	// Security monitoring: Record authentication success
	if l.rateLimiter != nil {
		l.rateLimiter.RecordSuccess(dn)
	}

	l.logger.Info("authentication_successful",
		slog.String("operation", "CheckPasswordForDN"),
		slog.String("dn_masked", maskedDN),
		slog.String("client_ip_masked", maskSensitiveData(clientIP)),
		slog.Duration("duration", time.Since(start)))

	return user, nil
}

// encodePassword encodes a password for Active Directory according to Microsoft specifications.
// Active Directory requires passwords to be UTF-16LE encoded and enclosed in quotes.
//
// Parameters:
//   - password: The plain text password to encode
//
// Returns:
//   - string: The UTF-16LE encoded password suitable for Active Directory operations
//   - error: Any encoding error
//
// This function is used internally for password change operations in Active Directory.
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2
func encodePassword(password string) (string, error) {
	encoded, err := utf16le.NewEncoder().String("\"" + password + "\"")
	if err != nil {
		return "", err
	}

	return encoded, nil
}

// ChangePasswordForSAMAccountName changes a user's password in Active Directory.
// This method requires the current password for authentication and changes it to the new password.
//
// Parameters:
//   - sAMAccountName: The Security Account Manager account name of the user
//   - oldPassword: The current password (required for authentication)
//   - newPassword: The new password to set
//
// Returns:
//   - error: ErrActiveDirectoryMustBeLDAPS if trying to change AD passwords over unencrypted connection,
//     ErrUserNotFound if user doesn't exist, authentication error if old password is wrong,
//     or any other LDAP operation error
//
// Requirements:
//   - For Active Directory servers, LDAPS (SSL/TLS) connection is mandatory
//   - User must provide their current password for verification
//   - New password must meet the domain's password policy requirements
//
// The password change uses the Microsoft-specific unicodePwd attribute with proper UTF-16LE encoding.
// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2
func (l *LDAP) ChangePasswordForSAMAccountName(sAMAccountName, oldPassword, newPassword string) (err error) {
	return l.ChangePasswordForSAMAccountNameContext(context.Background(), sAMAccountName, oldPassword, newPassword)
}

// ChangePasswordForSAMAccountNameContext changes a user's password in Active Directory with context support.
// This method requires the current password for authentication and changes it to the new password.
//
// Parameters:
//   - ctx: Context for controlling the operation timeout and cancellation
//   - sAMAccountName: The Security Account Manager account name of the user
//   - oldPassword: The current password (required for authentication)
//   - newPassword: The new password to set
//
// Returns:
//   - error: ErrActiveDirectoryMustBeLDAPS if trying to change AD passwords over unencrypted connection,
//     ErrUserNotFound if user doesn't exist, authentication error if old password is wrong,
//     context cancellation error, or any other LDAP operation error
//
// Requirements:
//   - For Active Directory servers, LDAPS (SSL/TLS) connection is mandatory
//   - User must provide their current password for verification
//   - New password must meet the domain's password policy requirements
//
// The password change uses the Microsoft-specific unicodePwd attribute with proper UTF-16LE encoding.
// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2
func (l *LDAP) ChangePasswordForSAMAccountNameContext(ctx context.Context, sAMAccountName, oldPassword, newPassword string) (err error) {
	start := time.Now()

	// Create secure credentials for password handling
	oldCreds, err := NewSecureCredentialSimple("", oldPassword)
	if err != nil {
		return fmt.Errorf("failed to create secure credentials for old password: %w", err)
	}
	defer func() {
		if err := oldCreds.ZeroizeCredentials(); err != nil {
			l.logger.Warn("failed to zeroize old credentials", slog.String("error", err.Error()))
		}
	}()

	newCreds, err := NewSecureCredentialSimple("", newPassword)
	if err != nil {
		return fmt.Errorf("failed to create secure credentials for new password: %w", err)
	}
	defer func() {
		if err := newCreds.ZeroizeCredentials(); err != nil {
			l.logger.Warn("failed to zeroize new credentials", slog.String("error", err.Error()))
		}
	}()

	// Mask sensitive data for logging
	maskedUsername := maskSensitiveData(sAMAccountName)

	l.logger.Info("password_change_attempt",
		slog.String("operation", "ChangePasswordForSAMAccountName"),
		slog.String("username_masked", maskedUsername))

	// Security check: Active Directory requires LDAPS for password operations
	if l.config.IsActiveDirectory && !strings.HasPrefix(l.config.Server, "ldaps://") {
		l.logger.Error("password_change_requires_ldaps",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("server", l.config.Server))
		return ErrActiveDirectoryMustBeLDAPS
	}

	// Check for context cancellation before starting
	select {
	case <-ctx.Done():
		l.logger.Debug("password_change_cancelled_before_start",
			slog.String("username_masked", maskedUsername),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("password change cancelled for user %s: %w", sAMAccountName, WrapLDAPError("ChangePasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	// Find the user first
	user, err := l.FindUserBySAMAccountNameContext(ctx, sAMAccountName)
	if err != nil {
		l.logger.Error("password_change_user_not_found",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return fmt.Errorf("failed to find user %s for password change: %w", sAMAccountName, err)
	}

	// Encode both passwords for Active Directory
	oldEncoded, newEncoded, err := l.encodePasswordPair(oldCreds, newCreds, sAMAccountName)
	if err != nil {
		l.logger.Error("password_change_encoding_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return fmt.Errorf("failed to encode passwords for user %s: %w", sAMAccountName, err)
	}

	// Check for context cancellation before LDAP operations
	select {
	case <-ctx.Done():
		l.logger.Debug("password_change_cancelled_before_modify",
			slog.String("username_masked", maskedUsername),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("password change cancelled before modify for user %s: %w", sAMAccountName, WrapLDAPError("ChangePasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return connectionError("SAM account", "password change", err)
	}
	defer func() { _ = c.Close() }()

	// Create modify request for password change
	userDN := user.DN()
	modifyRequest := ldap.NewModifyRequest(userDN, nil)

	// Delete old password and add new password (Microsoft's recommended approach)
	modifyRequest.Delete("unicodePwd", []string{oldEncoded})
	modifyRequest.Add("unicodePwd", []string{newEncoded})

	// Perform the password change
	err = c.Modify(modifyRequest)
	if err != nil {
		l.logger.Error("password_change_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("dn", userDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))

		ldapErr := NewLDAPError("ChangePasswordForSAMAccountName", l.config.Server, err).
			WithDN(userDN).WithContext("samAccountName", sAMAccountName)

		return fmt.Errorf("failed to change password for user %s: %w", sAMAccountName, ldapErr)
	}

	l.logger.Info("password_change_successful",
		slog.String("operation", "ChangePasswordForSAMAccountName"),
		slog.String("username_masked", maskedUsername),
		slog.String("dn", userDN),
		slog.Duration("duration", time.Since(start)))

	return nil
}
