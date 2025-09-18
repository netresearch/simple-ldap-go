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
	start := time.Now()

	// Create secure credential for password handling
	creds := NewSecureCredential("", password, 5*time.Minute)
	defer creds.Zeroize() // Ensure password is securely zeroed

	// Mask sensitive data for logging
	maskedUsername := maskSensitiveData(sAMAccountName)

	// Extract client IP from context for security monitoring
	clientIP := extractClientIP(ctx)

	// Security monitoring: Check rate limiting before authentication attempt
	if l.rateLimiter != nil {
		if err := l.rateLimiter.CheckAttempt(sAMAccountName, clientIP); err != nil {
			l.logger.Warn("authentication_rate_limited",
				slog.String("operation", "CheckPasswordForSAMAccountName"),
				slog.String("username_masked", maskedUsername),
				slog.String("client_ip_masked", maskSensitiveData(clientIP)),
				slog.String("reason", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("authentication blocked by rate limiting for user %s: %w", sAMAccountName, err)
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
		bindErr = c.Bind(dummyDN, credPassword)
		// Override bind error with user lookup error for proper error reporting
		bindErr = userLookupErr
		userDN = dummyDN
	}

	err = bindErr
	if err != nil {
		// Security monitoring: Record authentication failure
		if l.rateLimiter != nil {
			l.rateLimiter.RecordFailure(sAMAccountName, clientIP)
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
	creds := NewSecureCredential("", password, 5*time.Minute)
	defer creds.Zeroize() // Ensure password is securely zeroed

	// Mask sensitive data for logging (DN contains sensitive info)
	maskedDN := maskSensitiveData(dn)

	// Extract client IP from context for security monitoring
	clientIP := extractClientIP(ctx)

	// Security monitoring: Check rate limiting before authentication attempt
	if l.rateLimiter != nil {
		if err := l.rateLimiter.CheckAttempt(dn, clientIP); err != nil {
			l.logger.Warn("authentication_rate_limited",
				slog.String("operation", "CheckPasswordForDN"),
				slog.String("dn_masked", maskedDN),
				slog.String("client_ip_masked", maskSensitiveData(clientIP)),
				slog.String("reason", err.Error()),
				slog.Duration("duration", time.Since(start)))
			return nil, fmt.Errorf("authentication blocked by rate limiting for DN %s: %w", dn, err)
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
			l.rateLimiter.RecordFailure(dn, clientIP)
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
	oldCreds := NewSecureCredential("", oldPassword, 5*time.Minute)
	defer oldCreds.Zeroize() // Ensure old password is securely zeroed
	newCreds := NewSecureCredential("", newPassword, 5*time.Minute)
	defer newCreds.Zeroize() // Ensure new password is securely zeroed

	// Mask sensitive data for logging
	maskedUsername := maskSensitiveData(sAMAccountName)

	l.logger.Info("password_change_attempt",
		slog.String("operation", "ChangePasswordForSAMAccountName"),
		slog.String("username_masked", maskedUsername))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return connectionError("password", "change", err)
	}
	defer func() { _ = c.Close() }()

	// Check for context cancellation before user lookup
	if err := l.checkContextCancellation(ctx, "password_change", sAMAccountName, "before_user_lookup"); err != nil {
		return err
	}

	user, err := l.FindUserBySAMAccountNameContext(ctx, sAMAccountName)
	if err != nil {
		l.logger.Error("password_change_user_lookup_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return fmt.Errorf("failed to find user %s for password change: %w", sAMAccountName, err)
	}

	if l.config.IsActiveDirectory && !strings.HasPrefix(l.config.Server, "ldaps://") {
		l.logger.Error("password_change_requires_ldaps",
			slog.String("username_masked", maskedUsername),
			slog.String("server_masked", maskSensitiveData(l.config.Server)),
			slog.String("error", ErrActiveDirectoryMustBeLDAPS.Error()))
		return fmt.Errorf("password change for user %s on Active Directory server %s: %w",
			sAMAccountName, l.config.Server, ErrActiveDirectoryMustBeLDAPS)
	}

	// Check for context cancellation before bind
	if err := l.checkContextCancellation(ctx, "password_change", sAMAccountName, "before_bind"); err != nil {
		return err
	}

	_, oldCredPassword := oldCreds.GetCredentials()
	if err := c.Bind(user.DN(), oldCredPassword); err != nil {
		// Mask sensitive data for logging
		maskedDN := maskSensitiveData(user.DN())
		l.logger.Warn("password_change_old_password_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("dn_masked", maskedDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		ldapErr := NewLDAPError("ChangePasswordForSAMAccountName", l.config.Server, err).
			WithDN(user.DN()).WithContext("samAccountName", sAMAccountName)
		return fmt.Errorf("old password verification failed for user %s (DN: %s): %w", sAMAccountName, user.DN(), ldapErr)
	}

	// Check for context cancellation before password encoding
	if err := l.checkContextCancellation(ctx, "password_change", sAMAccountName, "before_encoding"); err != nil {
		return err
	}

	// Encode both passwords for Active Directory operation
	oldEncoded, newEncoded, err := l.encodePasswordPair(oldCreds, newCreds, sAMAccountName)
	if err != nil {
		return err
	}

	// Check for context cancellation before modify operation
	if err := l.checkContextCancellation(ctx, "password_change", sAMAccountName, "before_modify"); err != nil {
		return err
	}

	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2?redirectedfrom=MSDN
	// If the Modify request contains a delete operation containing a value Vdel for unicodePwd followed
	// by an add operation containing a value Vadd for unicodePwd, the server considers the request
	// to be a request to change the password. [...]. Vdel is the old password, while Vadd is the new password.
	modifyRequest := ldap.NewModifyRequest(user.DN(), nil)
	modifyRequest.Add("unicodePwd", []string{newEncoded})
	modifyRequest.Delete("unicodePwd", []string{oldEncoded})

	if err := c.Modify(modifyRequest); err != nil {
		// Mask sensitive data for logging
		maskedDN := maskSensitiveData(user.DN())
		l.logger.Error("password_change_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username_masked", maskedUsername),
			slog.String("dn_masked", maskedDN),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		ldapErr := NewLDAPError("ChangePasswordForSAMAccountName", l.config.Server, err).
			WithDN(user.DN()).WithContext("samAccountName", sAMAccountName)
		return fmt.Errorf("password modification failed for user %s (DN: %s): %w", sAMAccountName, user.DN(), ldapErr)
	}

	// Mask sensitive data for logging
	maskedDN := maskSensitiveData(user.DN())
	l.logger.Info("password_change_successful",
		slog.String("operation", "ChangePasswordForSAMAccountName"),
		slog.String("username_masked", maskedUsername),
		slog.String("dn_masked", maskedDN),
		slog.Duration("duration", time.Since(start)))

	return nil
}

// Error handling helper methods for authentication operations

// executeWithRetry executes an operation with exponential backoff retry logic
// This provides resilient execution for transient failures
func (l *LDAP) executeWithRetry(ctx context.Context, operation string, fn func() error) error {
	maxRetries := 3
	baseDelay := 100 * time.Millisecond
	maxDelay := 2 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		// Don't retry on context cancellation or authentication failures
		if IsContextError(err) || IsAuthenticationError(err) {
			return err
		}

		// Don't retry if not retryable
		if !IsRetryable(err) {
			return err
		}

		// Last attempt, return the error
		if attempt == maxRetries {
			return fmt.Errorf("%s failed after %d attempts: %w", operation, maxRetries+1, err)
		}

		// Calculate delay with exponential backoff and jitter
		delay := time.Duration(attempt) * baseDelay
		if delay > maxDelay {
			delay = maxDelay
		}

		// Add jitter (±25%)
		jitter := time.Duration(float64(delay) * 0.25 * (2.0*float64(time.Now().UnixNano()%1000)/1000.0 - 1.0))
		delay += jitter

		l.logger.Debug("operation_retry",
			slog.String("operation", operation),
			slog.Int("attempt", attempt+1),
			slog.Int("max_retries", maxRetries+1),
			slog.Duration("delay", delay),
			slog.String("error", err.Error()))

		// Wait with context cancellation support
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%s cancelled during retry: %w", operation, ctx.Err())
		case <-timer.C:
			// Continue to next attempt
		}
	}

	return fmt.Errorf("%s exhausted all retry attempts", operation)
}
