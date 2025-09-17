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
	l.logger.Debug("authentication_attempt_sam_account",
		slog.String("operation", "CheckPasswordForSAMAccountName"),
		slog.String("username", sAMAccountName))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection for SAM account authentication: %w", err)
	}
	defer c.Close()

	// Check for context cancellation before user lookup
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_user_lookup",
			slog.String("username", sAMAccountName),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled for user %s: %w", sAMAccountName, WrapLDAPError("CheckPasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	user, err := l.FindUserBySAMAccountNameContext(ctx, sAMAccountName)
	if err != nil {
		l.logger.Error("authentication_user_lookup_failed",
			slog.String("operation", "CheckPasswordForSAMAccountName"),
			slog.String("username", sAMAccountName),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to find user by SAM account name %s: %w", sAMAccountName, err)
	}

	// Check for context cancellation before bind attempt
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_bind",
			slog.String("username", sAMAccountName),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled before bind for user %s: %w", sAMAccountName, WrapLDAPError("CheckPasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	err = c.Bind(user.DN(), password)
	if err != nil {
		l.logger.Warn("authentication_failed",
			slog.String("operation", "CheckPasswordForSAMAccountName"),
			slog.String("username", sAMAccountName),
			slog.String("dn", user.DN()),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		ldapErr := NewLDAPError("CheckPasswordForSAMAccountName", l.config.Server, err).
			WithDN(user.DN()).WithContext("samAccountName", sAMAccountName)
		return nil, fmt.Errorf("authentication failed for user %s (DN: %s): %w", sAMAccountName, user.DN(), ldapErr)
	}

	l.logger.Info("authentication_successful",
		slog.String("operation", "CheckPasswordForSAMAccountName"),
		slog.String("username", sAMAccountName),
		slog.String("dn", user.DN()),
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
	l.logger.Debug("authentication_attempt_dn",
		slog.String("operation", "CheckPasswordForDN"),
		slog.String("dn", dn))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection for DN authentication: %w", err)
	}
	defer c.Close()

	// Check for context cancellation before user lookup
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_user_lookup",
			slog.String("dn", dn),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled for DN %s: %w", dn, WrapLDAPError("CheckPasswordForDN", l.config.Server, ctx.Err()))
	default:
	}

	user, err := l.FindUserByDNContext(ctx, dn)
	if err != nil {
		l.logger.Error("authentication_user_lookup_failed",
			slog.String("operation", "CheckPasswordForDN"),
			slog.String("dn", dn),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to find user by DN %s: %w", dn, err)
	}

	// Check for context cancellation before bind attempt
	select {
	case <-ctx.Done():
		l.logger.Debug("authentication_cancelled_before_bind",
			slog.String("dn", dn),
			slog.String("error", ctx.Err().Error()))
		return nil, fmt.Errorf("authentication cancelled before bind for DN %s: %w", dn, WrapLDAPError("CheckPasswordForDN", l.config.Server, ctx.Err()))
	default:
	}

	err = c.Bind(user.DN(), password)
	if err != nil {
		l.logger.Warn("authentication_failed",
			slog.String("operation", "CheckPasswordForDN"),
			slog.String("dn", dn),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		ldapErr := NewLDAPError("CheckPasswordForDN", l.config.Server, err).WithDN(dn)
		return nil, fmt.Errorf("authentication failed for DN %s: %w", dn, ldapErr)
	}

	l.logger.Info("authentication_successful",
		slog.String("operation", "CheckPasswordForDN"),
		slog.String("dn", dn),
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
	l.logger.Info("password_change_attempt",
		slog.String("operation", "ChangePasswordForSAMAccountName"),
		slog.String("username", sAMAccountName))

	c, err := l.GetConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection for password change: %w", err)
	}
	defer c.Close()

	// Check for context cancellation before user lookup
	select {
	case <-ctx.Done():
		l.logger.Debug("password_change_cancelled_before_user_lookup",
			slog.String("username", sAMAccountName),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("password change cancelled for user %s: %w", sAMAccountName, WrapLDAPError("ChangePasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	user, err := l.FindUserBySAMAccountNameContext(ctx, sAMAccountName)
	if err != nil {
		l.logger.Error("password_change_user_lookup_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username", sAMAccountName),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return fmt.Errorf("failed to find user %s for password change: %w", sAMAccountName, err)
	}

	if l.config.IsActiveDirectory && !strings.HasPrefix(l.config.Server, "ldaps://") {
		l.logger.Error("password_change_requires_ldaps",
			slog.String("username", sAMAccountName),
			slog.String("server", l.config.Server),
			slog.String("error", ErrActiveDirectoryMustBeLDAPS.Error()))
		return fmt.Errorf("password change for user %s on Active Directory server %s: %w",
			sAMAccountName, l.config.Server, ErrActiveDirectoryMustBeLDAPS)
	}

	// Check for context cancellation before bind
	select {
	case <-ctx.Done():
		l.logger.Debug("password_change_cancelled_before_bind",
			slog.String("username", sAMAccountName),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("password change cancelled before bind for user %s: %w", sAMAccountName, WrapLDAPError("ChangePasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	if err := c.Bind(user.DN(), oldPassword); err != nil {
		l.logger.Warn("password_change_old_password_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username", sAMAccountName),
			slog.String("dn", user.DN()),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		ldapErr := NewLDAPError("ChangePasswordForSAMAccountName", l.config.Server, err).
			WithDN(user.DN()).WithContext("samAccountName", sAMAccountName)
		return fmt.Errorf("old password verification failed for user %s (DN: %s): %w", sAMAccountName, user.DN(), ldapErr)
	}

	// Check for context cancellation before password encoding
	select {
	case <-ctx.Done():
		l.logger.Debug("password_change_cancelled_before_encoding",
			slog.String("username", sAMAccountName),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("password change cancelled before encoding for user %s: %w", sAMAccountName, WrapLDAPError("ChangePasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	oldEncoded, err := encodePassword(oldPassword)
	if err != nil {
		l.logger.Error("password_change_old_password_encoding_failed",
			slog.String("username", sAMAccountName),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to encode old password for user %s: %w", sAMAccountName, err)
	}

	newEncoded, err := encodePassword(newPassword)
	if err != nil {
		l.logger.Error("password_change_new_password_encoding_failed",
			slog.String("username", sAMAccountName),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to encode new password for user %s: %w", sAMAccountName, err)
	}

	// Check for context cancellation before modify operation
	select {
	case <-ctx.Done():
		l.logger.Debug("password_change_cancelled_before_modify",
			slog.String("username", sAMAccountName),
			slog.String("error", ctx.Err().Error()))
		return fmt.Errorf("password change cancelled before modify for user %s: %w", sAMAccountName, WrapLDAPError("ChangePasswordForSAMAccountName", l.config.Server, ctx.Err()))
	default:
	}

	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2?redirectedfrom=MSDN
	// If the Modify request contains a delete operation containing a value Vdel for unicodePwd followed
	// by an add operation containing a value Vadd for unicodePwd, the server considers the request
	// to be a request to change the password. [...]. Vdel is the old password, while Vadd is the new password.
	modifyRequest := ldap.NewModifyRequest(user.DN(), nil)
	modifyRequest.Add("unicodePwd", []string{newEncoded})
	modifyRequest.Delete("unicodePwd", []string{oldEncoded})

	if err := c.Modify(modifyRequest); err != nil {
		l.logger.Error("password_change_failed",
			slog.String("operation", "ChangePasswordForSAMAccountName"),
			slog.String("username", sAMAccountName),
			slog.String("dn", user.DN()),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		ldapErr := NewLDAPError("ChangePasswordForSAMAccountName", l.config.Server, err).
			WithDN(user.DN()).WithContext("samAccountName", sAMAccountName)
		return fmt.Errorf("password modification failed for user %s (DN: %s): %w", sAMAccountName, user.DN(), ldapErr)
	}

	l.logger.Info("password_change_successful",
		slog.String("operation", "ChangePasswordForSAMAccountName"),
		slog.String("username", sAMAccountName),
		slog.String("dn", user.DN()),
		slog.Duration("duration", time.Since(start)))

	return nil
}
