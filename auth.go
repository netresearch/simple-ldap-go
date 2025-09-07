package ldap

import (
	"errors"
	"strings"

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
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	user, err := l.FindUserBySAMAccountName(sAMAccountName)
	if err != nil {
		return nil, err
	}

	err = c.Bind(user.DN(), password)
	if err != nil {
		return nil, err
	}

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
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	user, err := l.FindUserByDN(dn)
	if err != nil {
		return nil, err
	}

	err = c.Bind(user.DN(), password)
	if err != nil {
		return nil, err
	}

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
	c, err := l.GetConnection()
	if err != nil {
		return err
	}
	defer c.Close()

	user, err := l.FindUserBySAMAccountName(sAMAccountName)
	if err != nil {
		return err
	}

	if l.config.IsActiveDirectory && !strings.HasPrefix(l.config.Server, "ldaps://") {
		return ErrActiveDirectoryMustBeLDAPS
	}

	if err := c.Bind(user.DN(), oldPassword); err != nil {
		return err
	}

	oldEncoded, err := encodePassword(oldPassword)
	if err != nil {
		return err
	}

	newEncoded, err := encodePassword(newPassword)
	if err != nil {
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
		return err
	}

	return nil
}
