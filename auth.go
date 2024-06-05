package ldap

import (
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
)

var (
	utf16le                       = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	ErrActiveDirectoryMustBeLDAPS = errors.New("ActiveDirectory servers must be connected to via LDAPS to change passwords")
)

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

func encodePassword(password string) (string, error) {
	encoded, err := utf16le.NewEncoder().String("\"" + password + "\"")
	if err != nil {
		return "", err
	}

	return encoded, nil
}

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
