package ldap

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")
	ErrMailDuplicated           = errors.New("mail is not unique")

	accountExpiresBase         = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	accountExpiresNever uint64 = 0x7FFFFFFFFFFFFFFF

	userFields = []string{"memberOf", "cn", "sAMAccountName", "mail", "userAccountControl", "description"}
)

type User struct {
	Object
	Enabled        bool
	SAMAccountName string
	Description    string
	Mail           *string
	// Groups is a list of CNs
	Groups []string
}

func userFromEntry(entry *ldap.Entry) (*User, error) {
	enabled, err := parseObjectEnabled(entry.GetAttributeValue("userAccountControl"))
	if err != nil {
		return nil, err
	}

	var mail *string
	if mails := entry.GetAttributeValues("mail"); len(mails) > 0 {
		mail = &mails[0]
	}

	return &User{
		Object:         objectFromEntry(entry),
		Enabled:        enabled,
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		Description:    entry.GetAttributeValue("description"),
		Mail:           mail,
		Groups:         entry.GetAttributeValues("memberOf"),
	}, nil
}

func (l *LDAP) FindUserByDN(dn string) (user *User, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=user)",
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "userAccountControl", "description"},
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrUserNotFound
	}

	if len(r.Entries) > 1 {
		return nil, ErrDNDuplicated
	}

	if user, err = userFromEntry(r.Entries[0]); err != nil {
		return nil, err
	}

	return
}

func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (user *User, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(sAMAccountName)),
		Attributes:   userFields,
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrUserNotFound
	}
	if len(r.Entries) > 1 {
		return nil, ErrSAMAccountNameDuplicated
	}

	if user, err = userFromEntry(r.Entries[0]); err != nil {
		return nil, err
	}

	return
}

func (l *LDAP) FindUserByMail(mail string) (user *User, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       fmt.Sprintf("(&(objectClass=user)(mail=%s))", ldap.EscapeFilter(mail)),
		Attributes:   userFields,
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrUserNotFound
	}
	if len(r.Entries) > 1 {
		return nil, ErrMailDuplicated
	}

	if user, err = userFromEntry(r.Entries[0]); err != nil {
		return nil, err
	}

	return
}

func (l *LDAP) FindUsers() (users []User, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=user)",
		Attributes:   userFields,
	})
	if err != nil {
		return nil, err
	}

	for _, entry := range r.Entries {
		user, err := userFromEntry(entry)
		if err != nil {
			continue
		}

		users = append(users, *user)
	}

	return
}

func (l *LDAP) AddUserToGroup(dn, groupDN string) error {
	c, err := l.GetConnection()
	if err != nil {
		return err
	}
	defer c.Close()

	req := ldap.NewModifyRequest(groupDN, nil)
	req.Add("member", []string{dn})

	return c.Modify(req)
}

func (l *LDAP) RemoveUserFromGroup(dn, groupDN string) error {
	c, err := l.GetConnection()
	if err != nil {
		return err
	}
	defer c.Close()

	req := ldap.NewModifyRequest(groupDN, nil)
	req.Delete("member", []string{dn})

	return c.Modify(req)
}

type FullUser struct {
	CN             string
	SAMAccountName *string
	FirstName      string
	LastName       string
	DisplayName    *string
	Description    *string
	Email          *string
	ObjectClasses  []string
	// AccountExpires represents the expiration date of the user's account.
	// When set to nil, the account never expires.
	AccountExpires     *time.Time
	UserAccountControl UAC
	Path               *string
}

func (l *LDAP) CreateUser(user FullUser, password string) (string, error) {
	if user.ObjectClasses == nil {
		user.ObjectClasses = []string{"top", "person", "organizationalPerson", "user"}
	}

	if user.DisplayName == nil {
		user.DisplayName = &user.CN
	}

	c, err := l.GetConnection()
	if err != nil {
		return "", err
	}
	defer c.Close()

	baseDN := ""
	if user.Path != nil {
		baseDN = *user.Path + ","
	}
	baseDN += l.config.BaseDN

	dn := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(user.CN), baseDN)

	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", user.ObjectClasses)
	req.Attribute("cn", []string{user.CN})
	req.Attribute("name", []string{user.FirstName + " " + user.LastName})
	req.Attribute("givenName", []string{user.FirstName})
	req.Attribute("sn", []string{user.LastName})
	req.Attribute("displayName", []string{*user.DisplayName})
	req.Attribute("accountExpires", []string{convertAccountExpires(user.AccountExpires)})
	req.Attribute("userAccountControl", []string{fmt.Sprintf("%d", user.UserAccountControl.Uint32())})

	if user.SAMAccountName != nil {
		req.Attribute("sAMAccountName", []string{*user.SAMAccountName})
	}

	if user.Description != nil {
		req.Attribute("description", []string{*user.Description})
	}

	if user.Email != nil {
		req.Attribute("mail", []string{*user.Email})
	}

	return dn, c.Add(req)
}

func (l *LDAP) DeleteUser(dn string) error {
	c, err := l.GetConnection()
	if err != nil {
		return err
	}
	defer c.Close()

	return c.Del(&ldap.DelRequest{DN: dn})
}
