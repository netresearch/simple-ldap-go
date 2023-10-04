package ldap

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")
)

type User struct {
	CN             string
	DN             string
	SAMAccountName string
	Enabled        bool
	// Groups is a list of CNs
	Groups []string
}

func (l *LDAP) FindUserByDN(dn string) (user *User, err error) {
	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=user)",
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "userAccountControl"},
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

	enabled, err := parseObjectEnabled(r.Entries[0].GetAttributeValue("userAccountControl"))
	if err != nil {
		return nil, err
	}

	user = &User{
		CN:             r.Entries[0].GetAttributeValue("cn"),
		DN:             r.Entries[0].DN,
		SAMAccountName: r.Entries[0].GetAttributeValue("sAMAccountName"),
		Enabled:        enabled,
		Groups:         r.Entries[0].GetAttributeValues("memberOf"),
	}

	return
}

func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (user *User, err error) {
	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(sAMAccountName)),
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "userAccountControl"},
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

	enabled, err := parseObjectEnabled(r.Entries[0].GetAttributeValue("userAccountControl"))
	if err != nil {
		return nil, err
	}

	user = &User{
		CN:             r.Entries[0].GetAttributeValue("cn"),
		DN:             r.Entries[0].DN,
		SAMAccountName: r.Entries[0].GetAttributeValue("sAMAccountName"),
		Enabled:        enabled,
		Groups:         r.Entries[0].GetAttributeValues("memberOf"),
	}

	return
}

func (l *LDAP) FindUsers() (users []User, err error) {
	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=user)",
		Attributes:   []string{"cn", "sAMAccountName", "memberOf", "userAccountControl"},
	})
	if err != nil {
		return nil, err
	}

	for _, entry := range r.Entries {
		enabled, err := parseObjectEnabled(entry.GetAttributeValue("userAccountControl"))
		if err != nil {
			continue
		}

		user := User{
			CN:             entry.GetAttributeValue("cn"),
			DN:             entry.DN,
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			Enabled:        enabled,
			Groups:         entry.GetAttributeValues("memberOf"),
		}

		users = append(users, user)
	}

	return
}
