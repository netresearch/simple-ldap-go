package ldap

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")
	ErrGroupNotFound            = errors.New("group not found")
	ErrDNDuplicated             = errors.New("DN is not unique")
)

type User struct {
	CN             string
	DN             string
	SAMAccountName string
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
		Attributes:   []string{"memberOf", "cn", "sAMAccountName"},
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

	user = &User{
		CN:             r.Entries[0].GetAttributeValue("cn"),
		DN:             r.Entries[0].DN,
		SAMAccountName: r.Entries[0].GetAttributeValue("sAMAccountName"),
	}

	user.Groups = append(user.Groups, r.Entries[0].GetAttributeValues("memberOf")...)

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
		Filter:       fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(sAMAccountName)),
		Attributes:   []string{"memberOf", "cn", "sAMAccountName"},
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

	user = &User{
		CN:             r.Entries[0].GetAttributeValue("cn"),
		DN:             r.Entries[0].DN,
		SAMAccountName: r.Entries[0].GetAttributeValue("sAMAccountName"),
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
		Attributes:   []string{"cn", "sAMAccountName", "memberOf"},
	})
	if err != nil {
		return nil, err
	}

	for _, entry := range r.Entries {
		user := User{
			CN:             entry.GetAttributeValue("cn"),
			DN:             entry.DN,
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			Groups:         entry.GetAttributeValues("memberOf"),
		}

		users = append(users, user)
	}

	return
}

type Group struct {
	CN string
	DN string
	// Members is a list of DNs
	Members []string
}

func (l *LDAP) FindGroups() (groups []Group, err error) {
	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=group)",
		Attributes:   []string{"cn", "member"},
	})
	if err != nil {
		return nil, err
	}

	for _, entry := range r.Entries {
		group := Group{
			CN:      entry.GetAttributeValue("cn"),
			DN:      entry.DN,
			Members: entry.GetAttributeValues("member"),
		}

		groups = append(groups, group)
	}

	return
}

func (l *LDAP) FindGroupByDN(dn string) (group *Group, err error) {
	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=group)",
		Attributes:   []string{"cn", "member"},
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrGroupNotFound
	}

	if len(r.Entries) > 1 {
		return nil, ErrDNDuplicated
	}

	group = &Group{
		CN:      r.Entries[0].GetAttributeValue("cn"),
		DN:      r.Entries[0].DN,
		Members: r.Entries[0].GetAttributeValues("member"),
	}

	return
}
