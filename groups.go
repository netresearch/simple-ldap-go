package ldap

import (
	"errors"

	"github.com/go-ldap/ldap/v3"
)

var ErrGroupNotFound = errors.New("group not found")

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