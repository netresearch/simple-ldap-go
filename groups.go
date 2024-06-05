package ldap

import (
	"errors"

	"github.com/go-ldap/ldap/v3"
)

var ErrGroupNotFound = errors.New("group not found")

type Group struct {
	Object
	// Members is a list of DNs
	Members []string
}

func (l *LDAP) FindGroupByDN(dn string) (group *Group, err error) {
	c, err := l.GetConnection()
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
		Object:  objectFromEntry(r.Entries[0]),
		Members: r.Entries[0].GetAttributeValues("member"),
	}

	return
}

func (l *LDAP) FindGroups() (groups []Group, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
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
			Object:  objectFromEntry(entry),
			Members: entry.GetAttributeValues("member"),
		}

		groups = append(groups, group)
	}

	return
}
