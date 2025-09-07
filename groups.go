package ldap

import (
	"errors"

	"github.com/go-ldap/ldap/v3"
)

// ErrGroupNotFound is returned when a group search operation finds no matching entries.
var ErrGroupNotFound = errors.New("group not found")

// Group represents an LDAP group object with its members.
type Group struct {
	Object
	// Members contains a list of distinguished names (DNs) of group members.
	Members []string
}

// FindGroupByDN retrieves a group by its distinguished name.
//
// Parameters:
//   - dn: The distinguished name of the group (e.g., "CN=Administrators,CN=Builtin,DC=example,DC=com")
//
// Returns:
//   - *Group: The group object if found
//   - error: ErrGroupNotFound if no group exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     or any LDAP operation error
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

// FindGroups retrieves all group objects from the directory.
//
// Returns:
//   - []Group: A slice of all group objects found in the directory
//   - error: Any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Groups that cannot be parsed are skipped and not included in the results.
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
