package ldap

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

var ErrComputerNotFound = errors.New("computer not found")

type Computer struct {
	Object
	SAMAccountName string
	Enabled        bool
	OS             string
	OSVersion      string
	// Groups is a list of CNs
	Groups []string
}

func (l *LDAP) FindComputerByDN(dn string) (computer *Computer, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=computer)",
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "userAccountControl", "operatingSystem", "operatingSystemVersion"},
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrComputerNotFound
	}

	if len(r.Entries) > 1 {
		return nil, ErrDNDuplicated
	}

	enabled, err := parseObjectEnabled(r.Entries[0].GetAttributeValue("userAccountControl"))
	if err != nil {
		return nil, err
	}

	computer = &Computer{
		Object:         objectFromEntry(r.Entries[0]),
		SAMAccountName: r.Entries[0].GetAttributeValue("sAMAccountName"),
		Enabled:        enabled,
		OS:             r.Entries[0].GetAttributeValue("operatingSystem"),
		OSVersion:      r.Entries[0].GetAttributeValue("operatingSystemVersion"),
		Groups:         r.Entries[0].GetAttributeValues("memberOf"),
	}

	return
}

func (l *LDAP) FindComputerBySAMAccountName(sAMAccountName string) (computer *Computer, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s))", ldap.EscapeFilter(sAMAccountName)),
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "userAccountControl", "operatingSystem", "operatingSystemVersion"},
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrComputerNotFound
	}

	if len(r.Entries) > 1 {
		return nil, ErrSAMAccountNameDuplicated
	}

	enabled, err := parseObjectEnabled(r.Entries[0].GetAttributeValue("userAccountControl"))
	if err != nil {
		return nil, err
	}

	computer = &Computer{
		Object:         objectFromEntry(r.Entries[0]),
		SAMAccountName: r.Entries[0].GetAttributeValue("sAMAccountName"),
		Enabled:        enabled,
		OS:             r.Entries[0].GetAttributeValue("operatingSystem"),
		OSVersion:      r.Entries[0].GetAttributeValue("operatingSystemVersion"),
		Groups:         r.Entries[0].GetAttributeValues("memberOf"),
	}

	return
}

func (l *LDAP) FindComputers() (computers []Computer, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=computer)",
		Attributes:   []string{"cn", "memberOf", "sAMAccountName", "userAccountControl", "operatingSystem", "operatingSystemVersion"},
	})
	if err != nil {
		return nil, err
	}

	for _, entry := range r.Entries {
		enabled, err := parseObjectEnabled(entry.GetAttributeValue("userAccountControl"))
		if err != nil {
			continue
		}

		computer := Computer{
			Object:         objectFromEntry(entry),
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			Enabled:        enabled,
			OS:             entry.GetAttributeValue("operatingSystem"),
			OSVersion:      entry.GetAttributeValue("operatingSystemVersion"),
			Groups:         entry.GetAttributeValues("memberOf"),
		}

		computers = append(computers, computer)
	}

	return
}
