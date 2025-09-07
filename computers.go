package ldap

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// ErrComputerNotFound is returned when a computer search operation finds no matching entries.
var ErrComputerNotFound = errors.New("computer not found")

// Computer represents an LDAP computer object with common attributes.
type Computer struct {
	Object
	// SAMAccountName is the Security Account Manager account name for the computer (typically ends with $).
	SAMAccountName string
	// Enabled indicates whether the computer account is enabled (not disabled by userAccountControl).
	Enabled bool
	// OS contains the operating system name from the operatingSystem attribute.
	OS string
	// OSVersion contains the operating system version from the operatingSystemVersion attribute.
	OSVersion string
	// Groups contains a list of distinguished names (DNs) of groups the computer belongs to.
	Groups []string
}

// FindComputerByDN retrieves a computer by its distinguished name.
//
// Parameters:
//   - dn: The distinguished name of the computer (e.g., "CN=COMPUTER01,CN=Computers,DC=example,DC=com")
//
// Returns:
//   - *Computer: The computer object if found
//   - error: ErrComputerNotFound if no computer exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     or any LDAP operation error
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
		Filter:       "(|(objectClass=computer)(objectClass=device))",
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "userAccountControl", "operatingSystem", "operatingSystemVersion", "description"},
	})
	if err != nil {
		// If LDAP error indicates object not found, return ErrComputerNotFound
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return nil, ErrComputerNotFound
		}
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrComputerNotFound
	}

	if len(r.Entries) > 1 {
		return nil, ErrDNDuplicated
	}

	var enabled bool
	var samAccountName string
	
	// Handle Active Directory vs OpenLDAP compatibility
	if uac := r.Entries[0].GetAttributeValue("userAccountControl"); uac != "" {
		// Active Directory
		var err error
		enabled, err = parseObjectEnabled(uac)
		if err != nil {
			return nil, err
		}
		samAccountName = r.Entries[0].GetAttributeValue("sAMAccountName")
	} else {
		// OpenLDAP - devices are typically enabled, use cn as account name
		enabled = true
		samAccountName = r.Entries[0].GetAttributeValue("cn")
	}

	computer = &Computer{
		Object:         objectFromEntry(r.Entries[0]),
		SAMAccountName: samAccountName,
		Enabled:        enabled,
		OS:             r.Entries[0].GetAttributeValue("operatingSystem"),
		OSVersion:      r.Entries[0].GetAttributeValue("operatingSystemVersion"),
		Groups:         r.Entries[0].GetAttributeValues("memberOf"),
	}

	return
}

// FindComputerBySAMAccountName retrieves a computer by its Security Account Manager account name.
//
// Parameters:
//   - sAMAccountName: The SAM account name of the computer (e.g., "COMPUTER01$")
//
// Returns:
//   - *Computer: The computer object if found
//   - error: ErrComputerNotFound if no computer exists with the given sAMAccountName,
//     ErrSAMAccountNameDuplicated if multiple computers have the same sAMAccountName,
//     or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Computer sAMAccountNames typically end with a dollar sign ($).
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
		Filter:       fmt.Sprintf("(&(|(objectClass=computer)(objectClass=device))(|(sAMAccountName=%s)(cn=%s)))", ldap.EscapeFilter(sAMAccountName), ldap.EscapeFilter(sAMAccountName)),
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "userAccountControl", "operatingSystem", "operatingSystemVersion", "description"},
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

	var enabled bool
	var samAccountName string
	
	// Handle Active Directory vs OpenLDAP compatibility
	if uac := r.Entries[0].GetAttributeValue("userAccountControl"); uac != "" {
		// Active Directory
		var err error
		enabled, err = parseObjectEnabled(uac)
		if err != nil {
			return nil, err
		}
		samAccountName = r.Entries[0].GetAttributeValue("sAMAccountName")
	} else {
		// OpenLDAP - devices are typically enabled, use cn as account name
		enabled = true
		samAccountName = r.Entries[0].GetAttributeValue("cn")
	}

	computer = &Computer{
		Object:         objectFromEntry(r.Entries[0]),
		SAMAccountName: samAccountName,
		Enabled:        enabled,
		OS:             r.Entries[0].GetAttributeValue("operatingSystem"),
		OSVersion:      r.Entries[0].GetAttributeValue("operatingSystemVersion"),
		Groups:         r.Entries[0].GetAttributeValues("memberOf"),
	}

	return
}

// FindComputers retrieves all computer objects from the directory.
//
// Returns:
//   - []Computer: A slice of all computer objects found in the directory
//   - error: Any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Computers that cannot be parsed (due to missing required attributes) are skipped.
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
		Filter:       "(|(objectClass=computer)(objectClass=device))",
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
