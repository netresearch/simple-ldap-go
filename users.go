package ldap

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	// ErrUserNotFound is returned when a user search operation finds no matching entries.
	ErrUserNotFound = errors.New("user not found")
	// ErrSAMAccountNameDuplicated is returned when multiple users have the same sAMAccountName,
	// indicating a data integrity issue in the directory.
	ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")
	// ErrMailDuplicated is returned when multiple users have the same email address,
	// indicating a data integrity issue in the directory.
	ErrMailDuplicated = errors.New("mail is not unique")

	// accountExpiresBase is the base date for Active Directory account expiration calculations (January 1, 1601 UTC).
	accountExpiresBase = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	// accountExpiresNever represents the value for accounts that never expire in Active Directory.
	accountExpiresNever uint64 = 0x7FFFFFFFFFFFFFFF

	// userFields contains the standard LDAP attributes retrieved for user objects.
	userFields = []string{"memberOf", "cn", "sAMAccountName", "mail", "userAccountControl", "description"}
)

// User represents an LDAP user object with common attributes.
type User struct {
	Object
	// Enabled indicates whether the user account is enabled (not disabled by userAccountControl).
	Enabled bool
	// SAMAccountName is the Security Account Manager account name (unique identifier for Windows authentication).
	SAMAccountName string
	// Description contains the user's description or notes.
	Description string
	// Mail contains the user's email address (nil if not set).
	Mail *string
	// Groups contains a list of distinguished names (DNs) of groups the user belongs to.
	Groups []string
}

func userFromEntry(entry *ldap.Entry) (*User, error) {
	var enabled bool
	var err error
	var samAccountName string

	// Try to get userAccountControl for Active Directory
	if uac := entry.GetAttributeValue("userAccountControl"); uac != "" {
		enabled, err = parseObjectEnabled(uac)
		if err != nil {
			return nil, err
		}
		samAccountName = entry.GetAttributeValue("sAMAccountName")
	} else {
		// For OpenLDAP compatibility, assume users are enabled by default
		// OpenLDAP doesn't have userAccountControl
		enabled = true
		// Use uid as sAMAccountName equivalent for OpenLDAP
		samAccountName = entry.GetAttributeValue("uid")
		if samAccountName == "" {
			// Fall back to cn if uid is not available
			samAccountName = entry.GetAttributeValue("cn")
		}
	}

	var mail *string
	if mails := entry.GetAttributeValues("mail"); len(mails) > 0 {
		mail = &mails[0]
	}

	return &User{
		Object:         objectFromEntry(entry),
		Enabled:        enabled,
		SAMAccountName: samAccountName,
		Description:    entry.GetAttributeValue("description"),
		Mail:           mail,
		Groups:         entry.GetAttributeValues("memberOf"),
	}, nil
}

// FindUserByDN retrieves a user by their distinguished name.
//
// Parameters:
//   - dn: The distinguished name of the user (e.g., "CN=John Doe,CN=Users,DC=example,DC=com")
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     or any LDAP operation error
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
		Filter:       "(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))",
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "uid", "userAccountControl", "description", "mail"},
	})
	if err != nil {
		// If LDAP error indicates object not found, return ErrUserNotFound
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return nil, ErrUserNotFound
		}
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

// FindUserBySAMAccountName retrieves a user by their Security Account Manager account name.
//
// Parameters:
//   - sAMAccountName: The SAM account name (e.g., "jdoe" for john.doe@domain.com)
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given sAMAccountName,
//     ErrSAMAccountNameDuplicated if multiple users have the same sAMAccountName,
//     or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// For OpenLDAP compatibility, it also searches for uid attribute when sAMAccountName is not found.
func (l *LDAP) FindUserBySAMAccountName(sAMAccountName string) (user *User, err error) {
	c, err := l.GetConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// Try Active Directory search first
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(sAMAccountName))
	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   userFields,
	})
	if err != nil {
		return nil, err
	}

	// If no results with Active Directory filter, try OpenLDAP compatibility
	if len(r.Entries) == 0 && !l.config.IsActiveDirectory {
		filter = fmt.Sprintf("(&(|(objectClass=inetOrgPerson)(objectClass=person))(uid=%s))", ldap.EscapeFilter(sAMAccountName))
		r, err = c.Search(&ldap.SearchRequest{
			BaseDN:       l.config.BaseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Filter:       filter,
			Attributes:   []string{"memberOf", "cn", "uid", "mail", "description"}, // OpenLDAP compatible attributes
		})
		if err != nil {
			return nil, err
		}
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

// FindUserByMail retrieves a user by their email address.
//
// Parameters:
//   - mail: The email address to search for (e.g., "john.doe@example.com")
//
// Returns:
//   - *User: The user object if found
//   - error: ErrUserNotFound if no user exists with the given email,
//     ErrMailDuplicated if multiple users have the same email address,
//     or any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
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
		Filter:       fmt.Sprintf("(&(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))(mail=%s))", ldap.EscapeFilter(mail)),
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "uid", "mail", "userAccountControl", "description"}, // Include both AD and OpenLDAP attributes
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

// FindUsers retrieves all user objects from the directory.
//
// Returns:
//   - []User: A slice of all user objects found in the directory
//   - error: Any LDAP operation error
//
// This method performs a subtree search starting from the configured BaseDN.
// Users that cannot be parsed (due to missing required attributes) are skipped.
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
		Filter:       "(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=person))",
		Attributes:   []string{"memberOf", "cn", "sAMAccountName", "uid", "mail", "userAccountControl", "description"}, // Include both AD and OpenLDAP attributes
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

// AddUserToGroup adds a user to a group by modifying the group's member attribute.
//
// Parameters:
//   - dn: The distinguished name of the user to add to the group
//   - groupDN: The distinguished name of the group to modify
//
// Returns:
//   - error: Any LDAP operation error, including insufficient permissions or if the user is already a member
//
// This operation requires write permissions on the target group object.
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

// RemoveUserFromGroup removes a user from a group by modifying the group's member attribute.
//
// Parameters:
//   - dn: The distinguished name of the user to remove from the group
//   - groupDN: The distinguished name of the group to modify
//
// Returns:
//   - error: Any LDAP operation error, including insufficient permissions or if the user is not a member
//
// This operation requires write permissions on the target group object.
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

// FullUser represents a complete user object for creation operations with all configurable attributes.
type FullUser struct {
	// CN is the common name of the user (required, used as the RDN component).
	CN string
	// SAMAccountName is the Security Account Manager account name (optional for creation).
	SAMAccountName *string
	// FirstName is the user's given name (required).
	FirstName string
	// LastName is the user's surname (required).
	LastName string
	// DisplayName is the name displayed in address lists (optional, defaults to CN if nil).
	DisplayName *string
	// Description contains additional information about the user (optional).
	Description *string
	// Email is the user's email address (optional).
	Email *string
	// ObjectClasses defines the LDAP object classes (optional, defaults to standard user classes).
	ObjectClasses []string
	// AccountExpires represents the expiration date of the user's account.
	// When set to nil, the account never expires.
	AccountExpires *time.Time
	// UserAccountControl contains the account control flags (enabled/disabled, password policies, etc.).
	UserAccountControl UAC
	// Path specifies the organizational unit path relative to BaseDN (optional, defaults to BaseDN).
	Path *string
}

// CreateUser creates a new user in the directory with the specified attributes.
//
// Parameters:
//   - user: The FullUser object containing all user attributes
//   - password: The initial password for the user (currently not implemented in this version)
//
// Returns:
//   - string: The distinguished name of the created user
//   - error: Any LDAP operation error, including duplicate entries or insufficient permissions
//
// Default behaviors:
//   - ObjectClasses defaults to ["top", "person", "organizationalPerson", "user"] if not specified
//   - DisplayName defaults to CN if not specified
//   - The user is created at the specified Path relative to BaseDN, or directly under BaseDN if Path is nil
//
// Example:
//
//	user := FullUser{
//	    CN: "John Doe",
//	    FirstName: "John",
//	    LastName: "Doe",
//	    SAMAccountName: &"jdoe",
//	    Email: &"john.doe@example.com",
//	    UserAccountControl: UAC{NormalAccount: true},
//	}
//	dn, err := client.CreateUser(user, "")
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

// DeleteUser removes a user from the directory.
//
// Parameters:
//   - dn: The distinguished name of the user to delete
//
// Returns:
//   - error: Any LDAP operation error, including user not found or insufficient permissions
//
// Warning: This operation is irreversible. Ensure you have proper backups and permissions before deletion.
func (l *LDAP) DeleteUser(dn string) error {
	c, err := l.GetConnection()
	if err != nil {
		return err
	}
	defer c.Close()

	return c.Del(&ldap.DelRequest{DN: dn})
}
