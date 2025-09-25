package objects

import (
	"context"
	"errors"

	ldaplib "github.com/netresearch/simple-ldap-go"
)

// ErrGroupNotFound is returned when a group search operation finds no matching entries.
var ErrGroupNotFound = errors.New("group not found")

// Group represents an LDAP group object with its members.
type Group struct {
	Object
	// Members contains a list of distinguished names (DNs) of group members.
	Members []string
}

// FullGroup represents a complete LDAP group object for creation and modification operations.
type FullGroup struct {
	// CN is the common name of the group (required, used as the RDN component).
	CN string
	// SAMAccountName is the Security Account Manager account name (optional).
	SAMAccountName string
	// Description provides additional information about the group (optional).
	Description string
	// GroupType defines the type and scope of the group (required for Active Directory).
	GroupType uint32
	// Member contains a list of distinguished names (DNs) of group members.
	Member []string
	// MemberOf contains a list of distinguished names (DNs) of parent groups.
	MemberOf []string
	// OtherAttributes contains additional LDAP attributes not covered by the above fields.
	OtherAttributes map[string][]string
}

// FindGroupByDN retrieves a group by its distinguished name.
//
// Parameters:
//   - client: The LDAP client instance
//   - dn: The distinguished name of the group (e.g., "CN=Administrators,CN=Builtin,DC=example,DC=com")
//
// Returns:
//   - *Group: The group object if found
//   - error: ErrGroupNotFound if no group exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     or any LDAP operation error
func FindGroupByDN(client *ldaplib.LDAP, dn string) (*Group, error) {
	return FindGroupByDNContext(client, context.Background(), dn)
}

// FindGroupByDNContext retrieves a group by its distinguished name with context support.
//
// Parameters:
//   - client: The LDAP client instance
//   - ctx: Context for controlling the operation timeout and cancellation
//   - dn: The distinguished name of the group (e.g., "CN=Administrators,CN=Builtin,DC=example,DC=com")
//
// Returns:
//   - *Group: The group object if found
//   - error: ErrGroupNotFound if no group exists with the given DN,
//     ErrDNDuplicated if multiple entries share the same DN (data integrity issue),
//     context cancellation error, or any LDAP operation error
func FindGroupByDNContext(client *ldaplib.LDAP, ctx context.Context, dn string) (*Group, error) {
	// Simplified implementation for v2.0.0
	// Full implementation would use client.GetConnectionContext and perform LDAP search
	return nil, errors.New("FindGroupByDN not fully implemented in v2.0.0 restructure")
}

// FindGroups retrieves all group objects from the directory.
//
// Parameters:
//   - client: The LDAP client instance
//
// Returns:
//   - []Group: A slice of all group objects found in the directory
//   - error: Any LDAP operation error
//
// This function performs a subtree search starting from the configured BaseDN.
// Groups that cannot be parsed are skipped and not included in the results.
func FindGroups(client *ldaplib.LDAP) ([]Group, error) {
	return FindGroupsContext(client, context.Background())
}

// FindGroupsContext retrieves all group objects from the directory with context support.
//
// Parameters:
//   - client: The LDAP client instance
//   - ctx: Context for controlling the operation timeout and cancellation
//
// Returns:
//   - []Group: A slice of all group objects found in the directory
//   - error: Any LDAP operation error or context cancellation error
//
// This function performs a subtree search starting from the configured BaseDN.
// Groups that cannot be parsed are skipped and not included in the results.
func FindGroupsContext(client *ldaplib.LDAP, ctx context.Context) ([]Group, error) {
	// Simplified implementation for v2.0.0
	// Full implementation would use client.GetConnectionContext and perform LDAP search
	return nil, errors.New("FindGroups not fully implemented in v2.0.0 restructure")
}
