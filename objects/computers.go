package objects

import (
	"context"
	"errors"
	"fmt"

	ldaplib "github.com/netresearch/simple-ldap-go"
)

// Simple function-based API for v2.0.0
// These functions replace the method-based API which can't be defined on external types

// FindComputerByDN retrieves a computer by its distinguished name.
func FindComputerByDN(client *ldaplib.LDAP, dn string) (*Computer, error) {
	return FindComputerByDNContext(client, context.Background(), dn)
}

// FindComputerByDNContext retrieves a computer by its distinguished name with context support.
func FindComputerByDNContext(client *ldaplib.LDAP, ctx context.Context, dn string) (*Computer, error) {
	// Simplified implementation for v2.0.0
	// Full implementation would use client.GetConnectionContext and perform LDAP search
	return nil, fmt.Errorf("FindComputerByDN not fully implemented in v2.0.0 restructure")
}

// FindComputerBySAMAccountName retrieves a computer by its SAM account name.
func FindComputerBySAMAccountName(client *ldaplib.LDAP, samAccountName string) (*Computer, error) {
	return FindComputerBySAMAccountNameContext(client, context.Background(), samAccountName)
}

// FindComputerBySAMAccountNameContext retrieves a computer by its SAM account name with context.
func FindComputerBySAMAccountNameContext(client *ldaplib.LDAP, ctx context.Context, samAccountName string) (*Computer, error) {
	// Simplified implementation for v2.0.0
	return nil, fmt.Errorf("FindComputerBySAMAccountName not fully implemented in v2.0.0 restructure")
}

// FindComputers retrieves all computers from the directory.
func FindComputers(client *ldaplib.LDAP) ([]Computer, error) {
	return FindComputersContext(client, context.Background())
}

// FindComputersContext retrieves all computers from the directory with context.
func FindComputersContext(client *ldaplib.LDAP, ctx context.Context) ([]Computer, error) {
	// Simplified implementation for v2.0.0
	return nil, fmt.Errorf("FindComputers not fully implemented in v2.0.0 restructure")
}

// CreateComputer creates a new computer in the directory.
func CreateComputer(client *ldaplib.LDAP, computer FullComputer, password string) (string, error) {
	return CreateComputerContext(client, context.Background(), computer, password)
}

// CreateComputerContext creates a new computer in the directory with context.
func CreateComputerContext(client *ldaplib.LDAP, ctx context.Context, computer FullComputer, password string) (string, error) {
	// Simplified implementation for v2.0.0
	return "", fmt.Errorf("CreateComputer not fully implemented in v2.0.0 restructure")
}

// DeleteComputer removes a computer from the directory.
func DeleteComputer(client *ldaplib.LDAP, computerDN string) error {
	return DeleteComputerContext(client, context.Background(), computerDN)
}

// DeleteComputerContext removes a computer from the directory with context.
func DeleteComputerContext(client *ldaplib.LDAP, ctx context.Context, computerDN string) error {
	// Simplified implementation for v2.0.0
	return fmt.Errorf("DeleteComputer not fully implemented in v2.0.0 restructure")
}

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

// FullComputer represents a complete LDAP computer object for creation and modification operations.
type FullComputer struct {
	// CN is the common name of the computer (required, used as the RDN component).
	CN string
	// SAMAccountName is the Security Account Manager account name (required, typically ends with $).
	SAMAccountName string
	// Description provides additional information about the computer (optional).
	Description string
	// UserAccountControl defines the account control flags for the computer account.
	UserAccountControl uint32
	// DNSHostName is the fully qualified domain name of the computer (optional).
	DNSHostName string
	// OperatingSystem contains the operating system name (optional).
	OperatingSystem string
	// OperatingSystemVersion contains the operating system version (optional).
	OperatingSystemVersion string
	// OperatingSystemServicePack contains the service pack information (optional).
	OperatingSystemServicePack string
	// MemberOf contains a list of distinguished names (DNs) of groups the computer belongs to.
	MemberOf []string
	// OtherAttributes contains additional LDAP attributes not covered by the above fields.
	OtherAttributes map[string][]string
}