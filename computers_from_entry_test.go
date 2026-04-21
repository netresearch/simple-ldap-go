package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestComputerFromEntry_ADFull exercises computerFromEntry against a
// typical AD entry populated with every extended attribute.
func TestComputerFromEntry_ADFull(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "CN=WS01,OU=Computers,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"WS01"}},
			{Name: "sAMAccountName", Values: []string{"WS01$"}},
			{Name: "userAccountControl", Values: []string{"4096"}}, // workstation trust, enabled
			{Name: "description", Values: []string{"Engineering workstation"}},
			{Name: "dNSHostName", Values: []string{"ws01.example.com"}},
			{Name: "operatingSystem", Values: []string{"Windows 11 Pro"}},
			{Name: "operatingSystemVersion", Values: []string{"10.0.22621"}},
			{Name: "operatingSystemServicePack", Values: []string{""}},
			{Name: "lastLogonTimestamp", Values: []string{"133253376000000000"}},
			{Name: "managedBy", Values: []string{"CN=Alice,OU=Users,DC=example,DC=com"}},
			{Name: "whenCreated", Values: []string{"20230101120000.0Z"}},
			{Name: "whenChanged", Values: []string{"20240601090000Z"}},
			{Name: "memberOf", Values: []string{"CN=workstations,OU=Groups,DC=example,DC=com"}},
		},
	}

	cp, err := computerFromEntry(entry)
	if err != nil {
		t.Fatalf("computerFromEntry returned error: %v", err)
	}

	if !cp.Enabled {
		t.Errorf("Enabled = false, want true (uac=4096)")
	}
	if cp.SAMAccountName != "WS01$" {
		t.Errorf("SAMAccountName = %q, want WS01$", cp.SAMAccountName)
	}
	if cp.Description != "Engineering workstation" {
		t.Errorf("Description = %q", cp.Description)
	}
	if cp.DNSHostName != "ws01.example.com" {
		t.Errorf("DNSHostName = %q", cp.DNSHostName)
	}
	if cp.OS != "Windows 11 Pro" || cp.OSVersion != "10.0.22621" {
		t.Errorf("OS fields mismatched: os=%q version=%q", cp.OS, cp.OSVersion)
	}
	if cp.LastLogon != 1680864000 {
		t.Errorf("LastLogon = %d, want 1680864000", cp.LastLogon)
	}
	if cp.ManagedByDN != "CN=Alice,OU=Users,DC=example,DC=com" {
		t.Errorf("ManagedByDN = %q", cp.ManagedByDN)
	}
	if cp.WhenCreated == 0 || cp.WhenChanged == 0 {
		t.Errorf("audit timestamps should be parsed: created=%d changed=%d",
			cp.WhenCreated, cp.WhenChanged)
	}
	if got := len(cp.Groups); got != 1 {
		t.Errorf("Groups length = %d, want 1", got)
	}
}

// TestComputerFromEntry_OpenLDAPDevice covers the OpenLDAP branch
// (no userAccountControl; cn used as the account name; Enabled
// defaults to true; audit timestamps absent).
func TestComputerFromEntry_OpenLDAPDevice(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "cn=laptop-001,ou=devices,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"laptop-001"}},
			{Name: "description", Values: []string{"Bob's laptop"}},
		},
	}

	cp, err := computerFromEntry(entry)
	if err != nil {
		t.Fatalf("computerFromEntry returned error: %v", err)
	}

	if !cp.Enabled {
		t.Errorf("OpenLDAP device should default Enabled=true")
	}
	if cp.SAMAccountName != "laptop-001" {
		t.Errorf("SAMAccountName = %q, want laptop-001 (cn fallback)", cp.SAMAccountName)
	}
	if cp.Description != "Bob's laptop" {
		t.Errorf("Description = %q", cp.Description)
	}
	if cp.OS != "" || cp.OSVersion != "" || cp.DNSHostName != "" {
		t.Errorf("AD-only fields should be empty for this entry")
	}
	if cp.WhenCreated != 0 || cp.WhenChanged != 0 || cp.ManagedByDN != "" {
		t.Errorf("audit fields should be zero-valued when absent: created=%d changed=%d managed=%q",
			cp.WhenCreated, cp.WhenChanged, cp.ManagedByDN)
	}
}

// TestComputerFromEntry_BadUAC ensures malformed userAccountControl
// propagates as an error so FindComputerByDN can return it and
// FindComputers can skip the entry.
func TestComputerFromEntry_BadUAC(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "CN=WS02,OU=Computers,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"WS02"}},
			{Name: "userAccountControl", Values: []string{"not-a-number"}},
			{Name: "sAMAccountName", Values: []string{"WS02$"}},
		},
	}

	_, err := computerFromEntry(entry)
	if err == nil {
		t.Fatalf("computerFromEntry returned nil error for malformed UAC")
	}
}
