package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestUserFromEntry_ADFull exercises userFromEntry against a typical
// Active Directory entry populated with every extended attribute added
// in this PR. Keeps coverage on the AD branch + the field-mapping code.
func TestUserFromEntry_ADFull(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "CN=Jane Doe,OU=Engineering,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"Jane Doe"}},
			{Name: "sAMAccountName", Values: []string{"jdoe"}},
			{Name: "userAccountControl", Values: []string{"512"}}, // normal, enabled
			{Name: "description", Values: []string{"Principal engineer"}},
			{Name: "mail", Values: []string{"jdoe@example.com"}},
			{Name: "lastLogonTimestamp", Values: []string{"133253376000000000"}},
			{Name: "givenName", Values: []string{"Jane"}},
			{Name: "sn", Values: []string{"Doe"}},
			{Name: "displayName", Values: []string{"Jane Doe (Eng)"}},
			{Name: "title", Values: []string{"Principal Engineer"}},
			{Name: "department", Values: []string{"Engineering"}},
			{Name: "company", Values: []string{"Example Corp"}},
			{Name: "manager", Values: []string{"CN=Alex Lead,OU=Engineering,DC=example,DC=com"}},
			{Name: "telephoneNumber", Values: []string{"+1-555-0100"}},
			{Name: "mobile", Values: []string{"+1-555-0101"}},
			{Name: "physicalDeliveryOfficeName", Values: []string{"HQ-2F"}},
			{Name: "accountExpires", Values: []string{"9223372036854775807"}}, // never
			{Name: "pwdLastSet", Values: []string{"133253376000000000"}},
			{Name: "lockoutTime", Values: []string{"0"}},
			{Name: "whenCreated", Values: []string{"20230101120000.0Z"}},
			{Name: "whenChanged", Values: []string{"20240601090000Z"}},
			{Name: "memberOf", Values: []string{"CN=Admins,DC=example,DC=com", "CN=Devs,DC=example,DC=com"}},
		},
	}

	u, err := userFromEntry(entry)
	if err != nil {
		t.Fatalf("userFromEntry returned error: %v", err)
	}

	if !u.Enabled {
		t.Errorf("Enabled = false, want true (uac=512)")
	}
	if u.SAMAccountName != "jdoe" {
		t.Errorf("SAMAccountName = %q, want jdoe", u.SAMAccountName)
	}
	if u.Description != "Principal engineer" {
		t.Errorf("Description = %q", u.Description)
	}
	if u.Mail == nil || *u.Mail != "jdoe@example.com" {
		t.Errorf("Mail = %v, want jdoe@example.com", u.Mail)
	}
	if u.LastLogon != 1680864000 {
		t.Errorf("LastLogon = %d, want 1680864000", u.LastLogon)
	}
	if u.GivenName != "Jane" || u.Surname != "Doe" || u.DisplayName != "Jane Doe (Eng)" {
		t.Errorf("identity fields mismatched: given=%q sn=%q display=%q",
			u.GivenName, u.Surname, u.DisplayName)
	}
	if u.Title != "Principal Engineer" || u.Department != "Engineering" || u.Company != "Example Corp" {
		t.Errorf("org fields mismatched: title=%q dept=%q company=%q",
			u.Title, u.Department, u.Company)
	}
	if u.ManagerDN != "CN=Alex Lead,OU=Engineering,DC=example,DC=com" {
		t.Errorf("ManagerDN = %q", u.ManagerDN)
	}
	if u.TelephoneNumber != "+1-555-0100" || u.Mobile != "+1-555-0101" {
		t.Errorf("phone fields mismatched: tel=%q mob=%q", u.TelephoneNumber, u.Mobile)
	}
	if u.Office != "HQ-2F" {
		t.Errorf("Office = %q", u.Office)
	}
	if u.AccountExpires != -1 {
		t.Errorf("AccountExpires = %d, want -1 (never)", u.AccountExpires)
	}
	if u.PwdLastSet != 1680864000 {
		t.Errorf("PwdLastSet = %d, want 1680864000", u.PwdLastSet)
	}
	if u.MustChangePassword {
		t.Errorf("MustChangePassword = true, want false (pwdLastSet != 0)")
	}
	if u.LockoutTime != 0 {
		t.Errorf("LockoutTime = %d, want 0", u.LockoutTime)
	}
	if u.WhenCreated == 0 {
		t.Errorf("WhenCreated = 0, expected a parsed timestamp")
	}
	if u.WhenChanged == 0 {
		t.Errorf("WhenChanged = 0, expected a parsed timestamp")
	}
	if got := len(u.Groups); got != 2 {
		t.Errorf("Groups length = %d, want 2", got)
	}
}

// TestUserFromEntry_OpenLDAP covers the openldap branch (no
// userAccountControl) and the "must change password" pwdLastSet=0
// case. Most identity fields are absent in this scenario — verifies
// they default to zero values cleanly.
func TestUserFromEntry_OpenLDAP(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"Alice Demo"}},
			{Name: "uid", Values: []string{"alice"}},
			{Name: "mail", Values: []string{"alice@example.com"}},
			{Name: "description", Values: []string{""}},
			{Name: "pwdLastSet", Values: []string{"0"}},
		},
	}

	u, err := userFromEntry(entry)
	if err != nil {
		t.Fatalf("userFromEntry returned error: %v", err)
	}

	if !u.Enabled {
		t.Errorf("OpenLDAP user should default Enabled=true")
	}
	if u.SAMAccountName != "alice" {
		t.Errorf("SAMAccountName = %q, want alice (uid fallback)", u.SAMAccountName)
	}
	if !u.MustChangePassword {
		t.Errorf("MustChangePassword = false, want true (pwdLastSet=0)")
	}
	if u.GivenName != "" || u.Surname != "" || u.Title != "" {
		t.Errorf("identity fields should be empty for this entry")
	}
	if u.AccountExpires != 0 {
		t.Errorf("AccountExpires = %d, want 0 (unset)", u.AccountExpires)
	}
	if u.WhenCreated != 0 || u.WhenChanged != 0 {
		t.Errorf("audit timestamps should be 0 when absent: created=%d changed=%d",
			u.WhenCreated, u.WhenChanged)
	}
}

// TestUserFromEntry_CNFallback exercises the OpenLDAP sAMAccountName
// fallback path where uid is missing — CN is used instead. The code
// path is otherwise uncovered.
func TestUserFromEntry_CNFallback(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "cn=svc-account,ou=services,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"svc-account"}},
		},
	}

	u, err := userFromEntry(entry)
	if err != nil {
		t.Fatalf("userFromEntry returned error: %v", err)
	}

	if u.SAMAccountName != "svc-account" {
		t.Errorf("SAMAccountName = %q, want svc-account (cn fallback)", u.SAMAccountName)
	}
}
