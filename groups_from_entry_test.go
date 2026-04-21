package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestGroupFromEntry_ADSecurityGlobal exercises groupFromEntry against
// a typical AD "security, global scope" group populated with every
// extended attribute, verifying both the field wiring and the helper
// methods (IsSecurity / IsDistribution / Scope).
func TestGroupFromEntry_ADSecurityGlobal(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "CN=developers,OU=Groups,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"developers"}},
			{Name: "description", Values: []string{"Engineering team"}},
			{Name: "member", Values: []string{
				"CN=Alice,OU=Users,DC=example,DC=com",
				"CN=Bob,OU=Users,DC=example,DC=com",
			}},
			{Name: "memberOf", Values: []string{"CN=staff,OU=Groups,DC=example,DC=com"}},
			// -2147483646 == 0x80000002 == GLOBAL | SECURITY
			{Name: "groupType", Values: []string{"-2147483646"}},
			{Name: "managedBy", Values: []string{"CN=Alice,OU=Users,DC=example,DC=com"}},
			{Name: "whenCreated", Values: []string{"20230101120000.0Z"}},
			{Name: "whenChanged", Values: []string{"20240601090000Z"}},
		},
	}

	g := groupFromEntry(entry)

	if g.Description != "Engineering team" {
		t.Errorf("Description = %q", g.Description)
	}
	if got := len(g.Members); got != 2 {
		t.Errorf("Members length = %d, want 2", got)
	}
	if got := len(g.MemberOf); got != 1 {
		t.Errorf("MemberOf length = %d, want 1", got)
	}
	if g.GroupType != 0x80000002 {
		t.Errorf("GroupType = %#x, want 0x80000002", g.GroupType)
	}
	if !g.IsSecurity() {
		t.Errorf("IsSecurity() = false, want true")
	}
	if g.IsDistribution() {
		t.Errorf("IsDistribution() = true, want false")
	}
	if got := g.Scope(); got != "global" {
		t.Errorf("Scope() = %q, want \"global\"", got)
	}
	if g.ManagedByDN != "CN=Alice,OU=Users,DC=example,DC=com" {
		t.Errorf("ManagedByDN = %q", g.ManagedByDN)
	}
	if g.WhenCreated == 0 || g.WhenChanged == 0 {
		t.Errorf("audit timestamps should be parsed: created=%d changed=%d",
			g.WhenCreated, g.WhenChanged)
	}
}

// TestGroupFromEntry_ADDistributionUniversal covers the "distribution,
// universal scope" flavour: no security flag, universal bit set.
func TestGroupFromEntry_ADDistributionUniversal(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "CN=news,OU=Groups,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"news"}},
			// 8 = UNIVERSAL, no security flag -> distribution
			{Name: "groupType", Values: []string{"8"}},
		},
	}

	g := groupFromEntry(entry)

	if g.IsSecurity() {
		t.Errorf("IsSecurity() = true, want false (distribution group)")
	}
	if !g.IsDistribution() {
		t.Errorf("IsDistribution() = false, want true")
	}
	if got := g.Scope(); got != "universal" {
		t.Errorf("Scope() = %q, want \"universal\"", got)
	}
}

// TestGroupFromEntry_NoGroupType covers the non-AD branch (OpenLDAP
// posixGroup / groupOfNames) where groupType is absent entirely.
func TestGroupFromEntry_NoGroupType(t *testing.T) {
	t.Parallel()

	entry := &ldap.Entry{
		DN: "cn=admins,ou=groups,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"admins"}},
			{Name: "description", Values: []string{"System administrators"}},
			{Name: "member", Values: []string{"uid=root,ou=people,dc=example,dc=com"}},
		},
	}

	g := groupFromEntry(entry)

	if g.GroupType != 0 {
		t.Errorf("GroupType = %#x, want 0 (unknown)", g.GroupType)
	}
	if g.IsSecurity() {
		t.Errorf("IsSecurity() = true, want false when groupType=0")
	}
	if g.IsDistribution() {
		t.Errorf("IsDistribution() = true, want false when groupType=0 (unknown, not confirmed)")
	}
	if got := g.Scope(); got != "" {
		t.Errorf("Scope() = %q, want \"\" when groupType=0", got)
	}
	if g.ManagedByDN != "" || g.WhenCreated != 0 || g.WhenChanged != 0 {
		t.Errorf("absent attrs should yield zero values: managedBy=%q created=%d changed=%d",
			g.ManagedByDN, g.WhenCreated, g.WhenChanged)
	}
}

// TestGroupFromEntry_GroupTypeScopes covers each individual scope bit
// via the bit-pattern input.
func TestGroupFromEntry_GroupTypeScopes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		bits  string
		scope string
	}{
		{"builtin", "1", "builtin"},
		{"global", "2", "global"},
		{"domain_local", "4", "domain-local"},
		{"universal", "8", "universal"},
		{"app_basic", "16", "app-basic"},
		{"app_query", "32", "app-query"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := groupFromEntry(&ldap.Entry{Attributes: []*ldap.EntryAttribute{
				{Name: "groupType", Values: []string{tc.bits}},
			}})
			if got := g.Scope(); got != tc.scope {
				t.Errorf("Scope() = %q, want %q for bits %s", got, tc.scope, tc.bits)
			}
		})
	}
}

// TestGroupFromEntry_InvalidGroupType ensures a malformed groupType
// string leaves GroupType at 0 rather than panicking.
func TestGroupFromEntry_InvalidGroupType(t *testing.T) {
	t.Parallel()

	g := groupFromEntry(&ldap.Entry{Attributes: []*ldap.EntryAttribute{
		{Name: "groupType", Values: []string{"not-a-number"}},
	}})
	if g.GroupType != 0 {
		t.Errorf("GroupType = %#x, want 0 for malformed input", g.GroupType)
	}
}
