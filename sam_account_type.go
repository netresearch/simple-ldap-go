package ldap

// SamAccountType represents the Security Account Manager account type values used in Active Directory.
// This enumeration defines the type of account object and is stored in the sAMAccountType attribute.
//
// Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
type SamAccountType uint32

const (
	// SamDomainObject (0x0) represents a domain object.
	SamDomainObject SamAccountType = 0x0
	// SamGroupObject (0x10000000) represents a security group object.
	SamGroupObject SamAccountType = 0x10000000
	// SamNonSecurityGroupObject (0x10000001) represents a non-security group object.
	SamNonSecurityGroupObject SamAccountType = 0x10000001
	// SamAliasObject (0x20000000) represents an alias object (local group).
	SamAliasObject SamAccountType = 0x20000000
	// SamNonSecurityAliasObject (0x20000001) represents a non-security alias object.
	SamNonSecurityAliasObject SamAccountType = 0x20000001
	// SamUserObject (0x30000000) represents a normal user account (also known as SAM_NORMAL_USER_ACCOUNT).
	SamUserObject SamAccountType = 0x30000000
	// SamMachineAccount (0x30000001) represents a computer/machine account.
	SamMachineAccount SamAccountType = 0x30000001
	// SamTrustAccount (0x30000002) represents an interdomain trust account.
	SamTrustAccount SamAccountType = 0x30000002
	// SamAppBasicGroup (0x40000000) represents an application basic group.
	SamAppBasicGroup SamAccountType = 0x40000000
	// SamAppQueryGroup (0x40000001) represents an application query group.
	SamAppQueryGroup SamAccountType = 0x40000001
	// SamAccountTypeMax (0x7fffffff) represents the maximum account type value.
	SamAccountTypeMax SamAccountType = 0x7fffffff
)

// String returns a human-readable description of the SAM account type.
//
// Returns:
//   - string: A descriptive name for the account type, or "Unknown" for unrecognized values
//
// This method is useful for logging and debugging to understand what type of account
// object is being processed.
func (t SamAccountType) String() string {
	switch t {
	case SamDomainObject:
		return "Domain Object"
	case SamGroupObject:
		return "Group Object"
	case SamNonSecurityGroupObject:
		return "Non-Security Group Object"
	case SamAliasObject:
		return "Alias Object"
	case SamNonSecurityAliasObject:
		return "Non-Security Alias Object"
	case SamUserObject:
		return "User Object / Normal User Account"
	case SamMachineAccount:
		return "Machine Account"
	case SamTrustAccount:
		return "Trust Account"
	case SamAppBasicGroup:
		return "App Basic Group"
	case SamAppQueryGroup:
		return "App Query Group"
	case SamAccountTypeMax:
		return "Account Type Max"
	default:
		return "Unknown"
	}
}
