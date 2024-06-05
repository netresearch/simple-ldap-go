package ldap

// SamAccountType is a bit mask that defines the type of an account.
// https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
type SamAccountType uint32

const (
	SamDomainObject           SamAccountType = 0x0
	SamGroupObject            SamAccountType = 0x10000000
	SamNonSecurityGroupObject SamAccountType = 0x10000001
	SamAliasObject            SamAccountType = 0x20000000
	SamNonSecurityAliasObject SamAccountType = 0x20000001
	// SamUserObject is also known as SAM_NORMAL_USER_ACCOUNT
	SamUserObject     SamAccountType = 0x30000000
	SamMachineAccount SamAccountType = 0x30000001
	SamTrustAccount   SamAccountType = 0x30000002
	SamAppBasicGroup  SamAccountType = 0x40000000
	SamAppQueryGroup  SamAccountType = 0x40000001
	SamAccountTypeMax SamAccountType = 0x7fffffff
)

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
