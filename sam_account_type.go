package ldap

// SamAccountType is a bit mask that defines the type of an account.
// https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
type SamAccountType uint32

const (
	SAM_DOMAIN_OBJECT             SamAccountType = 0x0
	SAM_GROUP_OBJECT              SamAccountType = 0x10000000
	SAM_NON_SECURITY_GROUP_OBJECT SamAccountType = 0x10000001
	SAM_ALIAS_OBJECT              SamAccountType = 0x20000000
	SAM_NON_SECURITY_ALIAS_OBJECT SamAccountType = 0x20000001
	SAM_USER_OBJECT               SamAccountType = 0x30000000
	SAM_NORMAL_USER_ACCOUNT       SamAccountType = 0x30000000
	SAM_MACHINE_ACCOUNT           SamAccountType = 0x30000001
	SAM_TRUST_ACCOUNT             SamAccountType = 0x30000002
	SAM_APP_BASIC_GROUP           SamAccountType = 0x40000000
	SAM_APP_QUERY_GROUP           SamAccountType = 0x40000001
	SAM_ACCOUNT_TYPE_MAX          SamAccountType = 0x7fffffff
)
