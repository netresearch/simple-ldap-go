package ldap

import "strings"

/*
Active Directory User Account Control Flag Values:
  ADS_UF_SCRIPT = 0x1,
  ADS_UF_ACCOUNTDISABLE = 0x2,
  ADS_UF_HOMEDIR_REQUIRED = 0x8,
  ADS_UF_LOCKOUT = 0x10,
  ADS_UF_PASSWD_NOTREQD = 0x20,
  ADS_UF_PASSWD_CANT_CHANGE = 0x40,
  ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80,
  ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x100,
  ADS_UF_NORMAL_ACCOUNT = 0x200,
  ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x800,
  ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x1000,
  ADS_UF_SERVER_TRUST_ACCOUNT = 0x2000,
  ADS_UF_DONT_EXPIRE_PASSWD = 0x10000,
  ADS_UF_MNS_LOGON_ACCOUNT = 0x20000,
  ADS_UF_SMARTCARD_REQUIRED = 0x40000,
  ADS_UF_TRUSTED_FOR_DELEGATION = 0x80000,
  ADS_UF_NOT_DELEGATED = 0x100000,
  ADS_UF_USE_DES_KEY_ONLY = 0x200000,
  ADS_UF_DONT_REQUIRE_PREAUTH = 0x400000,
  ADS_UF_PASSWORD_EXPIRED = 0x800000,
  ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000
*/

// UAC represents the User Account Control flags for Active Directory user and computer accounts.
// These flags control various security settings and account behaviors.
//
// Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
type UAC struct {
	// LogonScript (0x1) - Execute a logon script for the user
	LogonScript bool
	// AccountDisabled (0x2) - The account is disabled
	AccountDisabled bool
	// HomeDirRequired (0x8) - A home directory is required for the user
	HomeDirRequired bool
	// Lockout (0x10) - The account is locked out (read-only flag, set by the system)
	Lockout bool
	// PasswordNotRequired (0x20) - No password is required for the account
	PasswordNotRequired bool
	// PasswordCantChange (0x40) - The user cannot change their password
	PasswordCantChange bool
	// EncryptedTextPasswordAllowed (0x80) - Allows encrypted text passwords for the account
	EncryptedTextPasswordAllowed bool
	// TempDuplicateAccount (0x100) - This is a temporary duplicate account
	TempDuplicateAccount bool
	// NormalAccount (0x200) - This is a default account type representing a typical user
	NormalAccount bool
	// InterdomainTrustAccount (0x800) - This is a permit to trust account for a system domain that trusts other domains
	InterdomainTrustAccount bool
	// WorkstationTrustAccount (0x1000) - This is a computer account for a computer that is a member of this domain
	WorkstationTrustAccount bool
	// ServerTrustAccount (0x2000) - This is a computer account for a system backup domain controller that is a member of this domain
	ServerTrustAccount bool
	// NoPasswordExpiration (0x10000) - The password for this account does not expire
	NoPasswordExpiration bool
	// MNSLogonAccount (0x20000) - This is an MNS logon account
	MNSLogonAccount bool
	// SmartCardRequired (0x40000) - The user is required to log on using a smart card
	SmartCardRequired bool
	// TrustedForDelegation (0x80000) - The service account (user or computer account) under which a service runs is trusted for Kerberos delegation
	TrustedForDelegation bool
	// NotDelegated (0x100000) - The security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation
	NotDelegated bool
	// UseDESKeyOnly (0x200000) - Use DES encryption types for keys for this account
	UseDESKeyOnly bool
	// DontRequirePreauth (0x400000) - This account does not require Kerberos pre-authentication for logon
	DontRequirePreauth bool
	// PasswordExpired (0x800000) - The user password has expired
	PasswordExpired bool
	// TrustedToAuthenticateForDelegation (0x1000000) - The account is enabled for delegation; used with the Kerberos constrained delegation feature
	TrustedToAuthenticateForDelegation bool
}

// UACFromUint32 creates a UAC struct from a uint32 userAccountControl value.
// This function decodes the bitmask flags from Active Directory's userAccountControl attribute.
//
// Parameters:
//   - v: The uint32 value from the userAccountControl attribute
//
// Returns:
//   - UAC: A UAC struct with boolean flags corresponding to the bitmask
//
// Example:
//
//	// For a typical enabled user account (0x200 = ADS_UF_NORMAL_ACCOUNT)
//	uac := UACFromUint32(512)
//	// uac.NormalAccount will be true, AccountDisabled will be false
func UACFromUint32(v uint32) UAC {
	return UAC{
		LogonScript:                        v&0x1 != 0,
		AccountDisabled:                    v&0x2 != 0,
		HomeDirRequired:                    v&0x8 != 0,
		Lockout:                            v&0x10 != 0,
		PasswordNotRequired:                v&0x20 != 0,
		PasswordCantChange:                 v&0x40 != 0,
		EncryptedTextPasswordAllowed:       v&0x80 != 0,
		TempDuplicateAccount:               v&0x100 != 0,
		NormalAccount:                      v&0x200 != 0,
		InterdomainTrustAccount:            v&0x800 != 0,
		WorkstationTrustAccount:            v&0x1000 != 0,
		ServerTrustAccount:                 v&0x2000 != 0,
		NoPasswordExpiration:               v&0x10000 != 0,
		MNSLogonAccount:                    v&0x20000 != 0,
		SmartCardRequired:                  v&0x40000 != 0,
		TrustedForDelegation:               v&0x80000 != 0,
		NotDelegated:                       v&0x100000 != 0,
		UseDESKeyOnly:                      v&0x200000 != 0,
		DontRequirePreauth:                 v&0x400000 != 0,
		PasswordExpired:                    v&0x800000 != 0,
		TrustedToAuthenticateForDelegation: v&0x1000000 != 0,
	}
}

// Uint32 converts the UAC struct back to a uint32 userAccountControl value.
// This function encodes the boolean flags into the bitmask format expected by Active Directory.
//
// Returns:
//   - uint32: The userAccountControl bitmask value suitable for Active Directory operations
//
// This method is useful when creating or modifying user accounts and need to set the
// userAccountControl attribute with the appropriate flags.
func (u UAC) Uint32() uint32 {
	var v uint32 = 0

	if u.LogonScript {
		v |= 0x1
	}

	if u.AccountDisabled {
		v |= 0x2
	}

	if u.HomeDirRequired {
		v |= 0x8
	}

	if u.Lockout {
		v |= 0x10
	}

	if u.PasswordNotRequired {
		v |= 0x20
	}

	if u.PasswordCantChange {
		v |= 0x40
	}

	if u.EncryptedTextPasswordAllowed {
		v |= 0x80
	}

	if u.TempDuplicateAccount {
		v |= 0x100
	}

	if u.NormalAccount {
		v |= 0x200
	}

	if u.InterdomainTrustAccount {
		v |= 0x800
	}

	if u.WorkstationTrustAccount {
		v |= 0x1000
	}

	if u.ServerTrustAccount {
		v |= 0x2000
	}

	if u.NoPasswordExpiration {
		v |= 0x10000
	}

	if u.MNSLogonAccount {
		v |= 0x20000
	}

	if u.SmartCardRequired {
		v |= 0x40000
	}

	if u.TrustedForDelegation {
		v |= 0x80000
	}

	if u.NotDelegated {
		v |= 0x100000
	}

	if u.UseDESKeyOnly {
		v |= 0x200000
	}

	if u.DontRequirePreauth {
		v |= 0x400000
	}

	if u.PasswordExpired {
		v |= 0x800000
	}

	if u.TrustedToAuthenticateForDelegation {
		v |= 0x1000000
	}

	return v
}

// String returns a human-readable representation of the UAC flags.
// Only flags that are set to true are included in the output string.
//
// Returns:
//   - string: A comma-separated list of active UAC flag names
//
// Example output: "NormalAccount, NoPasswordExpiration"
// If no flags are set, returns an empty string.
func (u UAC) String() string {
	s := strings.Builder{}

	if u.LogonScript {
		s.WriteString("LogonScript, ")
	}

	if u.AccountDisabled {
		s.WriteString("AccountDisabled, ")
	}

	if u.HomeDirRequired {
		s.WriteString("HomeDirRequired, ")
	}

	if u.Lockout {
		s.WriteString("Lockout, ")
	}

	if u.PasswordNotRequired {
		s.WriteString("PasswordNotRequired, ")
	}

	if u.PasswordCantChange {
		s.WriteString("PasswordCantChange, ")
	}

	if u.EncryptedTextPasswordAllowed {
		s.WriteString("EncryptedTextPasswordAllowed, ")
	}

	if u.TempDuplicateAccount {
		s.WriteString("TempDuplicateAccount, ")
	}

	if u.NormalAccount {
		s.WriteString("NormalAccount, ")
	}

	if u.InterdomainTrustAccount {
		s.WriteString("InterdomainTrustAccount, ")
	}

	if u.WorkstationTrustAccount {
		s.WriteString("WorkstationTrustAccount, ")
	}

	if u.ServerTrustAccount {
		s.WriteString("ServerTrustAccount, ")
	}

	if u.NoPasswordExpiration {
		s.WriteString("NoPasswordExpiration, ")
	}

	if u.MNSLogonAccount {
		s.WriteString("MNSLogonAccount, ")
	}

	if u.SmartCardRequired {
		s.WriteString("SmartCardRequired, ")
	}

	if u.TrustedForDelegation {
		s.WriteString("TrustedForDelegation, ")
	}

	if u.NotDelegated {
		s.WriteString("NotDelegated, ")
	}

	if u.UseDESKeyOnly {
		s.WriteString("UseDESKeyOnly, ")
	}

	if u.DontRequirePreauth {
		s.WriteString("DontRequirePreauth, ")
	}

	if u.PasswordExpired {
		s.WriteString("PasswordExpired, ")
	}

	if u.TrustedToAuthenticateForDelegation {
		s.WriteString("TrustedToAuthenticateForDelegation, ")
	}

	return strings.TrimSuffix(s.String(), ", ")
}
