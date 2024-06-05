package ldap

/*
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

type UAC struct {
	Script                             bool
	AccountDisabled                    bool
	HomeDirRequired                    bool
	Lockout                            bool
	PasswordNotRequired                bool
	PasswordCantChange                 bool
	EncryptedTextPasswordAllowed       bool
	TempDuplicateAccount               bool
	NormalAccount                      bool
	InterdomainTrustAccount            bool
	WorkstationTrustAccount            bool
	ServerTrustAccount                 bool
	DontExpirePassword                 bool
	MNSLogonAccount                    bool
	SmartCardRequired                  bool
	TrustedForDelegation               bool
	NotDelegated                       bool
	UseDESKeyOnly                      bool
	DontRequirePreauth                 bool
	PasswordExpired                    bool
	TrustedToAuthenticateForDelegation bool
}

func (u *UAC) Uint32() uint32 {
	var v uint32 = 0

	if u.Script {
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

	if u.DontExpirePassword {
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
