package ldap

// User represents an LDAP user object with common attributes.
type User struct {
	Object
	// Enabled indicates whether the user account is enabled (not disabled by userAccountControl).
	Enabled bool
	// SAMAccountName is the Security Account Manager account name (unique identifier for Windows authentication).
	SAMAccountName string
	// Description contains the user's description or notes.
	Description string
	// Mail contains the user's email address (nil if not set).
	Mail *string
	// Groups contains a list of distinguished names (DNs) of groups the user belongs to.
	Groups []string
}

// FullUser represents a complete LDAP user object for creation and modification operations.
type FullUser struct {
	// CN is the common name of the user (required, used as the RDN component).
	CN string
	// FirstName is the user's first name (optional).
	FirstName string
	// LastName is the user's last name (optional).
	LastName string
	// SAMAccountName is the Security Account Manager account name (required for Active Directory).
	SAMAccountName *string
	// DisplayName is the user's display name (optional).
	DisplayName *string
	// Description provides additional information about the user (optional).
	Description *string
	// Email is the user's email address (optional).
	Email *string
	// UserPrincipalName is the user's principal name in the format user@domain (optional).
	UserPrincipalName *string
	// EmployeeID is the employee identifier (optional).
	EmployeeID *string
	// Department is the user's department (optional).
	Department *string
	// Title is the user's job title (optional).
	Title *string
	// Company is the user's company name (optional).
	Company *string
	// Manager is the DN of the user's manager (optional).
	Manager *string
	// TelephoneNumber is the user's telephone number (optional).
	TelephoneNumber *string
	// Mobile is the user's mobile phone number (optional).
	Mobile *string
	// StreetAddress is the user's street address (optional).
	StreetAddress *string
	// City is the user's city (optional).
	City *string
	// StateOrProvince is the user's state or province (optional).
	StateOrProvince *string
	// PostalCode is the user's postal code (optional).
	PostalCode *string
	// Country is the user's country (optional).
	Country *string
	// UserAccountControl defines the account control flags for the user account.
	UserAccountControl uint32
	// OtherAttributes contains additional LDAP attributes not covered by the above fields.
	OtherAttributes map[string][]string
}

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
