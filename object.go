package ldap

import "github.com/go-ldap/ldap/v3"

// Object represents the base LDAP object with common name and distinguished name.
type Object struct {
	cn string
	dn string
}

// objectFromEntry creates an Object from an LDAP entry.
func objectFromEntry(entry *ldap.Entry) Object {
	return Object{
		cn: entry.GetAttributeValue("cn"),
		dn: entry.DN,
	}
}

// DN returns the distinguished name of the object.
// The distinguished name uniquely identifies an object in the LDAP directory tree.
func (o Object) DN() string {
	return o.dn
}

// CN returns the common name of the object.
// The common name is the human-readable name component of the distinguished name.
func (o Object) CN() string {
	return o.cn
}
