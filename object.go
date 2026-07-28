package ldap

import "github.com/go-ldap/ldap/v3"

// Object represents the base LDAP object with common name and distinguished name.
type Object struct {
	cn string
	dn string
}

// NewObject builds an Object with the given common name and distinguished name.
//
// Production code never needs this: an Object is normally decoded from a
// directory response, and its fields are unexported so that what a directory
// returned cannot be edited afterwards. NewObject exists so that callers can
// construct fixtures — a User, Group or Computer whose DN() and CN() answer
// known values — without reaching into the unexported fields via reflection.
//
// The arguments are cn first, dn second, matching the field order; both are
// strings, so a swapped call compiles.
func NewObject(cn, dn string) Object {
	return Object{
		cn: cn,
		dn: dn,
	}
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
