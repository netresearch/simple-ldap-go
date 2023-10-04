package ldap

import "github.com/go-ldap/ldap/v3"

type Object struct {
	cn string
	dn string
}

func objectFromEntry(entry *ldap.Entry) Object {
	return Object{
		cn: entry.GetAttributeValue("cn"),
		dn: entry.DN,
	}
}

func (o Object) DN() string {
	return o.dn
}

func (o Object) CN() string {
	return o.cn
}
