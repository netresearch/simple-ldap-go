package ldap

import "github.com/go-ldap/ldap/v3"

type LDAP struct {
	server string

	baseDN string

	user     string
	password string

	isActiveDirectory bool
}

func New(server, baseDN, user, password string, isActiveDirectory bool) LDAP {
	return LDAP{
		server,
		baseDN,
		user,
		password,
		isActiveDirectory,
	}
}

func (l LDAP) getConnection() (*ldap.Conn, error) {
	c, err := ldap.DialURL(l.server)
	if err != nil {
		return nil, err
	}

	if err = c.Bind(l.user, l.password); err != nil {
		return nil, err
	}

	return c, nil
}
