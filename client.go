package ldap

import "github.com/go-ldap/ldap/v3"

type LDAP struct {
	server string

	baseDN string

	user     string
	password string
}

func New(server, baseDN, user, password string) LDAP {
	return LDAP{
		server,
		baseDN,
		user,
		password,
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
