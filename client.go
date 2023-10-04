package ldap

import (
	"errors"

	"github.com/go-ldap/ldap/v3"
)

type Config struct {
	Server string
	BaseDN string

	IsActiveDirectory bool
}

type LDAP struct {
	config Config

	user     string
	password string
}

var ErrDNDuplicated = errors.New("DN is not unique")

func New(config Config, user, password string) (*LDAP, error) {
	l := &LDAP{
		config,
		user,
		password,
	}

	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	c.Close()

	return l, nil
}

func (l LDAP) getConnection() (*ldap.Conn, error) {
	c, err := ldap.DialURL(l.config.Server)
	if err != nil {
		return nil, err
	}

	if err = c.Bind(l.user, l.password); err != nil {
		return nil, err
	}

	return c, nil
}
