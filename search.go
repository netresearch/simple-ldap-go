package ldap

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrSAMAccountNameDuplicated = errors.New("sAMAccountName is not unique")
)

type User struct {
	CN             string
	DN             string
	SAMAccountName string
	Groups         []string
}

func (l LDAP) FindUserBySAMAccountName(sAMAccountName string) (user *User, err error) {
	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Search(&ldap.SearchRequest{
		BaseDN:       l.baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       fmt.Sprintf("(sAMAccountName=%s)", sAMAccountName),
		Attributes:   []string{"memberOf", "cn", "sAMAccountName"},
	})
	if err != nil {
		return nil, err
	}

	if len(r.Entries) == 0 {
		return nil, ErrUserNotFound
	}

	if len(r.Entries) > 1 {
		return nil, ErrSAMAccountNameDuplicated
	}

	user = &User{
		CN:             r.Entries[0].GetAttributeValue("cn"),
		DN:             r.Entries[0].DN,
		SAMAccountName: r.Entries[0].GetAttributeValue("sAMAccountName"),
	}

	for _, group := range r.Entries[0].GetAttributeValues("memberOf") {
		user.Groups = append(user.Groups, group)
	}

	return
}
