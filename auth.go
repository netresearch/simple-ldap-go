package ldap

func (l LDAP) CheckPasswordForSAMAccountName(sAMAccountName, password string) (*User, error) {
	c, err := l.getConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	user, err := l.FindUserBySAMAccountName(sAMAccountName)
	if err != nil {
		return nil, err
	}

	err = c.Bind(user.DN, password)
	if err != nil {
		return nil, err
	}

	return user, nil
}
