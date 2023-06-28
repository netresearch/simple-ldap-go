package ldap

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestAuthWithReaduser(t *testing.T) {
	wantSAMAccountName := "testuser"
	wantCN := "Test User"

	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	user, err := l.CheckPasswordForSAMAccountName(wantSAMAccountName, "testuser")
	if err != nil {
		t.Error(err)
		return
	}

	if strings.ToLower(user.CN) != strings.ToLower(wantCN) {
		t.Errorf("expected CN %q, got %q", wantCN, user.CN)
	}

	if strings.ToLower(user.SAMAccountName) != strings.ToLower(wantSAMAccountName) {
		t.Errorf("expected CN %q, got %q", wantSAMAccountName, user.SAMAccountName)
	}
}

func TestAuthWithNonexistantUser(t *testing.T) {
	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	_, err = l.CheckPasswordForSAMAccountName("invalidtestuser", "thisshouldfail")
	if err != ErrUserNotFound {
		t.Errorf("expected error %q, got %q", ErrUserNotFound, err)
	}
}

func TestAuthWithInvalidCredentials(t *testing.T) {
	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	_, err = l.CheckPasswordForSAMAccountName("testuser", "thisshouldfail")
	if err == nil {
		t.Errorf("expected error, got %q", err)
	}
}

func getWorkingLdap() (LDAP, error) {
	server, found := os.LookupEnv("LDAP_SERVER")
	if !found {
		return LDAP{}, errors.New("LDAP_SERVER not set")
	}

	baseDN, found := os.LookupEnv("LDAP_BASE_DN")
	if !found {
		return LDAP{}, errors.New("LDAP_BASE_DN not set")
	}

	readUser, found := os.LookupEnv("LDAP_READ_USER")
	if !found {
		return LDAP{}, errors.New("LDAP_READ_USER not set")
	}

	readPassword, found := os.LookupEnv("LDAP_READ_PASSWORD")
	if !found {
		return LDAP{}, errors.New("LDAP_READ_PASSWORD not set")
	}

	return New(server, baseDN, readUser, readPassword), nil
}
