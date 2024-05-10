package auth_methods

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/eghansah/auth-gateway/authlib"
	"go.uber.org/zap"
	"gopkg.in/ldap.v2"
)

func AuthenticateAgainstLDAP() authlib.AuthenticationMethod {
	return func(logger *zap.SugaredLogger, user authlib.User, lr authlib.LoginRequest) (*authlib.User, error) {

		ldapDomain := os.Getenv("AUTH_LDAP_DOMAIN")
		ldapIP := os.Getenv("AUTH_LDAP_SERVER_IP")
		ldapSupportsTLS := os.Getenv("AUTH_LDAP_SERVER_SUPPORTS_TLS")
		baseDN := os.Getenv("AUTH_BASE_DN")

		domainUsername := fmt.Sprintf("%s@%s", lr.Username, ldapDomain)
		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapIP, 389))
		if err != nil {
			logger.Errorf("Could not connet to LDAP server: %s\n", err)
			return nil, fmt.Errorf("could not connect to LDAP Server")
		}
		defer l.Close()

		if ldapSupportsTLS == "1" {
			// Reconnect with TLS
			err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				logger.Errorf("Could not connet to LDAP server wuth TLS: %s\n", err)
				return nil, err
			}
		}

		// First bind with a read only user
		err = l.Bind(domainUsername, lr.Password)
		if err != nil {
			logger.Errorf("LDAP bind failed: %s", err)
			return nil, err
		}

		// Search for the given username
		searchRequest := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
			fmt.Sprintf("(&(objectClass=person)(sAMAccountName=%s))", lr.Username),
			[]string{"dn", "mail", "displayName", "distinguishedName", "surName", "givenName", "sn"},
			//[]string{""},
			nil,
		)

		sr, err := l.Search(searchRequest)
		if err != nil {
			logger.Infof("%s: LDAP search returned an error: %s\n", err)
			return nil, err
		}

		logger.Infof("search results.1 => %+v\n", sr.Entries[0])
		logger.Infof("search results.2 => FirstName: %s\nLastName: %s\nOthers:%s\n\n",
			sr.Entries[0].GetAttributeValue("givenName"),
			sr.Entries[0].GetAttributeValue("surName"), sr.Entries[0].GetAttributeValue("sn"))

		if len(sr.Entries) != 1 {
			logger.Infof("%s: User with username '%s' does not exist or too many entries returned\n", lr.Username)
			return nil, fmt.Errorf("invalid username or password")
		}

		u := user.Clone()

		u.Email = sr.Entries[0].GetAttributeValue("mail")
		u.Email = strings.Trim(u.Email, " ")
		u.Email = strings.ToLower(u.Email)

		u.FullName = sr.Entries[0].GetAttributeValue("displayName")
		u.Username = lr.Username

		u.Firstname = sr.Entries[0].GetAttributeValue("givenName")
		u.Lastname = sr.Entries[0].GetAttributeValue("sn")

		u.AuthenticationSystem = "ldap"
		u.ID = user.ID

		return &u, nil
	}
}
