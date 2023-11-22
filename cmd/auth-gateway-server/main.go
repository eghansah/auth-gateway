package main

import (
	"fmt"
	"os"

	"github.com/eghansah/auth-gateway/authlib"
	"github.com/eghansah/auth-gateway/cmd/auth-gateway-server/auth_methods"
	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/spf13/viper"
)

func createService() {
	seviceID := xid.New().String()
	apiKey := uuid.New().String()
	fmt.Printf("\nService ID: %s\nAPI-KEY: %s\n", seviceID, apiKey)
}

func main() {

	//Check if user wants to run some other command
	if len(os.Args) > 1 && os.Args[1] == "generate-ids" {
		createService()
		return
	}

	MANDATORY_ENV_VARS := []string{
		// "AUTH_HOST",
		// "AUTH_PORT",
		// "AUTH_URL_PREFIX",
		// "AUTH_REDIS_SERVER",
		// "AUTH_SESSION_EXPIRY",
		// "AUTH_CSRF_KEY",
		// "AUTH_ENABLE_OTP",

		// "AUTH_LDAP_DOMAIN",
		// "AUTH_LDAP_SERVER_IP",
		// "AUTH_DBHOST",
		// "AUTH_DBPORT",
		// "AUTH_DBUSER",
		// "AUTH_DBPASSWD",
		// "AUTH_DBNAME",
		// "AUTH_CORS_ORIGIN_WHITELIST",
	}

	viper.AutomaticEnv()
	viper.SetDefault("SESSION_EXPIRY", 300)

	for _, k := range MANDATORY_ENV_VARS {
		if !viper.IsSet(k) {
			panic(fmt.Sprintf("'%s' environment variable needs to be set", k))
		}
	}

	//Bind env vars
	for _, k := range GetMapstructureTags(config{}) {
		viper.BindEnv(k, k)
	}

	s := server{
		supportedAuthenticationMethods: make(map[string]authlib.AuthenticationMethod),
	}
	cfg := config{
		Host: "127.0.0.1",
		Port: 9000,
	}
	err := viper.Unmarshal(&cfg)
	if err != nil {
		panic(err)
	}

	s.Init(cfg)
	s.addAuthenticationMethod("local", s.authenticateAgainstLocalDB())
	s.addAuthenticationMethod("ldap", auth_methods.AuthenticateAgainstLDAP())
	s.Run()
}
