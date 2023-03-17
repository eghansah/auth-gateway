package main

import (
	"fmt"
	"os"

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
		"DBHOST",
		"DBPORT",
		"DBUSER",
		"DBPASSWD",
		"DBNAME",
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

	s := server{}
	cfg := config{}
	err := viper.Unmarshal(&cfg)
	if err != nil {
		panic(err)
	}

	s.Init(cfg)
	s.addAuthenticationMethod("local", s.authenticateAgainstLocalDB())
	s.addAuthenticationMethod("ldap", auth_methods.AuthenticateAgainstLDAP())
	s.Run()
}
