package main

import (
	"fmt"
	"os"
	"time"

	"github.com/eghansah/auth-gateway/api"
	"github.com/eghansah/auth-gateway/api/auth_methods"
	"github.com/eghansah/auth-gateway/authlib"
	"github.com/eghansah/auth-gateway/utils"
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

	MANDATORY_ENV_VARS := []string{}

	viper.AutomaticEnv()
	viper.SetDefault("SESSION_EXPIRY", 300)

	for _, k := range MANDATORY_ENV_VARS {
		if !viper.IsSet(k) {
			panic(fmt.Sprintf("'%s' environment variable needs to be set", k))
		}
	}

	//Bind env vars
	for _, k := range utils.GetMapstructureTags(api.Config{}) {
		viper.BindEnv(k, k)
	}

	s := api.Server{
		SupportedAuthenticationMethods: make(map[string]authlib.AuthenticationMethod),
	}
	cfg := api.Config{
		Host:              "127.0.0.1",
		Port:              9000,
		SessionDuration:   5 * time.Minute,
		LoginURL:          "http://127.0.0.1:9000/auth/login",
		SubDirectory:      "/auth",
		SaveLoginSessions: false,
	}
	err := viper.Unmarshal(&cfg)
	if err != nil {
		panic(err)
	}

	s.Init(cfg)
	s.AddAuthenticationMethod("local", s.AuthenticateAgainstLocalDB())
	s.AddAuthenticationMethod("ldap", auth_methods.AuthenticateAgainstLDAP())
	s.Run()
}
