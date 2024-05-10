package api

import (
	"fmt"

	"github.com/eghansah/auth-gateway/authlib"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) AuthenticateAgainstLocalDB() authlib.AuthenticationMethod {
	return func(logger *zap.SugaredLogger, user authlib.User, lr authlib.LoginRequest) (*authlib.User, error) {

		if user.AuthenticationSystem != authlib.LOCAL_DB_AUTH {
			return nil, fmt.Errorf("specified auth is not local auth")
		}

		//User has been set to use local auth. Check password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(lr.Password)); err != nil {
			// expectedHash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
			// providedHash, _ := bcrypt.GenerateFromPassword([]byte(reqMap["password"]), 14)
			logger.Info("Password does not match stored password. Aborting login request.\n")

			return nil, fmt.Errorf("incorrect username or password")
		}

		u := user.Clone()
		return &u, nil
	}
}
