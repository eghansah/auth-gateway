package authlib

import (
	"fmt"
	"net/http"

	"github.com/eghansah/auth-gateway/utils"
	"github.com/go-chi/chi/middleware"
)

type NewUserLoginHandlerFunc func(loggedInUser *User) error

func (s *Handlers) LoginRequestCallbackHandler_v2(fn NewUserLoginHandlerFunc, redirectUrl string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestLogger := s.logger.With(
			"Function Name", "LoginRequestCallbackHandler",
			"request-id", middleware.GetReqID(r.Context()),
			"endpoint", r.URL.Path)

		requestLogger.Debug("Checking for tk parameter. . .")
		qs := r.URL.Query()
		if _, ok := qs["tk"]; !ok {
			//One time user token was not provided
			errorJSON(w, fmt.Errorf("one time user auth token not provided"), http.StatusBadRequest)
			return
		}

		u, err := s.GetUser(qs["tk"][0])
		if err != nil || u.GUID == "" {
			//No active session found.
			requestLogger.Info("No active session found. Redirecting to homepage . . .")
			http.Redirect(w, r, s.homePageURL, http.StatusTemporaryRedirect)
			return
		}

		//Login succesful. Calling function to save user details
		requestLogger.Info("Login succesful. Let's save user and generate session id")
		err = fn(u)
		if err != nil {
			//No active session found.
			requestLogger.With("err", err).Error("Error occured while saving new session")
			utils.ErrorJSON(w, fmt.Errorf("error occured while saving new session"), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
	}
}
