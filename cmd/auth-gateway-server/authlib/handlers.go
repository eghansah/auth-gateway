package authlib

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/xid"
)

func (s *Handlers) LoginRequestCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestLogger := s.logger.With(
			"Function Name", "LoginRequestCallbackHandler",
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

		//Login succesful. Let's generate session id
		requestLogger.Info("Login succesful. Let's save user and generate session id")

		sessionID := xid.New()
		requestLogger = requestLogger.With("sid", sessionID)

		requestLogger.Info("Saving session id")
		usr, _ := json.Marshal(u)
		s.cache.Set(sessionID.String(), string(usr), SESSION_EXPIRY)
		// s.cache.Set(ctx, sessionID.String(), *u, SESSION_EXPIRY)

		expire := time.Now().Add(5 * time.Minute)
		c := http.Cookie{
			Name:     "sid",
			Value:    sessionID.String(),
			HttpOnly: true,
			Path:     s.CookiePath,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			Expires:  expire,
		}
		requestLogger.With("cookie", c).Info("Requesting browser to save cookie")
		http.SetCookie(w, &c)

		requestLogger.With("homepage_url", s.homePageURL).
			Info("Redirecting user to homepage")
		http.Redirect(w, r, s.homePageURL, http.StatusTemporaryRedirect)
	}
}

func (s *Handlers) Logout() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With(
			"request-id", reqID,
			"handler", "Logout",
			"Function Name", "Logout",
			"endpoint", r.URL.Path,
			"request-method", r.Method,
		)

		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's delete it
			requestLogger.Info("Deleting cookie")
			s.cache.Delete(cookie.Value)
		}

		//Check if sid exists in cache
		// if s.cache.Exists(session.SID).Val() == 0 {

		resp := JSONResponse{}
		resp.Error = false
		resp.Message = "User Logged Out Successfully"

		expire := time.Now().Add(-72 * time.Hour) //setting to a time in the past
		c := http.Cookie{
			Name:     "sid",
			Value:    "",
			HttpOnly: true,
			Path:     s.CookiePath,
			SameSite: http.SameSiteStrictMode,
			Secure:   true,
			Expires:  expire,
		}
		requestLogger.Info("Requesting browser to save expired cookie (effectively a deletion)")
		http.SetCookie(w, &c)

		// writeJSON(w, http.StatusOK, resp)
		// }
	}
}
