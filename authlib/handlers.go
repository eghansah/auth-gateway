package authlib

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/rs/xid"
)

func (s *Handlers) LoginRequestCallbackHandler() http.HandlerFunc {
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

		//Login succesful. Let's generate session id
		requestLogger.Info("Login succesful. Let's save user and generate session id")

		sessionID := xid.New()
		requestLogger = requestLogger.With("sid", sessionID)

		requestLogger.Info("Saving session id")
		usr, _ := json.Marshal(u)
		// s.cache.Set(ctx, sessionID.String(), string(usr), SESSION_EXPIRY)
		s.cache.Set(sessionID.String(), string(usr), SESSION_EXPIRY)

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
		requestLogger.Info("Requesting browser to save cookie")
		http.SetCookie(w, &c)

		http.Redirect(w, r, s.homePageURL, http.StatusTemporaryRedirect)
	}
}

func (s *Handlers) Logout() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestLogger := s.logger.With(
			"request-id", middleware.GetReqID(r.Context()),
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

		writeJSON(w, http.StatusOK, resp)
		// }
	}
}

func (svc *Handlers) Refresh() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestLogger := svc.logger.With("function name", "Refresh")

		redirectURL := struct {
			URL string
		}{
			URL: fmt.Sprintf("%s?service=%s&next=%s%s",
				svc.loginPageURL,
				svc.serviceID, os.Getenv("URL_PREFIX"), r.URL.Path),
		}
		resp := JSONResponse{
			Error:   true,
			Message: "user not logged in",
			Data:    redirectURL,
		}

		requestLogger.Info("Check if sid (session id) cookie exists")
		cookie, err := r.Cookie("sid")
		if err != nil {
			requestLogger.Errorf("Error occured while fetching sid cookie: %s", err)
			requestLogger.Infof("sid cookie not found. Redirecting to login screen: %s", redirectURL)
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		//sid cookie exists. let's fetch user
		requestLogger.Info("sid cookie exists. Let's fetch user")

		cacheEntry, err := svc.cache.Get(cookie.Value)
		if cacheEntry == nil {
			requestLogger.Errorf("Error occured while fetching user json from cache: %s", err)
			requestLogger.Infof("Error occured while fetching user from cache. Redirecting to login screen: %s", redirectURL)
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		userJSON := cacheEntry.Value()

		user := User{}
		err = json.Unmarshal([]byte(userJSON), &user)
		if err != nil {
			requestLogger.Errorf("Could not parse user json: %s", err)
			requestLogger.Infof("Could not parse user JSON. Redirecting to login screen: %s", redirectURL)
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := &http.Client{Transport: tr}
		usrURL := fmt.Sprintf("%s/%s", svc.userRefreshURL, user.Username)

		authgwResp, err := client.Get(usrURL)
		if err != nil {
			requestLogger.With("err", err).Error("could not initiate request to auth gateway")
			resp.Message = "could not initiate request to auth gateway"
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		gwRsp, err := io.ReadAll(authgwResp.Body)
		if err != nil {
			requestLogger.With("err", err).Error("could not read auth gateway response")
			resp.Message = "could not read auth gateway response"
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		err = json.Unmarshal(gwRsp, &user)
		if err != nil {
			requestLogger.With("err", err).Error("could not parse auth gateway response")
			resp.Message = "could not parse auth gateway response"
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		newUserJSON, err := json.Marshal(user)
		if err != nil {
			requestLogger.With("err", err).Error("could not serialize auth gateway response")
			resp.Message = "could not serialize auth gateway response"
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		//Update cache with new user roles
		svc.cache.Set(cookie.Value, string(newUserJSON), time.Duration(svc.sessionExpiry))

		resp.Error = false
		resp.Message = "User roles refreshed"
		resp.Data = user
		writeJSON(w, http.StatusOK, resp)

	}
}
