package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/middleware"
)

type myString string

const SERVICE_ID_CONTEXT_KEY myString = "thirdPartyService.ServiceID"

func (svc *server) ApiKeyRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := svc.logger.With("request-id", reqID)

		reqApiKey := r.Header.Get("X-API-KEY")
		if reqApiKey == "" {
			//API-KEY was not provided
			requestLogger.Info("API Key not provided")
			errorJSON(w, fmt.Errorf("API Key not provided"), http.StatusBadRequest)
			return
		}

		//Checking for validity of API-KEY
		thirdPartyService := Service{}
		tx := svc.db.Model(Service{}).Where("enabled=1 and api_key = ?", reqApiKey).First(&thirdPartyService)
		if tx.Error != nil {
			requestLogger.Info(tx.Error)
			errMsg := fmt.Errorf("could not find any active service using the API Key provided")

			requestLogger.Infof("Could not find any active service using the API key provided")

			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		ctx := context.WithValue(r.Context(),
			SERVICE_ID_CONTEXT_KEY, thirdPartyService.ServiceID)
		newReq := r.WithContext(ctx)

		next.ServeHTTP(w, newReq)
	})
}

// func (svc *server) LoginRequired(h http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

// 		// ctx := context.Background()
// 		redirectURL := svc.cfg.LoginURL
// 		resp := JSONResponse{
// 			Error:   true,
// 			Message: "user not logged in",
// 			Data:    svc.cfg.LoginURL,
// 		}

// 		reqID := middleware.GetReqID(r.Context())
// 		requestLogger := svc.logger.With("request-id", reqID)

// 		requestLogger.Info("Check if sid (session id) cookie exists")
// 		cookie, err := r.Cookie("sid")
// 		if err != nil {
// 			requestLogger.Errorf("Error occured while fetching sid cookie: %s", err)
// 			requestLogger.Infof("sid cookie not found. Redirecting to login screen: %s", redirectURL)
// 			writeJSON(w, http.StatusUnauthorized, resp)
// 			return
// 		}

// 		//sid cookie exists. let's fetch user
// 		requestLogger.Info("sid cookie exists. Let's fetch user")

// 		cacheEntry, err := svc.cache.Get(cookie.Value)
// 		if cacheEntry == nil {
// 			requestLogger.Errorf("Error occured while fetching user json from cache: %s", err)
// 			requestLogger.Infof("Error occured while fetching user from cache. Redirecting to login screen: %s", redirectURL)
// 			writeJSON(w, http.StatusUnauthorized, resp)
// 			return
// 		}

// 		userJSON := cacheEntry.Value()

// 		// userJSON, err := s.cache.Get(ctx, cookie.Value).Result()
// 		if err != nil {
// 			requestLogger.Errorf("Error occured while fetching user json from cache: %s", err)
// 			requestLogger.Infof("Error occured while fetching user from cache. Redirecting to login screen: %s", redirectURL)
// 			writeJSON(w, http.StatusUnauthorized, resp)
// 			return
// 		}

// 		user := authlib.User{}
// 		err = json.Unmarshal([]byte(userJSON), &user)
// 		if err != nil {
// 			requestLogger.Errorf("Could not parse user json: %s", err)
// 			requestLogger.Infof("Could not parse user JSON. Redirecting to login screen: %s", redirectURL)
// 			writeJSON(w, http.StatusUnauthorized, resp)
// 			return
// 		}

// 		//User is valid.

// 		//create a new request context containing the authenticated user
// 		ctxWithUser := context.WithValue(r.Context(), CTX_USER_KEY, user)

// 		//create a new request using that new context
// 		rWithUser := r.WithContext(ctxWithUser)

// 		h.ServeHTTP(w, rWithUser)

// 	})
// }
