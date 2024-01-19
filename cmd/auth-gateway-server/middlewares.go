package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/middleware"
)

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

		next.ServeHTTP(w, r)
	})
}
