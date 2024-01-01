package authlib

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/lafriks/ttlcache/v3"
	"go.uber.org/zap"
)

type UserContextkey string

const SESSION_EXPIRY = 5 * time.Minute
const CTX_USER_KEY UserContextkey = "currentuser"

type AuthGateway struct {
	Middlewares Middlewares
	Handlers    Handlers
	// whoAmIURL string
	logger *zap.SugaredLogger
	cache  *ttlcache.Cache[string, string]
}

type Middlewares struct {
	loginPageURL string
	serviceID    string
	logger       *zap.SugaredLogger
	cache        *ttlcache.Cache[string, string]
}

type Handlers struct {
	loginPageURL string
	homePageURL  string
	whoAmIURL    string
	apikey       string
	serviceID    string
	CookiePath   string
	logger       *zap.SugaredLogger
	cache        *ttlcache.Cache[string, string]
}

type AuthGatewayOption struct {
	Logger      *zap.SugaredLogger
	RedisURL    string
	LoginURL    string
	WhoAmIURL   string
	HomePageURL string
	APIKey      string
	ServiceID   string
	Secret      string
	CookiePath  string
}

func NewAuthGateway(o AuthGatewayOption) (*AuthGateway, error) {
	if o.LoginURL == "" {
		return nil, fmt.Errorf("login_url must be specified in AuthGatewayOption")
	}

	if o.WhoAmIURL == "" {
		return nil, fmt.Errorf("whoami_url must be specified in AuthGatewayOption")
	}

	if o.CookiePath == "" {
		o.CookiePath = "/"
	}

	if o.Logger == nil {
		logger, err := zap.NewProduction()
		if err != nil {
			return nil, err
		}
		o.Logger = logger.Sugar()
	}

	if o.RedisURL == "" {
		return nil, fmt.Errorf("a valid redis url must be provided in AuthGatewayOption")
	}

	//redis://<user>:<pass>@localhost:6379/<db>
	// opt, err := redis.ParseURL(o.RedisURL)
	// if err != nil {
	// 	return nil, fmt.Errorf("auth_gateway_lib could not parse RedisURL provided: %s", err)
	// }

	// rdb := redis.NewClient(opt)
	rdb := ttlcache.New[string, string]()

	return &AuthGateway{
		logger: o.Logger,
		cache:  rdb,
		Middlewares: Middlewares{
			loginPageURL: o.LoginURL,
			cache:        rdb,
			logger:       o.Logger,
			serviceID:    o.ServiceID,
		},
		Handlers: Handlers{
			loginPageURL: o.LoginURL,
			whoAmIURL:    o.WhoAmIURL,
			homePageURL:  o.HomePageURL,
			apikey:       o.APIKey,
			serviceID:    o.ServiceID,
			cache:        rdb,
			logger:       o.Logger,
			CookiePath:   o.CookiePath,
		}}, nil
}

func (h *Handlers) GetUser(tk string) (*User, error) {

	u := User{}
	requestLogger := h.logger

	requestLogger.Debug("Constructing request to fetch details of logged in user . . .")
	req, err := http.NewRequest("GET", h.whoAmIURL, nil)
	if err != nil {
		requestLogger.Error("Error occured while creating get request to fetch details of logged in user: %s", err)
		return nil, fmt.Errorf("Error creating user request: %s", err)
	}

	req.Header.Add("X-API-KEY", h.apikey)

	whoAmIURL, _ := url.Parse(h.whoAmIURL)
	q := whoAmIURL.Query()
	q.Set("tk", tk)
	q.Set("service", h.serviceID)
	req.URL.RawQuery = q.Encode()

	fmt.Printf("\nMaking WhoAmI request: %s\n\n", req.URL.RawQuery)

	requestLogger.With(
		"tk", tk,
		"target", h.whoAmIURL,
		"raw-url", req.URL.String(),
	).Debug("Initiating request to fetch details of logged in user . . .")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		requestLogger.With(
			"error", err,
			"url_called", req.URL.String(),
		).Error("Errored when sending request to the server")

		return nil, fmt.Errorf("failed to fetch details of newly logged in user")
	}

	defer resp.Body.Close()
	resp_body, _ := io.ReadAll(resp.Body)

	requestLogger.Info("Auth server has responded")
	requestLogger.Info("resp_body => %s", string(resp_body))

	err = json.Unmarshal(resp_body, &u)
	if err != nil {
		requestLogger.With(
			"error", err,
			"url_called", req.URL.String(),
		).Error("Could not parse response ")

		return nil, fmt.Errorf("failed to fetch details of newly logged in user")
	}

	requestLogger.Info("Parsed Auth server response")
	return &u, nil
}

func (s *Middlewares) LoginRequired(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// ctx := context.Background()
		redirectURL := struct {
			URL string
		}{
			URL: fmt.Sprintf("%s?service=%s&next=%s%s", s.loginPageURL, s.serviceID, os.Getenv("URL_PREFIX"), r.URL.Path),
		}
		resp := JSONResponse{
			Error:   true,
			Message: "user not logged in",
			Data:    redirectURL,
		}

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

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

		cacheEntry, err := s.cache.Get(cookie.Value)
		if cacheEntry == nil {
			requestLogger.Errorf("Error occured while fetching user json from cache: %s", err)
			requestLogger.Infof("Error occured while fetching user from cache. Redirecting to login screen: %s", redirectURL)
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		userJSON := cacheEntry.Value()

		// userJSON, err := s.cache.Get(ctx, cookie.Value).Result()
		if err != nil {
			requestLogger.Errorf("Error occured while fetching user json from cache: %s", err)
			requestLogger.Infof("Error occured while fetching user from cache. Redirecting to login screen: %s", redirectURL)
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		user := User{}
		err = json.Unmarshal([]byte(userJSON), &user)
		if err != nil {
			requestLogger.Errorf("Could not parse user json: %s", err)
			requestLogger.Infof("Could not parse user JSON. Redirecting to login screen: %s", redirectURL)
			writeJSON(w, http.StatusUnauthorized, resp)
			return
		}

		//User is valid.

		//create a new request context containing the authenticated user
		ctxWithUser := context.WithValue(r.Context(), CTX_USER_KEY, user)

		//create a new request using that new context
		rWithUser := r.WithContext(ctxWithUser)

		h.ServeHTTP(w, rWithUser)

	})
}

func (s *Middlewares) AddLoggedInUserDetails(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With("request-id", reqID)

		requestLogger.Info("Check if sid (session id) cookie exists")
		cookie, err := r.Cookie("sid")
		if err != nil {
			requestLogger.Errorf("Error occured while fetching sid cookie: %s", err)
			requestLogger.Info("Continue without adding logged in user info")
			h.ServeHTTP(w, r)
			return
		}

		//sid cookie exists. let's fetch user
		requestLogger.Info("sid cookie exists. Let's fetch user")

		cacheEntry, err := s.cache.Get(cookie.Value)
		if cacheEntry == nil {
			// requestLogger.Errorf("Error occured while fetching user json from cache: %s", err)
			requestLogger.Info("Continue without adding logged in user info")
			h.ServeHTTP(w, r)
			return
		}

		userJSON := cacheEntry.Value()
		if err != nil {
			requestLogger.Errorf("Error occured while fetching user json from cache: %s", err)
			requestLogger.Info("Continue without adding logged in user info")
			h.ServeHTTP(w, r)
			return
		}

		user := User{}
		err = json.Unmarshal([]byte(userJSON), &user)
		if err != nil {
			requestLogger.Errorf("Could not parse user json: %s", err)
			requestLogger.Info("Continue without adding logged in user info")
			h.ServeHTTP(w, r)
			return
		}

		//User is valid.

		//create a new request context containing the authenticated user
		ctxWithUser := context.WithValue(r.Context(), CTX_USER_KEY, user)

		//create a new request using that new context
		rWithUser := r.WithContext(ctxWithUser)

		h.ServeHTTP(w, rWithUser)

	})
}
