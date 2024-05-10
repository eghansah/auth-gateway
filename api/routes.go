package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/eghansah/auth-gateway/authlib"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/rs/xid"
)

// var STATIC_PATH string
type UserContextkey string

const CTX_USER_KEY UserContextkey = "currentuser"

func (s *Server) InitRoutes() {

	r := chi.NewRouter()

	// allowedDomains := strings.Split(s.cfg.CORSWhiteList, " ")
	// mycors, _ := fcors.AllowAccess(
	// 	fcors.FromOrigins("", allowedDomains...),
	// 	fcors.WithMethods(
	// 		http.MethodGet,
	// 		http.MethodPost,
	// 		http.MethodPut,
	// 		http.MethodDelete,
	// 	),
	// 	fcors.WithRequestHeaders("Authorization"),
	// )
	// r.Use(mycors)

	// A good base middleware stack
	corsMiddleware := cors.New(cors.Options{
		// AllowedOrigins:   strings.Split(s.cfg.CORSWhiteList, " "),
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	r.Use(corsMiddleware.Handler)

	// r.Use(func(next http.Handler) http.Handler {
	// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		w.Header().Set("Content-Type", "text/html; charset=ascii")
	// 		w.Header().Set("Access-Control-Allow-Origin", "*")
	// 		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,access-control-allow-origin, access-control-allow-headers")
	// 		// next.ServeHTTP(w, r)
	// 	})
	// })

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(120 * time.Second))

	STATIC_PATH := fmt.Sprintf("%s/auth/static/", s.cfg.URLPrefix)
	// r.PathPrefix(STATIC_PATH).Handler(http.StripPrefix(STATIC_PATH, http.FileServer(http.Dir("./html"))))

	r.Handle(
		fmt.Sprintf("%s*", STATIC_PATH),
		http.StripPrefix(STATIC_PATH, http.FileServer(http.Dir("./html"))))

	r.Route(fmt.Sprintf("%s/auth", s.cfg.URLPrefix), func(r chi.Router) {

		r.Use(s.CSRFMiddleware)

		r.Get("/static/", func(w http.ResponseWriter, r *http.Request) {
			http.StripPrefix(STATIC_PATH, http.FileServer(http.Dir("./html")))
		})

		r.Get("/services", s.ListServices())
		r.Get("/service/register", s.RegisterService())
		r.Post("/service/register", s.RegisterService())

		r.Get("/register", s.Register())
		r.Post("/register", s.Register())

		r.Get("/login", s.Login())
		r.Post("/login", s.Login())

		r.Get("/logout", s.Logout())

		r.Get("/apikeys", s.GenerateNewSessionKeys())
		r.Get("/whoami", s.WhoAmI())
		r.Get("/profile", s.ProfilePage())

		r.Get("/api/verify_login", s.GetLoggedInUserDetails())
		r.Post("/api/login", s.APILogin())
	})

	r.Route(fmt.Sprintf("%s/auth/apiv2", s.cfg.URLPrefix),
		func(r chi.Router) {
			r.Use(s.ApiKeyRequired)
			// r.Use(s.LoginRequired)

			r.Get("/users/{username}", s.GetUser())
			r.Post("/users", s.RegisterUserViaApi())
			r.Post("/users/{username}/{action}", s.UpdateUser())

			r.Get("/groups/{gid}", s.GetGroup())
			r.Get("/groups", s.Groups())
			r.Post("/groups", s.CreateGroup())

			r.Post("/permissions", s.CreatePermission())
			r.Get("/permissions", s.GetPermissions())
			r.Get("/permissions/{service}", s.GetPermissions())

		})

	s.svr.Handler = r

	// credentials := handlers.AllowCredentials()
	// headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "x-csrf-token"})
	// methods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	// origins := handlers.AllowedOrigins(strings.Split(s.cfg.CORSWhiteList, " "))

	// s.svr.Handler = &r
	// s.svr.Handler = handlers.CORS(credentials, headers, methods, origins)(&r)
}

func (s *Server) createRequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("x-req-id")
		if reqID == "" {
			reqID = xid.New().String()
			r.Header.Add("x-req-id", reqID)
		}

		s.logger.With("x-req-id", reqID).Infof("Received new request: %s", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) LoginRequired(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		if reqID == "" {
			reqID = xid.New().String()
			r.Header.Add("x-req-id", reqID)
		}

		requestLogger := s.logger.With("request-id", reqID)

		requestLogger.Info("Check if sid (session id) cookie exists")
		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's check if session is valid
			requestLogger = requestLogger.With("sid", cookie.Value)
			requestLogger.Info("sid cookie exists. Let's check if session is valid")

			obj, err := s.cache.Get(cookie.Value) //.Int()
			if err != nil {
				requestLogger.Errorf("Error while fetching session id from cache: %s", err)
				// return nil
			}

			uid, err := strconv.ParseInt(obj.Value(), 10, 64)
			if err != nil {
				requestLogger.Errorf("could not convert user id ('%s') to int: %s", obj.Value(), err)
				// return nil
			}

			if err == nil {
				//Session ID is valid
				//Let's fetch user
				requestLogger.Info("Session ID is valid. Let's fetch user")

				user := authlib.User{}
				tx := s.db.Model(authlib.User{}).Where("id = ?", uid).First(&user)
				if tx.Error != nil {
					requestLogger.Error("An error occured while fetching user from db: %s", tx.Error)
				} else {
					//User is valid. Redirect

					//create a new request context containing the authenticated user
					ctxWithUser := context.WithValue(r.Context(), CTX_USER_KEY, user)

					//create a new request using that new context
					rWithUser := r.WithContext(ctxWithUser)

					h.ServeHTTP(w, rWithUser)

					// h.ServeHTTP(w, r)
					return
				}

			}
		}

		loginurl := s.cfg.LoginURL
		redirectURL := fmt.Sprintf("%s?next=%s", loginurl, r.URL.Path)
		requestLogger.Infof("No valid user login session found. Redirecting to login screen: %s", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)

	})
}
