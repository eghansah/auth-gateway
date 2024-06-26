package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"

	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/eghansah/auth-gateway/authlib"
	"github.com/eghansah/auth-gateway/utils"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/lafriks/ttlcache/v3"
	"github.com/natefinch/lumberjack"
	"github.com/rs/xid"
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	_ "github.com/sijms/go-ora/v2"
)

type Config struct {
	Host                  string        `mapstructure:"AUTH_HOST"`
	Port                  int           `mapstructure:"AUTH_PORT"`
	URLPrefix             string        `mapstructure:"AUTH_URL_PREFIX"`
	RedisServer           string        `mapstructure:"AUTH_REDIS_SERVER"`
	SessionDuration       time.Duration `mapstructure:"AUTH_SESSION_EXPIRY"`
	CSRFKey               string        `mapstructure:"AUTH_CSRF_KEY"`
	EnableTOTP            bool          `mapstructure:"AUTH_ENABLE_OTP"`
	Domain                string        `mapstructure:"AUTH_LDAP_DOMAIN"`
	LdapServerIP          string        `mapstructure:"AUTH_LDAP_SERVER_IP"`
	LdapServerSupportsTLS int           `mapstructure:"AUTH_LDAP_SERVER_SUPPORTS_TLS"`
	DBHost                string        `mapstructure:"AUTH_DBHOST"`
	DBPort                int           `mapstructure:"AUTH_DBPORT"`
	DBUser                string        `mapstructure:"AUTH_DBUSER"`
	DBPassword            string        `mapstructure:"AUTH_DBPASSWD"`
	DBName                string        `mapstructure:"AUTH_DBNAME"`
	DBType                string        `mapstructure:"AUTH_DB_TYPE"`
	CORSWhiteList         string        `mapstructure:"AUTH_CORS_ORIGIN_WHITELIST"`
	SubDirectory          string        `mapstructure:"AUTH_SUBDIRECTORY"`
	LoginURL              string        `mapstructure:"LOGIN_URL"`
	SaveLoginSessions     bool          `mapstructure:"SAVE_LOGIN_SESSIONS"`
	LogLevel              string
}

type Server struct {
	db  *gorm.DB
	svr *http.Server
	cfg Config
	// router                         *mux.Router
	cache                          *ttlcache.Cache[string, string]
	CSRFMiddleware                 func(http.Handler) http.Handler
	logger                         *zap.SugaredLogger
	SupportedAuthenticationMethods map[string]authlib.AuthenticationMethod
}

const STATIC_PATH = "/auth/static/"
const API_LOGIN_URL = "/auth/api/login"
const API_WHOAMI_URL = "/auth/whoami"
const PROFILE_URL = "/auth/profile"

func (s *Server) AddAuthenticationMethod(authMethodCode string, authMethod authlib.AuthenticationMethod) {
	s.SupportedAuthenticationMethods[authMethodCode] = authMethod
}

func (s *Server) authenticateUser(logger *zap.SugaredLogger, user authlib.User, lr authlib.LoginRequest) (*authlib.User, error) {
	authMethod, ok := s.SupportedAuthenticationMethods[user.AuthenticationSystem]
	if !ok {
		//Auth method not supported
		return nil, fmt.Errorf("authentication method not supported")
	}

	return authMethod(logger, user, lr)
}

func (s *Server) sendPasswordResetEmail(r *http.Request, to *mail.Email,
	resetReq PasswordResetRequest) (*rest.Response, error) {
	from := mail.NewEmail("support", viper.GetString("SUPPORT_EMAIL"))
	subject := "Password Reset"
	passwordResetLink := fmt.Sprintf("https://%s/change-password/%s", r.Host, resetReq.ResetCode)
	plainTextContent := fmt.Sprintf(`Dear %s,
	To complete your password reset, kindly copy and paste the link below in your browser. 
	Kindly note that the link expires in 60 minutes.
	%s
	
	Please ignore this email if you did not request for the reset.
	
	
	Thank you`, to.Name, passwordResetLink)

	var buf bytes.Buffer
	data := struct {
		PasswordResetLink string
	}{
		PasswordResetLink: passwordResetLink,
	}
	tmpl := template.Must(template.ParseFiles("html/forgot_password_email.html"))
	tmpl.Execute(&buf, data)
	htmlContent := buf.String()
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))

	return client.Send(message)
}

func (s *Server) getUser(reqID, sessionID string) *authlib.User {

	// pc, _, _, _ := runtime.Caller(1)
	// details := runtime.FuncForPC(pc)

	requestLogger := s.logger.With("request-id", reqID, "session-id", sessionID)

	//sid cookie exists. Let's check if session is valid
	requestLogger.Info("Let's check if session is valid")

	obj, err := s.cache.Get(sessionID) //.Int()
	if err != nil {
		requestLogger.Info("Error while fetching session id from cache: %s", err)
		return nil
	}

	if obj == nil {
		requestLogger.Infof("No user found with session id '%s'. Session may have expired", sessionID)
		return nil
	}

	uid, err := strconv.ParseInt(obj.Value(), 10, 64)
	if err != nil {
		requestLogger.Errorf("could not convert user id ('%s') to int: %s", obj.Value(), err)
		return nil
	}

	//Session ID is valid
	//Let's fetch user
	requestLogger.Info("Session ID is valid. Let's fetch user")

	user := authlib.User{}
	tx := s.db.Model(authlib.User{}).Where("id = ?", uid).First(&user)
	if tx.Error != nil {
		requestLogger.Errorf("An error occured while fetching user from db: %s", tx.Error)
		return nil
	}

	requestLogger.Info("User found. Returning user")
	return &user
}

func (s *Server) InitLogger() {
	writeSyncer := s.getLogWriter()
	syncer := zap.CombineWriteSyncers(os.Stdout, writeSyncer)
	encoder := s.getEncoder()
	core := zapcore.NewCore(encoder, syncer, zapcore.DebugLevel)
	// Print function lines
	logger := zap.New(core, zap.AddCaller())
	s.logger = logger.Sugar()
}

func (s *Server) getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	// The format time can be customized
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

// Save file log cut
func (s *Server) getLogWriter() zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   "./logs/auth.log", // Log name
		MaxSize:    1,                 // File content size, MB
		MaxBackups: 5,                 // Maximum number of old files retained
		MaxAge:     30,                // Maximum number of days to keep old files
		Compress:   false,             // Is the file compressed
	}
	return zapcore.AddSync(lumberJackLogger)
}

func (s *Server) Init(c Config) {
	s.cfg = c
	// fmt.Printf("config => %+v\n\n", s.cfg)

	s.InitLogger()

	csrfSecure := true
	if viper.GetBool("AUTH_DEBUG") {
		csrfSecure = false
	}
	_ = csrfSecure
	s.CSRFMiddleware = csrf.Protect([]byte(s.cfg.CSRFKey),
		csrf.Secure(true),
		csrf.Path("/"),
		csrf.TrustedOrigins(viper.GetStringSlice("AUTH_CORS_ORIGIN_WHITELIST")),
		// instruct the browser to never send cookies during cross site requests
		csrf.SameSite(csrf.SameSiteNoneMode),
	)

	// w.Header().Set("Vary", "Origin")
	// w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	// w.Header().Set("Access-Control-Allow-Credentials", "true")
	// w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	// w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

	s.svr = &http.Server{
		Addr: fmt.Sprintf("%s:%d", c.Host, c.Port),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}

	s.cache = ttlcache.New[string, string](
		ttlcache.WithTTL[string, string](s.cfg.SessionDuration),
	)
	go s.cache.Start() // starts automatic expired item deletion

	var db *gorm.DB
	var err error
	switch strings.TrimSpace(strings.ToLower(s.cfg.DBType)) {
	case "mssql":
		fallthrough
	case "sqlserver":
		var err error

		s.logger.Info("Initiating sqlserver DB connection . . .")
		query := url.Values{}
		query.Add("database", s.cfg.DBName)
		query.Add("parseTime", "True")
		query.Add("loc", "Local")

		dsn := &url.URL{
			Scheme: "sqlserver",
			User:   url.UserPassword(s.cfg.DBUser, s.cfg.DBPassword),
			Host:   fmt.Sprintf("%s:%d", s.cfg.DBHost, s.cfg.DBPort),
			// Path:  instance, // if connecting to an instance instead of a port
			RawQuery: query.Encode(),
		}

		db, err = gorm.Open(sqlserver.Open(dsn.String()), &gorm.Config{
			NamingStrategy: schema.NamingStrategy{
				TablePrefix: "auth_",
			},
		})
		if err != nil {
			panic(err)
		}

		if err != nil {
			log.Printf("Unable to initialize db connection: %s\n", err.Error())
			panic(err)
		}

	case "mysql":
		s.logger.Info("Initiating MySQL DB connection . . .")
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			s.cfg.DBUser, s.cfg.DBPassword, s.cfg.DBHost, s.cfg.DBPort, s.cfg.DBName)
		// fmt.Println(dsn)
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
			NamingStrategy: schema.NamingStrategy{
				TablePrefix: "auth_",
			},
		})

	default:
		s.logger.Info("Initiating SQlite DB connection . . .")
		db, err = gorm.Open(sqlite.Open("mdb.db"), &gorm.Config{})
	}

	if err != nil {
		log.Fatalf("Unable to initialize db connection: %s\n", err.Error())
	}

	s.db = db

	s.MigrateDB()
	s.InitRoutes()

}

func (s *Server) Run() {
	mode := "PRODUCTION"
	if viper.GetBool("DEBUG") {
		mode = "DEV"
	}
	s.logger.Infof("Server running in %s mode at http://%s:%d/", mode, s.cfg.Host, s.cfg.Port)
	s.logger.Infof("CORS WHITELISTED ORIGINS: %v", strings.Split(s.cfg.CORSWhiteList, " "))
	s.svr.ListenAndServe()
}

func (s *Server) Register() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)
		tmpl := template.Must(template.ParseFiles("html/register.html"))

		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's check if session is valid

			obj, err := s.cache.Get(cookie.Value) //.Int()
			if err != nil {
				requestLogger.Errorf("Error while fetching session id from cache: %s", err)
				// return nil
			}

			fmt.Printf("obj => %+v\n", obj)
			if obj != nil {
				uid, err := strconv.ParseInt(obj.Value(), 10, 64)
				if err != nil {
					requestLogger.Errorf("could not convert user id ('%s') to int: %s", obj.Value(), err)
					// return nil
				}

				if err == nil {
					//Session ID is valid
					//Let's fetch user
					user := authlib.User{}
					tx := s.db.Model(authlib.User{}).Where("id = ?", uid).First(&user)
					if tx.Error != nil {
						requestLogger.Errorf("Error occured while fetching user with id '%d' from db: %s", uid, tx.Error)
					} else {
						//User is valid. Redirect
						s.redirectAfterSuccessfulLogin(w, r, cookie, &user)
						return
					}

				}
			}
		}

		if r.Method == "GET" {
			tmpl.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
			})
			return
		}

		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = io.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewBuffer(rawReqBody))

		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		//Check for required params
		required := []string{"email", "password"}
		for _, rq := range required {
			if _, ok := reqMap[rq]; !ok {
				tmpl.Execute(w, map[string]interface{}{
					csrf.TemplateTag: csrf.TemplateField(r),
					"msg":            fmt.Sprintf("Required parameter missing: %s", rq),
				})
				return
			}
		}

		passwd, _ := bcrypt.GenerateFromPassword([]byte(reqMap["password"]), 14)
		u := &authlib.User{
			Firstname:            reqMap["firstname"],
			Lastname:             reqMap["lastname"],
			Email:                reqMap["email"],
			Username:             reqMap["email"],
			Password:             passwd,
			SID:                  xid.New().String(),
			GUID:                 uuid.New().String(),
			AuthenticationSystem: "local",
		}

		tx := s.db.Create(u)
		if tx.Error != nil {
			log.Println(tx.Error)
			tmpl.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
				"msg":            "Could not register user",
			})
			return
		}

		w.Write([]byte("User successfully registered"))
	}
}

func (s *Server) GetCSRFToken() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		token := csrf.Token(r)
		c := http.Cookie{
			Name:     "_gorilla_csrf",
			Value:    token,
			HttpOnly: true,
			Path:     s.cfg.SubDirectory,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		}

		//Extend session expiry
		// s.cache.Expire(c.Value, time.Duration(s.cfg.SessionExpiryInSeconds*time.Second))
		http.SetCookie(w, &c)
		fmt.Fprint(w, token)
	}
}

func (s *Server) APILogin() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		// if cookie, err := r.Cookie("sid"); err == nil {
		// 	//sid cookie exists. Let's check if session is valid
		// 	requestLogger = requestLogger.With("sid", cookie.Value)
		// 	requestLogger.Info("sid cookie exists. Let's check if session is valid")

		// 	obj, err := s.cache.Get(cookie.Value) //.Int()
		// 	if err != nil {
		// 		requestLogger.Errorf("Error while fetching session id '%s' from cache: %s", cookie.Value, err)
		// 		// return nil

		// 		errMsg := fmt.Errorf("Invalid session id. Req ID: %s", reqID)
		// 		errorJSON(w, errMsg, http.StatusUnauthorized)
		// 		return
		// 	}

		// 	if obj != nil {
		// 		uid, err := strconv.ParseInt(obj.Value(), 10, 64)
		// 		if err != nil {
		// 			requestLogger.Errorf("could not convert user id ('%s') to int: %s", obj.Value(), err)
		// 			// return nil

		// 			errMsg := fmt.Errorf("Invalid user id. Req ID: %s", reqID)
		// 			errorJSON(w, errMsg, http.StatusUnauthorized)
		// 			return
		// 		}

		// 		if err == nil {
		// 			//Session ID is valid
		// 			//Let's fetch user
		// 			requestLogger.Info("Session ID is valid. Let's fetch user")

		// 			user := authlib.User{}
		// 			tx := s.db.Model(authlib.User{}).Where("id = ?", uid).First(&user)
		// 			if tx.Error != nil {
		// 				requestLogger.Errorf("An error occured while fetching user from db: %s", tx.Error)
		// 			} else {
		// 				//User is valid. Redirect
		// 				requestLogger.Info("User is valid. Calling redirectAfterSuccessfulLogin . . .")
		// 				s.redirectAfterSuccessfulLogin(w, r, cookie, &user)
		// 				return
		// 			}

		// 		}
		// 	}
		// }

		// requestLogger.Info("Either no sid cookie was found or sid was not found in cache. Proceeding")

		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = io.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewBuffer(rawReqBody))

		requestLogger.Info("Parsing request body . . . ")
		// requestLogger.Info("Parsing request body: %s", string(rawReqBody))
		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		// vars := mux.Vars(r)

		//Check for required params
		required := []string{"username", "password", "token"}
		for _, r := range required {
			if _, ok := reqMap[r]; !ok {
				requestLogger.Infof("Required parameter missing: %s", r)

				errMsg := fmt.Errorf("Required parameter missing: %s", r)
				utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
				return
			}
		}

		user := authlib.User{}
		tx := s.db.Model(authlib.User{}).Where("username = ?", strings.ToLower(reqMap["username"])).First(&user)
		if tx.Error != nil {
			requestLogger.Errorf("An error occured while reading user from DB: %s", tx.Error)
			requestLogger.Info("Treating above error as user does not exist.")
			utils.ErrorJSON(w, fmt.Errorf("invalid username/password"), http.StatusNotFound)
			return
		}

		requestLogger.Info("User found. Checking for password")

		lr := authlib.LoginRequest{
			Username: strings.ToLower(reqMap["username"]),
			Password: reqMap["password"],
			Token:    reqMap["token"]}

		authenticatedUser, err := s.authenticateUser(requestLogger, user, lr)
		if err != nil {
			requestLogger.With("err", err).Info("authenticateUser returned an error")
			// errMsg := fmt.Errorf("incorrect username or password")
			utils.ErrorJSON(w, err, http.StatusUnauthorized)
			return
		}

		if authenticatedUser.ID == 0 {
			authenticatedUser.GUID = xid.New().String()
			authenticatedUser.SID = xid.New().String()
			authenticatedUser.Active = true
			authenticatedUser.ExpiryDate = time.Now()

			s.db.Create(&authenticatedUser)
		}

		if !authenticatedUser.Active || authenticatedUser.Locked {
			requestLogger.Info("User is not active.")
			utils.ErrorJSON(w, fmt.Errorf("user is not active"), http.StatusUnauthorized)
			return
		}

		//Fetch user roles
		authenticatedUser.IAMRoles = s.GetUserPermissions(authenticatedUser.Email, requestLogger)
		authenticatedUser.Attributes = map[string]string{}

		//Login succesful. Let's generate session id
		requestLogger.Info("Login succesful. Let's generate session id")

		sessionID := xid.New()
		requestLogger = requestLogger.With("sid", sessionID)

		if s.cfg.SaveLoginSessions {
			requestLogger.Infof("Saving session id: %s => %s", sessionID.String(), fmt.Sprintf("%d", authenticatedUser.ID))
			s.cache.Set(sessionID.String(), fmt.Sprintf("%d", authenticatedUser.ID), s.cfg.SessionDuration)
		} else {
			requestLogger.Info("will not save session as SAVE_LOGIN_SESSIONS is not set to true")
		}

		c := http.Cookie{
			Name:     "sid",
			Value:    sessionID.String(),
			HttpOnly: true,
			Path:     s.cfg.SubDirectory,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		}

		requestLogger.Info("Extending session expiry")
		//Extend session expiry
		// s.cache.Expire(c.Value, time.Duration(s.cfg.SessionExpiryInSeconds*time.Second))
		http.SetCookie(w, &c)

		qs := r.URL.Query()

		requestLogger.Info("checking for presence of service_id ")
		if _, ok := qs["service"]; ok {
			requestLogger.Info("service_id provided. Calling redirectAfterSuccessfulLogin to redirect to service_id. . .")
			s.redirectAfterSuccessfulLogin(w, r, &c, &user)
			return
		}

		requestLogger.Info("redirect user to profile page")

		// http.Redirect(w, r, profileURL.Path, http.StatusSeeOther)
		ur := utils.JSONResponse{
			Error:       false,
			Message:     "Login successful",
			RedirectURL: fmt.Sprintf("%s%s", s.cfg.URLPrefix, PROFILE_URL),
			Status:      "redirect_internal",
		}

		js, _ := json.Marshal(ur)
		w.WriteHeader(http.StatusOK)
		w.Write(js)

	}
}

func (s *Server) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		if r.Method == "GET" {
			t := template.Must(template.ParseFiles("templates/login.html"))

			// Get current user infomration.
			// fmt.Printf("url => %+v", u.Path)
			err := t.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
				"STATIC_PATH":    fmt.Sprintf("%s%s", s.cfg.URLPrefix, STATIC_PATH),
				"API_LOGIN_URL":  fmt.Sprintf("%s%s", s.cfg.URLPrefix, API_LOGIN_URL),
				"API_WHOAMI_URL": fmt.Sprintf("%s%s", s.cfg.URLPrefix, API_WHOAMI_URL),
				"PROFILE_URL":    fmt.Sprintf("%s%s", s.cfg.URLPrefix, PROFILE_URL),
				"QUERY_PARAMS":   r.URL.RawQuery,
			})
			if err != nil {
				requestLogger.Errorf("template execution returned an error - %s", err)
			}
			return
		}
	}
}

func (s *Server) redirectAfterSuccessfulLogin(w http.ResponseWriter, r *http.Request, cookie *http.Cookie, u *authlib.User) {

	// pc, _, _, _ := runtime.Caller(1)
	// details := runtime.FuncForPC(pc)

	reqID := middleware.GetReqID(r.Context())
	requestLogger := s.logger.With("request-id", reqID)

	qs := r.URL.Query()

	requestLogger.Info("checking for service id ")
	if _, ok := qs["service"]; ok {
		service := Service{}
		tx := s.db.Model(Service{}).Where("service_id = ?", qs["service"][0]).First(&service)
		if tx.Error != nil {
			log.Println(tx.Error)
			requestLogger.Errorf("Error occured while fetching service with service_id '%s': %s", qs["service"][0], tx.Error)

			utils.ErrorJSON(w, fmt.Errorf("Invalid App"), http.StatusNotFound)
			return
		}

		//Save a short-lived auth token in cache
		requestLogger.Info("Crearting a short-lived auth token in cache")
		tk := xid.New().String()
		tkValue := OneTimeUserAuthToken{}
		tkValue.ApiKey = service.APIKey
		tkValue.GlobalUserID = u.GUID

		tkVal, _ := json.Marshal(tkValue)

		requestLogger.Info("saving short live auth token to redis cache")
		s.cache.Set(tk, string(tkVal), 60*time.Second)

		requestLogger.With("target-url", service.LoginRedirectURL,
			"http-status-code", http.StatusSeeOther,
		).Info("Redirecting request")

		u := utils.JSONResponse{
			Error:       false,
			Status:      "redirect_external",
			RedirectURL: fmt.Sprintf("%s?tk=%s", service.LoginRedirectURL, tk),
		}
		js, _ := json.Marshal(u)

		w.WriteHeader(http.StatusOK)
		w.Write(js)
		return
	}

	requestLogger.Info("redirect user to profile page")
	profileURL := fmt.Sprintf("%s%s", s.cfg.URLPrefix, PROFILE_URL)

	// http.Redirect(w, r, profileURL.Path, http.StatusSeeOther)
	ur := utils.JSONResponse{
		Error:       false,
		Status:      "redirect_internal",
		RedirectURL: profileURL,
	}
	js, _ := json.Marshal(ur)

	w.WriteHeader(http.StatusOK)
	w.Write(js)

}

func (s *Server) ProfilePage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		t := template.Must(template.ParseFiles("templates/profile.html"))

		// Get current user infomration.
		err := t.Execute(w, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"STATIC_PATH":    STATIC_PATH,
		})
		if err != nil {
			requestLogger.Errorf("template execution returned an error - %s", err)
		}
	}
}

func (s *Server) GetLoggedInUserDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// pc, _, _, _ := runtime.Caller(1)
		// details := runtime.FuncForPC(pc)

		// requestLogger := s.logger.WithFields(logrus.Fields{
		// 	"Function Name": "GetLoggedInUserDetails",
		// 	"Called From":   details.Name(),
		// 	"endpoint":      r.URL.Path,
		// })

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		u := authlib.User{}

		requestLogger.With("ctx", r.Context()).Info("Context printed !!!")

		reqApiKey := r.Header.Get("X-API-KEY")
		if reqApiKey == "" {
			//API-KEY was not provided
			requestLogger.Info("API Key not provided")
			utils.ErrorJSON(w, fmt.Errorf("API Key not provided"), http.StatusBadRequest)
			return
		}

		//Checking for validity of API-KEY
		thirdPartyService := Service{}
		tx := s.db.Model(Service{}).Where("enabled=1 and api_key = ?", reqApiKey).First(&thirdPartyService)
		if tx.Error != nil {
			requestLogger.Info(tx.Error)
			errMsg := fmt.Errorf("Could not find any active service using the API Key provided")

			requestLogger.Infof("Could not find any active service using the API key provided")

			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		qs := r.URL.Query()
		if _, ok := qs["tk"]; !ok {
			//One time user token was not provided
			errMsg := fmt.Errorf("One time user auth token not provided")

			requestLogger.Info("One time user auth token not provided")

			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		tk, err := s.cache.Get(qs["tk"][0])
		if err != nil || tk == nil {
			//Token is not in cache
			errMsg := fmt.Errorf("Could not find the specified session")

			requestLogger.Info("Could not find the specified session")

			utils.ErrorJSON(w, errMsg, http.StatusNotFound)
			return
		}

		token := OneTimeUserAuthToken{}
		err = json.Unmarshal([]byte(tk.Value()), &token)
		if err != nil {
			//Could not parse token
			errMsg := fmt.Errorf("Auth token is corrupt")

			requestLogger.Info("Auth token is corrupt")

			utils.ErrorJSON(w, errMsg, http.StatusInternalServerError)
			return
		}

		if reqApiKey != token.ApiKey {
			//Token is not in cache
			errMsg := fmt.Errorf("Unauthorized access to session")

			requestLogger.Info("Unauthorized access to session")

			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		usr := authlib.User{}
		tx = s.db.Model(authlib.User{}).Where("active=1 and guid = ?", token.GlobalUserID).First(&usr)
		if tx.Error != nil {
			log.Println(tx.Error)
			errMsg := fmt.Errorf("Could not find active user with this ID")

			requestLogger.Info("Could not find active user with this ID")

			utils.ErrorJSON(w, errMsg, http.StatusNotFound)
			return
		}

		u = authlib.User{}
		u.Firstname = usr.Firstname
		u.Lastname = usr.Lastname
		u.Email = usr.Email
		u.GUID = usr.GUID
		u.Active = usr.Active

		u.IAMRoles = s.GetUserPermissions(u.Email, requestLogger)

		requestLogger.Info("User found => %+v", u)

		utils.WriteJSON(w, http.StatusOK, u)

	}
}

func (s *Server) WhoAmI() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		redirectURL := struct {
			URL string
		}{
			URL: s.cfg.LoginURL,
		}
		resp := utils.JSONResponse{
			Error:   true,
			Message: "user not logged in",
			Data:    redirectURL,
		}

		requestLogger.Info("Checking if cookie exists")
		cookie, err := r.Cookie("sid")
		if err != nil {
			requestLogger.Info("could not fetch cookie. panic. Are you calling the right endpoint? If you're calling from an API, you're probably looking for the /api/verify_login endpoint")

			utils.WriteJSON(w, http.StatusUnauthorized, resp)
			return
		}

		requestLogger.Info("Fetching user")
		usr := s.getUser(reqID, cookie.Value)
		if usr == nil {
			requestLogger.Info("could not fetch user. panic")

			utils.WriteJSON(w, http.StatusUnauthorized, resp)
			return
		}

		u := authlib.User{}
		u.Firstname = usr.Firstname
		u.Lastname = usr.Lastname
		u.Email = usr.Email
		u.GUID = usr.GUID
		u.Active = usr.Active
		u.IAMRoles = s.GetUserPermissions(u.Email, requestLogger)

		jsResp := utils.JSONResponse{
			Data: u,
		}

		qs := r.URL.Query()
		requestLogger.Infof("\n\nqs =>>>> %+v\n%s\n\n", qs, r.URL.Query())
		if redirectToUrl, ok := qs["next"]; ok {
			jsResp.RedirectURL = redirectToUrl[0]
		}

		if _, ok := qs["service"]; ok {
			//Service parameter was provided.
			//If valid, add redirect-url so auth frontend will redirect

			requestLogger.Infof("Service parameter found: %+v \n", qs)

			thirdPartyService := Service{}
			tx := s.db.Model(Service{}).Where("enabled=1 and service_id = ?", qs["service"][0]).First(&thirdPartyService)
			if tx.Error == nil {
				//Service successfully fetched from DB
				redirectTokenObj := OneTimeUserAuthToken{
					ApiKey:       thirdPartyService.APIKey,
					GlobalUserID: u.GUID,
				}
				js, _ := json.Marshal(redirectTokenObj)

				redirectToken := fmt.Sprintf("rdtk%s", xid.New().String())
				s.cache.Set(redirectToken, string(js), time.Second*30)

				rawRedirectURL := thirdPartyService.LoginRedirectURL
				requestLogger.Infof("Redirect URL configured for this service is '%s'", rawRedirectURL)

				redirectURLObj, err := url.Parse(rawRedirectURL)
				if err != nil {
					requestLogger.Error("Could not parse redirect URL: %s", err)
				} else {
					q := redirectURLObj.Query()
					q.Set("tk", redirectToken)
					redirectURLObj.RawQuery = q.Encode()
					jsResp.RedirectURL = fmt.Sprint(redirectURLObj)
					jsResp.Status = "redirect_external"

					requestLogger.Infof("Redirect URL => %s\n", fmt.Sprint(redirectURLObj))
				}
			}
		}

		js, _ := json.Marshal(jsResp)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	}
}

func (s *Server) PasswordResetRequestHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		u := utils.JSONResponse{
			Status: "ok",
		}

		requestLogger.Info("Extracting request parameters . . .")
		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = io.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewBuffer(rawReqBody))

		requestLogger.Info("Parsing request body")
		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		email := ""
		var ok bool
		if email, ok = reqMap["email"]; !ok {
			requestLogger.Info("Required parameter missing: email")

			errMsg := fmt.Errorf("Required parameter missing: email")
			utils.ErrorJSON(w, errMsg)
			return
		}

		requestLogger.Info("Fetching user")
		user := authlib.User{}
		if result := s.db.Where("active = true and email = ?", email).First(&user); result.Error != nil {
			requestLogger.Errorf("Failing silently as no active user was found: %s", result.Error)
			errMsg := fmt.Errorf("no active user found")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		requestLogger.Info("Creating password request entry")
		reqCode, err := uuid.NewUUID()
		if err != nil {
			requestLogger.Errorf("UUID code generation returned an error: %s", err)

			errMsg := fmt.Errorf("")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		passwdResetReq := &PasswordResetRequest{
			ResetCode: reqCode.String(),
			Email:     email,
			Active:    true,
			ExpiresOn: time.Now().Local().Add(time.Hour*time.Duration(1) +
				time.Minute*time.Duration(0) +
				time.Second*time.Duration(0)),
		}

		result := s.db.Debug().Model(PasswordResetRequest{}).Where("email = ? and active = true", email).Updates(
			map[string]interface{}{
				"Active": false,
				"status": "replaced_by_new_request",
			})
		if result.Error != nil {
			//Could not invalidate previous reset requests.
			requestLogger.Errorf("Could not disable previous reset requests: %s", result.Error)

			errMsg := fmt.Errorf("unexpected error")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		tx := s.db.Create(passwdResetReq)
		if tx.Error != nil {
			requestLogger.Errorf("An unexpected error occured while saving password reset request to db: %s", tx.Error)

			errMsg := fmt.Errorf("unexpected error")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		//Password request saved successfully. Let's fire email
		to := mail.NewEmail(fmt.Sprintf("%s %s", user.Firstname, user.Lastname), passwdResetReq.Email)
		response, err := s.sendPasswordResetEmail(r, to, *passwdResetReq)
		if err != nil {
			requestLogger.Errorf("An unexpected error occured while sending email: %s", err)

			errMsg := fmt.Errorf("unexpected error")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		requestLogger.Infof("sendPasswordResetEmail Response.StatusCode => %s", response.StatusCode)
		requestLogger.Infof("sendPasswordResetEmail Response.Headers => %s", response.Headers)
		requestLogger.Infof("sendPasswordResetEmail Response.Body => %s", response.Body)
		requestLogger.Infof("sendPasswordResetEmail Response => %s", response)
		requestLogger.Info("Email sent successfully")

		js, _ := json.Marshal(u)
		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
}

func (s *Server) ChangePasswordHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = io.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewBuffer(rawReqBody))

		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		//Check for required params
		required := []string{"reset_code", "password"}
		for _, rq := range required {
			if _, ok := reqMap[rq]; !ok {
				requestLogger.Infof("Mandatory parameter not found: %s", rq)

				errMsg := fmt.Errorf("required parameters missing")
				utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
				return
			}
		}

		// Get active reset request associated with reset_code
		resetReqObj := PasswordResetRequest{}
		result := s.db.Debug().Where("reset_code=? and active=true and expires_on > now()",
			reqMap["reset_code"]).First(&resetReqObj)
		if result.Error != nil {
			requestLogger.Errorf("Error occured while fetching password_reset_request from db: %s", result.Error)

			errMsg := fmt.Errorf("Could not find any outstanding password reset request with the details provided")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		//Get user associated with password request
		u := authlib.User{}
		result = s.db.Model(authlib.User{}).Where("email = ?", resetReqObj.Email).First(&u)
		if result.Error != nil {
			requestLogger.Errorf("Error occured while fetching user from db: %s", result.Error)

			errMsg := fmt.Errorf("Could not find any active user with outstanding password reset request using the details provided")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		passwd, _ := bcrypt.GenerateFromPassword([]byte(reqMap["password"]), 14)
		result = s.db.Debug().Model(authlib.User{}).Where("email = ? and active = true", resetReqObj.Email).Updates(
			map[string]interface{}{
				"password": passwd})
		if result.Error != nil {
			requestLogger.Errorf("Error occured while updating user password in db: %s", result.Error)

			errMsg := fmt.Errorf("Could not update user password")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		//Disable the password reset request
		result = s.db.Debug().Model(PasswordResetRequest{}).Where("reset_code=? ",
			reqMap["reset_code"]).Updates(map[string]interface{}{
			"active": false,
			"status": "completed",
		})
		if result.Error != nil {
			requestLogger.Errorf("Error occured while disabling password: %s", result.Error)

			errMsg := fmt.Errorf("unexpected error")
			utils.ErrorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		resp := utils.JSONResponse{}
		resp.Status = "ok"
		resp.Message = "Password Changed Successfully"
		js, _ := json.Marshal(resp)

		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
}

func (s *Server) Logout() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's check if session is valid
			requestLogger = requestLogger.With("sid", cookie.Value)
			requestLogger.Info("sid cookie exists. Let's check if session is valid")

			s.cache.Delete(cookie.Value)
		}

		resp := utils.JSONResponse{}
		resp.Status = "ok"
		resp.Message = "User Logged Out Successfully"
		js, _ := json.Marshal(resp)

		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
}

func (s *Server) GenerateNewSessionKeys() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		serviceID := xid.New().String()
		apiKey := uuid.New().String()
		secretKey := strings.Replace(uuid.New().String(), "-", "", -1)

		w.Write([]byte(fmt.Sprintf(`
		<html>
		<body>
		<table>
		<tr>
		<td><b>Service ID:</b></td>
		<td>%s</td>
		</tr>
		<tr>
		<td><b>API Key</b></td>
		<td>%s</td>
		</tr>
		<tr>
		<td><b>Secret Key</b></td>
		<td>%s</td>
		</tr>
		</table>
		</body>
		</html>`, serviceID, apiKey, secretKey)))
	}
}

func (s *Server) ListServices() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID, "function", "ListServices")

		services := []Service{}
		tx := s.db.Find(&services)
		if tx.Error != nil {
			requestLogger.Errorf("An error occured while reading service from DB: %s", tx.Error)
			utils.ErrorJSON(w, fmt.Errorf("services could not be listed"), http.StatusNotFound)
			return
		}

		utils.WriteJSON(w, http.StatusOK, services)
	}
}

func (s *Server) RegisterService() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)
		tmpl := template.Must(template.ParseFiles("html/register_service.html"))

		requestLogger.Info("Register service handler")
		if r.Method == "GET" {
			tmpl.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
			})
			return
		}

		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = io.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewBuffer(rawReqBody))

		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		//Check for required params
		required := []string{"login_redirect_url", "sid", "domain", "callback"}
		for _, rq := range required {
			if _, ok := reqMap[rq]; !ok {
				tmpl.Execute(w, map[string]interface{}{
					csrf.TemplateTag: csrf.TemplateField(r),
					"msg":            fmt.Sprintf("Required parameter missing: %s", rq),
				})
				return
			}
		}

		apiKey := uuid.New().String()
		secretKey := strings.Replace(uuid.New().String(), "-", "", -1)

		newSvc := Service{
			APIKey:    apiKey,
			SecretKey: secretKey,
			ServiceID: reqMap["sid"],
			Domain: sql.NullString{
				Valid:  true,
				String: reqMap["domain"]},
			LoginRedirectURL: reqMap["login_redirect_url"],
			CallbackURL: sql.NullString{
				Valid:  true,
				String: reqMap["callback"]},
			Enabled: false,
		}

		tx := s.db.Create(&newSvc)
		if tx.Error != nil {
			log.Println(tx.Error)
			tmpl.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
				"msg":            "Could not register service",
			})
			return
		}

		w.Write([]byte("Service successfully registered"))
	}
}

func (s *Server) RegisterUserViaApi() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		newUser := authlib.User{}

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = io.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewBuffer(rawReqBody))

		err := json.Unmarshal([]byte(rawReqBody), &newUser)
		if err != nil {
			requestLogger.With("err", err).Error("could not parse request")
			utils.ErrorJSON(w, fmt.Errorf("could not parse request"))
			return
		}

		newUser.SID = xid.New().String()
		newUser.GUID = uuid.New().String()
		newUser.Locked = false
		newUser.Active = false

		tx := s.db.Create(newUser)
		if tx.Error != nil {
			requestLogger.With("err", tx.Error).Error("could not register user")
			utils.ErrorJSON(w, fmt.Errorf("could not register user"))
			return
		}

		newUser.UserMessage = "User successfully registered"
		utils.WriteJSON(w, http.StatusOK, newUser)
	}
}

func (s *Server) UpdateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		username := chi.URLParam(r, "username")
		action := chi.URLParam(r, "action")

		user := authlib.User{}
		tx := s.db.Model(authlib.User{}).Where("username = ?", strings.ToLower(username)).First(&user)
		if tx.Error != nil {
			requestLogger.Errorf("An error occured while reading user from DB: %s", tx.Error)
			requestLogger.Info("Treating above error as user does not exist.")
			utils.ErrorJSON(w, fmt.Errorf("user not found"), http.StatusNotFound)
			return
		}

		switch action {
		case "lock":
			user.Locked = true
		case "unlock":
			user.Locked = false
		case "disable":
			user.Active = false
		case "enable":
			user.Active = true
		}

		err := s.db.Save(&user)
		if err != nil {
			requestLogger.With("err", err).Error("could not save update to user")
			utils.ErrorJSON(w, errors.New("could not save update to user"))
			return
		}

		user.UserMessage = "user status updated"
		utils.WriteJSON(w, http.StatusOK, user)

	}
}

func (s *Server) GetUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		requestLogger := s.logger.With("request-id", reqID)

		username := chi.URLParam(r, "username")

		user := authlib.User{}
		tx := s.db.Model(authlib.User{}).Where("username = ?", strings.ToLower(username)).First(&user)
		if tx.Error != nil {
			requestLogger.Errorf("An error occured while reading user from DB: %s", tx.Error)
			requestLogger.Info("Treating above error as user does not exist.")
			utils.ErrorJSON(w, fmt.Errorf("user not found"), http.StatusNotFound)
			return
		}

		u := authlib.User{}
		u.Firstname = user.Firstname
		u.Lastname = user.Lastname
		u.Email = user.Email
		u.GUID = user.GUID
		u.Active = user.Active

		u.IAMRoles = s.GetUserPermissions(u.Email, requestLogger)

		utils.WriteJSON(w, http.StatusOK, u)

	}
}

func (s *Server) CreateGroup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		// var user authlib.User = r.Context().Value(authlib.CTX_USER_KEY).(authlib.User)
		logger := s.logger.With("request-id", reqID)

		eGrp := EnhancedGroup{}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.With("err", err).
				Error("could not read request body")
			utils.ErrorJSON(w, errors.New("could not read request body"))
			return
		}

		err = json.Unmarshal(body, &eGrp)
		if err != nil {
			logger.With("err", err).
				Error("could not parse request body")
			utils.ErrorJSON(w, errors.New("could not parse request body"))
			return
		}

		logger.With("reqPayload", eGrp).Info("request successfully parsed")

		//Check if group already exists
		grpMaster := GroupMaster{}
		grpTx := s.db.Model(GroupMaster{}).
			Where("group_id = ?", eGrp.GroupID).
			First(&grpMaster)

		if grpTx.Error == nil && !grpMaster.Authorized {
			logger.Error("cannot modify unauthorized record")
			utils.ErrorJSON(w, errors.New("cannot modify unauthorzed record"))
			return
		}

		if grpMaster.ID != 0 {
			//group already exists. Change to unauthorized and
			//increase mod no
			grpMaster.ModNo += 1
			grpMaster.Authorized = false
		} else {
			grpMaster.ModNo = 1
			grpMaster.GroupID = eGrp.GroupID
			grpMaster.Authorized = false
		}

		tx := s.db.Begin()
		if tx.Error != nil {
			logger.With("err", tx.Error).
				Error("could not initiate transaction")
			utils.ErrorJSON(w, errors.New("could not initiate transaction"))
			return
		}

		defer tx.Rollback()

		t := tx.Save(&grpMaster)
		if t.Error != nil {
			logger.With("err", t.Error).
				Errorf("could not save new grpMaster record - %s", grpMaster.GroupID)
			utils.ErrorJSON(w, errors.New("could not save group"))
			return
		}

		grpDetails := GroupDetail{
			GroupID:   grpMaster.GroupID,
			GroupName: eGrp.GroupName,
			Active:    eGrp.Active,
			ModNo:     grpMaster.ModNo,
			CreatedBy: eGrp.CreatedBy,
			CreatedOn: time.Now(),
		}
		t = tx.Save(&grpDetails)
		if t.Error != nil {
			logger.With("err", t.Error).
				Errorf("could not save new grpDetails record - %s", grpMaster.GroupID)
			utils.ErrorJSON(w, errors.New("could not save group"))
			return
		}

		//Save Group permissions
		for service, permissions := range eGrp.Permissions {
			for _, perm := range permissions {
				acl := AccessControl{
					Group:   eGrp.GroupID,
					Service: service,
					Role:    perm,
					ModNo:   grpMaster.ModNo,
				}

				t := tx.Save(&acl)
				if t.Error != nil {
					logger.With("err", t.Error).
						Errorf("could not save new grp permission - %s -%s", grpDetails.GroupName, perm)
					utils.ErrorJSON(w, errors.New("could not save group permission"))
					return
				}
			}
		}

		t = tx.Commit()
		if t.Error != nil {
			logger.With("err", t.Error).
				Error("could not commit record")
			utils.ErrorJSON(w, errors.New("could not commit record"))
			return
		}

		utils.WriteJSON(w, http.StatusOK, utils.JSONResponse{Message: "Group successfully created"})
	}
}

func (s *Server) GetGroup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		reqID := middleware.GetReqID(r.Context())
		logger := s.logger.With("request-id", reqID)

		gid := chi.URLParam(r, "gid")

		grp := EnhancedGroup{}
		tx := s.db.Model(GroupMaster{}).Where("group_id = ?", strings.ToLower(gid)).First(&grp)
		if tx.Error != nil {
			logger.Errorf("An error occured while reading group from DB: %s", tx.Error)
			logger.Info("Treating above error as Group does not exist.")
			utils.ErrorJSON(w, fmt.Errorf("Group not found"), http.StatusNotFound)
			return
		}

		tx = s.db.Model(GroupDetail{}).
			Where("group_id = ? and mod_no = ?", grp.GroupID, grp.ModNo).
			First(&grp)
		if tx.Error != nil {
			logger.Errorf("An error occured while reading group details from DB: %s", tx.Error)
			logger.Info("Treating above error as Group does not exist.")
			utils.ErrorJSON(w, fmt.Errorf("Group not found"), http.StatusNotFound)
			return
		}

		permissions := map[string][]string{}
		rows, err := s.db.Model(AccessControl{}).
			Where("group = ? and mod_no = ?", grp.GroupID, grp.ModNo).
			Rows()
		if err != nil {
			logger.With("err", err).Error("could not fetch permissions")
			utils.ErrorJSON(w, errors.New("could not fetch permissions"))
			return
		}

		for rows.Next() {
			acl := AccessControl{}
			err = s.db.ScanRows(rows, &acl)
			if err != nil {
				logger.With("err", err).Error("could not scan row")
				utils.ErrorJSON(w, errors.New("could not scan row"))
				return
			}

			if _, ok := permissions[acl.Service]; !ok {
				permissions[acl.Service] = make([]string, 0)
			}

			permissions[acl.Service] = append(permissions[acl.Service], acl.Role)
		}

		grp.Permissions = permissions
		utils.WriteJSON(w, http.StatusOK, grp)

	}
}

func (s *Server) Groups() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := s.logger.With("request-id", reqID)

		groups := []GroupMaster{}

		rows, err := s.db.Model(GroupMaster{}).Where("authorized = 1").Rows()
		if err != nil {
			logger.With("err", err).
				Error("could not fetch groups")
			utils.ErrorJSON(w, errors.New("could not fetch groups"))
			return
		}

		for rows.Next() {
			grp := GroupMaster{}
			err := s.db.ScanRows(rows, &grp)
			if err != nil {
				logger.With("err", err).Error("could not scan row")
				continue
			}

			groups = append(groups, grp)
		}

		utils.WriteJSON(w, http.StatusOK, utils.JSONResponse{Data: groups})
	}
}

func (s *Server) CreatePermission() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := s.logger.With("request-id", reqID)

		perm := []AppRole{}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.With("err", err).
				Error("could not read request body")
			utils.ErrorJSON(w, errors.New("could not read request body"))
			return
		}

		err = json.Unmarshal(body, &perm)
		if err != nil {
			logger.With("err", err).
				Error("could not parse request body")
			utils.ErrorJSON(w, errors.New("could not parse request body"))
			return
		}

		tx := s.db.Begin()
		if tx.Error != nil {
			logger.With("err", tx.Error).
				Error("could not initiate transaction")
			utils.ErrorJSON(w, errors.New("could not initiate transaction"))
			return
		}

		defer tx.Rollback()

		for _, p := range perm {
			p.Service = r.Context().Value(SERVICE_ID_CONTEXT_KEY).(string)
			t := tx.Save(&p)
			if t.Error != nil {
				logger.With("err", t.Error,
					"permission", p).
					Errorf("could not save perimssion")
			}
		}

		t := tx.Commit()
		if t.Error != nil {
			logger.With("err", t.Error).
				Error("could not commit record")
		}

		utils.WriteJSON(w, http.StatusOK, utils.JSONResponse{Message: "Permission successfully created"})
	}
}

func (s *Server) GetPermissions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := s.logger.With("request-id", reqID)

		permissions := map[string][]AppRole{}
		serviceOfInterest := chi.URLParam(r, "service")

		rows, err := s.db.Model(AppRole{}).Rows()
		if err != nil {
			logger.With("err", err).
				Error("could not fetch permissions")
			utils.ErrorJSON(w, errors.New("could not fetch permissions"))
			return
		}

		for rows.Next() {
			perm := AppRole{}
			err := s.db.ScanRows(rows, &perm)
			if err != nil {
				logger.With("err", err).Error("could not scan row")
				continue
			}

			if serviceOfInterest != "" && perm.Service != serviceOfInterest {
				//Skip
				continue
			}

			if _, ok := permissions[perm.Service]; !ok {
				permissions[perm.Service] = make([]AppRole, 0)
			}

			permissions[perm.Service] = append(
				permissions[perm.Service], perm)

		}

		utils.WriteJSON(w, http.StatusOK, permissions)
	}
}
