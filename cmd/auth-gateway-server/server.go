package main

import (
	"bytes"
	"encoding/json"
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
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/lafriks/ttlcache/v3"
	"github.com/natefinch/lumberjack"
	"github.com/rs/xid"
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	_ "github.com/sijms/go-ora/v2"
)

type config struct {
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
	CORSWhiteList         string        `mapstructure:"AUTH_CORS_ORIGIN_WHITELIST"`
	SubDirectory          string        `mapstructure:"AUTH_SUBDIRECTORY"`
	LogLevel              string
}

type server struct {
	db                             *gorm.DB
	svr                            *http.Server
	cfg                            config
	router                         *mux.Router
	cache                          *ttlcache.Cache[string, string]
	CSRFMiddleware                 func(http.Handler) http.Handler
	logger                         *zap.SugaredLogger
	supportedAuthenticationMethods map[string]authlib.AuthenticationMethod
}

func (s *server) addAuthenticationMethod(authMethodCode string, authMethod authlib.AuthenticationMethod) {
	s.supportedAuthenticationMethods[authMethodCode] = authMethod
}

func (s *server) authenticateUser(logger *zap.SugaredLogger, user authlib.User, lr authlib.LoginRequest) (*authlib.User, error) {
	authMethod, ok := s.supportedAuthenticationMethods[user.AuthenticationSystem]
	if !ok {
		//Auth method not supported
		return nil, fmt.Errorf("authentication method not supported")
	}

	return authMethod(logger, user, lr)
}

func (s *server) sendPasswordResetEmail(r *http.Request, to *mail.Email,
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

func (s *server) getUser(reqID, sessionID string) *authlib.User {

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

func (s *server) InitLogger() {
	writeSyncer := s.getLogWriter()
	syncer := zap.CombineWriteSyncers(os.Stdout, writeSyncer)
	encoder := s.getEncoder()
	core := zapcore.NewCore(encoder, syncer, zapcore.DebugLevel)
	// Print function lines
	logger := zap.New(core, zap.AddCaller())
	s.logger = logger.Sugar()
}

func (s *server) getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	// The format time can be customized
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

// Save file log cut
func (s *server) getLogWriter() zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   "./logs/auth.log", // Log name
		MaxSize:    1,                 // File content size, MB
		MaxBackups: 5,                 // Maximum number of old files retained
		MaxAge:     30,                // Maximum number of days to keep old files
		Compress:   false,             // Is the file compressed
	}
	return zapcore.AddSync(lumberJackLogger)
}

func (s *server) Init(c config) {
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

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		s.cfg.DBUser, s.cfg.DBPassword, s.cfg.DBHost, s.cfg.DBPort, s.cfg.DBName)
	// fmt.Println(dsn)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: "auth_",
		},
	})

	if err != nil {
		log.Fatalf("Unable to initialize db connection: %s\n", err.Error())
	}

	s.db = db

	s.MigrateDB()
	s.InitRoutes()

}

func (s *server) Run() {
	mode := "PRODUCTION"
	if viper.GetBool("DEBUG") {
		mode = "DEV"
	}
	log.Printf("Server running in %s mode at http://%s:%d/\n\n", mode, s.cfg.Host, s.cfg.Port)
	log.Printf("\tCORS WHITELISTED ORIGINS: %v\n", strings.Split(s.cfg.CORSWhiteList, " "))
	s.svr.ListenAndServe()
}

func (s *server) Register() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
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

func (s *server) GetCSRFToken() http.HandlerFunc {

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

func (s *server) APILogin() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With("request-id", reqID)

		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's check if session is valid
			requestLogger = requestLogger.With("sid", cookie.Value)
			requestLogger.Info("sid cookie exists. Let's check if session is valid")

			obj, err := s.cache.Get(cookie.Value) //.Int()
			if err != nil {
				requestLogger.Errorf("Error while fetching session id '%s' from cache: %s", cookie.Value, err)
				// return nil

				errMsg := fmt.Errorf("Invalid session id. Req ID: %s", reqID)
				errorJSON(w, errMsg, http.StatusUnauthorized)
				return
			}

			if obj != nil {
				uid, err := strconv.ParseInt(obj.Value(), 10, 64)
				if err != nil {
					requestLogger.Errorf("could not convert user id ('%s') to int: %s", obj.Value(), err)
					// return nil

					errMsg := fmt.Errorf("Invalid user id. Req ID: %s", reqID)
					errorJSON(w, errMsg, http.StatusUnauthorized)
					return
				}

				if err == nil {
					//Session ID is valid
					//Let's fetch user
					requestLogger.Info("Session ID is valid. Let's fetch user")

					user := authlib.User{}
					tx := s.db.Model(authlib.User{}).Where("id = ?", uid).First(&user)
					if tx.Error != nil {
						requestLogger.Errorf("An error occured while fetching user from db: %s", tx.Error)
					} else {
						//User is valid. Redirect
						requestLogger.Info("User is valid. Calling redirectAfterSuccessfulLogin . . .")
						s.redirectAfterSuccessfulLogin(w, r, cookie, &user)
						return
					}

				}
			}
		}

		requestLogger.Info("Either no sid cookie was found or sid was not found in cache. Proceeding")

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
				errorJSON(w, errMsg, http.StatusBadRequest)
				return
			}
		}

		user := authlib.User{}
		tx := s.db.Model(authlib.User{}).Where("username = ?", strings.ToLower(reqMap["username"])).First(&user)
		if tx.Error != nil {
			requestLogger.Errorf("An error occured while reading user from DB: %s", tx.Error)
			requestLogger.Info("Treating above error as user does not exist.")
		} else {
			requestLogger.Info("User found. Checking for password")
		}

		lr := authlib.LoginRequest{
			Username: strings.ToLower(reqMap["username"]),
			Password: reqMap["password"],
			Token:    reqMap["token"]}

		authenticatedUser, err := s.authenticateUser(requestLogger, user, lr)
		if err != nil {
			requestLogger.Info("authenticateUser returned an error: %s", err)
			// errMsg := fmt.Errorf("incorrect username or password")
			errorJSON(w, err, http.StatusUnauthorized)
			return
		}

		if authenticatedUser.ID == 0 {
			authenticatedUser.GUID = xid.New().String()
			authenticatedUser.SID = xid.New().String()
			authenticatedUser.Active = true
			authenticatedUser.ExpiryDate = time.Now()

			s.db.Create(&authenticatedUser)
		}

		//Fetch user roles
		authenticatedUser.IAMRoles = s.GetUserPermissions(authenticatedUser.Email)

		//Login succesful. Let's generate session id
		requestLogger.Info("Login succesful. Let's generate session id")

		sessionID := xid.New()
		requestLogger = requestLogger.With("sid", sessionID)

		requestLogger.Infof("Saving session id: %s => %s", sessionID.String(), fmt.Sprintf("%d", authenticatedUser.ID))
		s.cache.Set(sessionID.String(), fmt.Sprintf("%d", authenticatedUser.ID), s.cfg.SessionDuration)

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
		profileURL, err := s.router.Get("profile").URL()
		if err != nil {
			requestLogger.Errorf("Profile URL reversal failed: %s", err)
		}

		// http.Redirect(w, r, profileURL.Path, http.StatusSeeOther)
		ur := JSONResponse{
			Error:       false,
			Message:     "Login successful",
			RedirectURL: profileURL.Path,
			Status:      "redirect_internal",
		}

		js, _ := json.Marshal(ur)
		w.WriteHeader(http.StatusOK)
		w.Write(js)

	}
}

func (s *server) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With("request-id", reqID)

		if r.Method == "GET" {
			t := template.Must(template.ParseFiles("templates/login.html"))

			apiLoginURL, err := s.router.Get("api_login").URL()
			if err != nil {
				requestLogger.Errorf("could not find api_login url: %s. Defaulting to empty path.", err)
				apiLoginURL = &url.URL{}
			}

			apiWhoAmIURL, err := s.router.Get("whoami").URL()
			if err != nil {
				requestLogger.Errorf("could not find api_whoami url: %s. Defaulting to empty path.", err)
				apiWhoAmIURL = &url.URL{}
			}

			profileURL, err := s.router.Get("profile").URL()
			if err != nil {
				requestLogger.Errorf("could not find api_whoami url: %s. Defaulting to empty path.", err)
				profileURL = &url.URL{}
			}

			// Get current user infomration.
			// fmt.Printf("url => %+v", u.Path)
			err = t.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
				"STATIC_PATH":    STATIC_PATH,
				"API_LOGIN_URL":  apiLoginURL.Path,
				"API_WHOAMI_URL": apiWhoAmIURL.Path,
				"PROFILE_URL":    profileURL.Path,
				"QUERY_PARAMS":   r.URL.RawQuery,
			})
			if err != nil {
				requestLogger.Errorf("template execution returned an error - %s", err)
			}
			return
		}
	}
}

func (s *server) redirectAfterSuccessfulLogin(w http.ResponseWriter, r *http.Request, cookie *http.Cookie, u *authlib.User) {

	// pc, _, _, _ := runtime.Caller(1)
	// details := runtime.FuncForPC(pc)

	reqID := r.Header.Get("x-req-id")
	requestLogger := s.logger.With("request-id", reqID)

	qs := r.URL.Query()

	requestLogger.Info("checking for service id ")
	if _, ok := qs["service"]; ok {
		service := Service{}
		tx := s.db.Model(Service{}).Where("service_id = ?", qs["service"][0]).First(&service)
		if tx.Error != nil {
			log.Println(tx.Error)
			requestLogger.Errorf("Error occured while fetching service with service_id '%s': %s", qs["service"][0], tx.Error)

			errorJSON(w, fmt.Errorf("Invalid App"), http.StatusNotFound)
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

		u := JSONResponse{
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
	profileURL, err := s.router.Get("profile").URL()
	if err != nil {
		requestLogger.Errorf("Profile URL reversal failed: %s", err)
	}

	// http.Redirect(w, r, profileURL.Path, http.StatusSeeOther)
	ur := JSONResponse{
		Error:       false,
		Status:      "redirect_internal",
		RedirectURL: profileURL.Path,
	}
	js, _ := json.Marshal(ur)

	w.WriteHeader(http.StatusOK)
	w.Write(js)

}

func (s *server) ProfilePage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("x-req-id")
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

func (s *server) GetLoggedInUserDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// pc, _, _, _ := runtime.Caller(1)
		// details := runtime.FuncForPC(pc)

		// requestLogger := s.logger.WithFields(logrus.Fields{
		// 	"Function Name": "GetLoggedInUserDetails",
		// 	"Called From":   details.Name(),
		// 	"endpoint":      r.URL.Path,
		// })

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With("request-id", reqID)

		u := authlib.User{}

		reqApiKey := r.Header.Get("X-API-KEY")
		if reqApiKey == "" {
			//API-KEY was not provided
			requestLogger.Info("API Key not provided")
			errorJSON(w, fmt.Errorf("API Key not provided"), http.StatusBadRequest)
			return
		}

		//Checking for validity of API-KEY
		thirdPartyService := Service{}
		tx := s.db.Model(Service{}).Where("enabled=1 and api_key = ?", reqApiKey).First(&thirdPartyService)
		if tx.Error != nil {
			requestLogger.Info(tx.Error)
			errMsg := fmt.Errorf("Could not find any active service using the API Key provided")

			requestLogger.Infof("Could not find any active service using the API key provided")

			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		qs := r.URL.Query()
		if _, ok := qs["tk"]; !ok {
			//One time user token was not provided
			errMsg := fmt.Errorf("One time user auth token not provided")

			requestLogger.Info("One time user auth token not provided")

			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		tk, err := s.cache.Get(qs["tk"][0])
		if err != nil || tk == nil {
			//Token is not in cache
			errMsg := fmt.Errorf("Could not find the specified session")

			requestLogger.Info("Could not find the specified session")

			errorJSON(w, errMsg, http.StatusNotFound)
			return
		}

		token := OneTimeUserAuthToken{}
		err = json.Unmarshal([]byte(tk.Value()), &token)
		if err != nil {
			//Could not parse token
			errMsg := fmt.Errorf("Auth token is corrupt")

			requestLogger.Info("Auth token is corrupt")

			errorJSON(w, errMsg, http.StatusInternalServerError)
			return
		}

		if reqApiKey != token.ApiKey {
			//Token is not in cache
			errMsg := fmt.Errorf("Unauthorized access to session")

			requestLogger.Info("Unauthorized access to session")

			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		usr := authlib.User{}
		tx = s.db.Model(authlib.User{}).Where("active=1 and guid = ?", token.GlobalUserID).First(&usr)
		if tx.Error != nil {
			log.Println(tx.Error)
			errMsg := fmt.Errorf("Could not find active user with this ID")

			requestLogger.Info("Could not find active user with this ID")

			errorJSON(w, errMsg, http.StatusNotFound)
			return
		}

		u = authlib.User{}
		u.Firstname = usr.Firstname
		u.Lastname = usr.Lastname
		u.Email = usr.Email
		u.GUID = usr.GUID
		u.Active = usr.Active

		u.IAMRoles = s.GetUserPermissions(u.Email)

		requestLogger.Info("User found => %+v", u)

		writeJSON(w, http.StatusOK, u)

	}
}

func (s *server) WhoAmI() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With("request-id", reqID)

		requestLogger.Info("Checking if cookie exists")
		cookie, err := r.Cookie("sid")
		if err != nil {
			requestLogger.Info("could not fetch cookie. panic. Are you calling the right endpoint? If you're calling from an API, you're probably looking for the /api/verify_login endpoint")
			errMsg := fmt.Errorf("No cookie found")

			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		requestLogger.Info("Fetching user")
		usr := s.getUser(reqID, cookie.Value)
		if usr == nil {
			requestLogger.Info("could not fetch user. panic")
			errMsg := fmt.Errorf("Could not find active user with this ID")

			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		u := authlib.User{}
		u.Firstname = usr.Firstname
		u.Lastname = usr.Lastname
		u.Email = usr.Email
		u.GUID = usr.GUID
		u.Active = usr.Active
		u.IAMRoles = s.GetUserPermissions(u.Email)

		jsResp := JSONResponse{
			Data: u,
		}

		qs := r.URL.Query()
		requestLogger.Info("\n\nqs =>>>> %+v\n%s\n\n", qs, r.URL.Query())
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
					jsResp.Status = "reditect_external"
				}
			}
		}

		js, _ := json.Marshal(jsResp)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	}
}

func (s *server) PasswordResetRequestHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With("request-id", reqID)

		u := JSONResponse{
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
			errorJSON(w, errMsg)
			return
		}

		requestLogger.Info("Fetching user")
		user := authlib.User{}
		if result := s.db.Where("active = true and email = ?", email).First(&user); result.Error != nil {
			requestLogger.Errorf("Failing silently as no active user was found: %s", result.Error)
			errMsg := fmt.Errorf("no active user found")
			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		requestLogger.Info("Creating password request entry")
		reqCode, err := uuid.NewUUID()
		if err != nil {
			requestLogger.Errorf("UUID code generation returned an error: %s", err)

			errMsg := fmt.Errorf("")
			errorJSON(w, errMsg, http.StatusBadRequest)
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
			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		tx := s.db.Create(passwdResetReq)
		if tx.Error != nil {
			requestLogger.Errorf("An unexpected error occured while saving password reset request to db: %s", tx.Error)

			errMsg := fmt.Errorf("unexpected error")
			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		//Password request saved successfully. Let's fire email
		to := mail.NewEmail(fmt.Sprintf("%s %s", user.Firstname, user.Lastname), passwdResetReq.Email)
		response, err := s.sendPasswordResetEmail(r, to, *passwdResetReq)
		if err != nil {
			requestLogger.Errorf("An unexpected error occured while sending email: %s", err)

			errMsg := fmt.Errorf("unexpected error")
			errorJSON(w, errMsg, http.StatusBadRequest)
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

func (s *server) ChangePasswordHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("x-req-id")
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
				errorJSON(w, errMsg, http.StatusBadRequest)
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
			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		//Get user associated with password request
		u := authlib.User{}
		result = s.db.Model(authlib.User{}).Where("email = ?", resetReqObj.Email).First(&u)
		if result.Error != nil {
			requestLogger.Errorf("Error occured while fetching user from db: %s", result.Error)

			errMsg := fmt.Errorf("Could not find any active user with outstanding password reset request using the details provided")
			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		passwd, _ := bcrypt.GenerateFromPassword([]byte(reqMap["password"]), 14)
		result = s.db.Debug().Model(authlib.User{}).Where("email = ? and active = true", resetReqObj.Email).Updates(
			map[string]interface{}{
				"password": passwd})
		if result.Error != nil {
			requestLogger.Errorf("Error occured while updating user password in db: %s", result.Error)

			errMsg := fmt.Errorf("Could not update user password")
			errorJSON(w, errMsg, http.StatusBadRequest)
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
			errorJSON(w, errMsg, http.StatusBadRequest)
			return
		}

		resp := JSONResponse{}
		resp.Status = "ok"
		resp.Message = "Password Changed Successfully"
		js, _ := json.Marshal(resp)

		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
}

func (s *server) Logout() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.With("request-id", reqID)

		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's check if session is valid
			requestLogger = requestLogger.With("sid", cookie.Value)
			requestLogger.Info("sid cookie exists. Let's check if session is valid")

			s.cache.Delete(cookie.Value)
		}

		resp := JSONResponse{}
		resp.Status = "ok"
		resp.Message = "User Logged Out Successfully"
		js, _ := json.Marshal(resp)

		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
}

func (s *server) GenerateNewSessionKeys() http.HandlerFunc {

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
