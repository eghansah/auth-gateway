package main

import (
	"database/sql"
	"time"

	"github.com/eghansah/auth-gateway/authlib"
	"gorm.io/gorm"
)

// type FunctionScreens struct {
// 	Name       string
// 	Parent     int
// 	URL        string
// 	FunctionID string
// 	Enabled    bool
// }

type UserPermissions struct {
	Permissions map[string]bool `json:"permissions"`
}

type Permission struct {
	Service     string `gorm:"uniqueIndex,size:255"`
	Permission  string `gorm:"uniqueIndex,size:255"`
	Description string
}

type UserGroup struct {
	gorm.Model
	User   string `gorm:"uniqueIndex,size:255"`
	Group  string `gorm:"uniqueIndex,size:255"`
	Active bool
}

type AccessControl struct {
	gorm.Model
	Username  string `gorm:"uniqueIndex,size:255"`
	Group     string `gorm:"uniqueIndex,size:255"`
	Service   string `gorm:"uniqueIndex,size:255"`
	Role      string `gorm:"uniqueIndex,size:255"`
	IsAllowed bool
}

type OneTimeUserAuthToken struct {
	ApiKey       string `json:"apikey"`
	GlobalUserID string `json:"global_user_id"`
}

type Service struct {
	gorm.Model
	ID               int64
	ServiceID        string         `gorm:"uniqueIndex,size:255"`
	Domain           sql.NullString `gorm:"uniqueIndex,size:255"`
	LoginRedirectURL string
	CallbackURL      sql.NullString
	SecretKey        string
	APIKey           string
	Enabled          bool
}

type PasswordResetRequest struct {
	gorm.Model
	ResetCode string `gorm:"uniqueIndex,size:255"`
	Email     string
	ExpiresOn time.Time
	Active    bool
	Status    sql.NullString
}

func (s *server) GetUserGroups(username string) []string {
	groups := make([]string, 1)
	s.db.Model(UserGroup{}).Select("group").Where("user = ? and active=true", username).Find(&groups)

	return groups
}

func (s *server) GetUserPermissions(username string) map[string]bool {

	perm := make(map[string]bool)

	grps := s.GetUserGroups(username)

	dbPermissions := make([]AccessControl, 1)
	s.db.Model(AccessControl{}).Where("username = ? or `group` in (?)", username, grps).Find(&dbPermissions)

	for _, policy := range dbPermissions {
		if allowed, ok := perm[policy.Role]; ok {
			//We already have a setting for this role.
			//If the previous setting was to deny this role, then don't allow
			if !allowed {
				continue
			}
		}

		perm[policy.Role] = policy.IsAllowed
	}

	return perm
}

func (s *server) MigrateDB() {
	s.db.AutoMigrate(authlib.User{})
	s.db.AutoMigrate(Service{})
	s.db.AutoMigrate(PasswordResetRequest{})
	s.db.AutoMigrate(AccessControl{})
	s.db.AutoMigrate(UserGroup{})
	// s.db.AutoMigrate(FunctionScreens{})

	// apikey, err := GenerateRandomStringURLSafe(64)
	// if err != nil {
	// 	log.Fatalf("Could not generate apikey: %s", err)
	// }

	// secret, err := GenerateRandomStringURLSafe(64)
	// if err != nil {
	// 	log.Fatalf("Could not generate secret: %s", err)
	// }

	// serviceID := xid.New().String()
	// s.db.Create(&Service{
	// 	ServiceID:        serviceID,
	// 	LoginRedirectURL: "http://127.0.0.1",
	// 	APIKey:           apikey,
	// 	SecretKey:        secret,
	// 	Enabled:          true,
	// })
}
