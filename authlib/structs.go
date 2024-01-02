package authlib

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	LOCAL_DB_AUTH = "local"
	LDAP_AUTH     = "ldap"
)

type User struct {
	gorm.Model
	ID                   int64
	SID                  string `gorm:"uniqueIndex;size:255" json:"-"`
	GUID                 string `gorm:"uniqueIndex;size:255" json:"global_id"`
	Username             string `gorm:"uniqueIndex;size:255"`
	Firstname            string `json:"firstname"`
	Lastname             string `json:"lastname"`
	FullName             string `json:"fullname"`
	Email                string `gorm:"uniqueIndex;size:255" json:"email"`
	Password             []byte `json:"-"`
	Active               bool
	Locked               bool
	ExpiryDate           time.Time
	AuthenticationSystem string
	EnableTOTP           bool
	TOTPSecret           string
	TOTPSecretLength     int64
	IAMRoles             map[string]map[string]bool `gorm:"-" json:"iam_roles"`
	Attributes           map[string]string          `gorm:"-" json:"attributes"`
	UserMessage          string                     `json:"message,omitempty"`
	// Domains              []string
}

// type APIUserResponse struct {
// 	User
// 	Status        string          `json:"status"`
// 	ErrMsg        string          `json:"err_msg"`
// 	RedirectToURL string          `json:"redirect_to"`
// 	IAMRoles      map[string]bool `json:"iam_roles"`
// }

type UserGroup struct {
	Username string `gorm:"uniqueIndex:user_grp;size:255"`
	Group    string `gorm:"uniqueIndex:user_grp;size:255"`
	Enabled  bool
}

type UserAttribute struct {
	Username  string `gorm:"uniqueIndex:user_grp;size:255"`
	Attribute string `gorm:"uniqueIndex:user_grp;size:255"`
	Value     string
}

type LoginRequest struct {
	Username string
	Password string
	Token    string
}

type AuthenticationMethod func(*zap.SugaredLogger, User, LoginRequest) (*User, error)

func (user *User) Clone() User {
	return User{
		ID:                   user.ID,
		SID:                  user.SID,
		GUID:                 user.GUID,
		Username:             user.Username,
		Firstname:            user.Firstname,
		Lastname:             user.Lastname,
		FullName:             user.FullName,
		Email:                user.Email,
		Password:             user.Password,
		Active:               user.Active,
		Locked:               user.Locked,
		ExpiryDate:           user.ExpiryDate,
		AuthenticationSystem: user.AuthenticationSystem,
		EnableTOTP:           user.EnableTOTP,
		TOTPSecret:           user.TOTPSecret,
		TOTPSecretLength:     user.TOTPSecretLength,
		IAMRoles:             user.IAMRoles,
		Attributes:           user.Attributes,
		UserMessage:          user.UserMessage,
	}
}
