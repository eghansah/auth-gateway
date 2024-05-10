package api

import (
	"database/sql"
	"time"

	"github.com/eghansah/auth-gateway/authlib"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type UserPermissions struct {
	Permissions map[string]bool `json:"permissions"`
}

type AppRole struct {
	gorm.Model
	Service     string `gorm:"index:idx_svc_permission,unique;size:255"`
	Permission  string `gorm:"index:idx_svc_permission,unique;size:255"`
	Description string
}

type GroupMaster struct {
	gorm.Model
	GroupID    string `gorm:"index:idx_grpmaster,unique;size:255"`
	ModNo      int
	Authorized bool
}

type GroupDetail struct {
	gorm.Model
	GroupID        string `gorm:"index:idx_gid;size:255"`
	GroupName      string `gorm:"index:idx_gname;size:255"`
	Active         bool
	ModNo          int       `gorm:"index"`
	CreatedBy      string    `gorm:"index"`
	CreatedOn      time.Time `gorm:"index"`
	ApprovalStatus string    `gorm:"index"`
	ApprovedBy     string    `gorm:"index"`
	ApprovedOn     time.Time `gorm:"index"`
}

type EnhancedGroup struct {
	gorm.Model
	GroupID        string
	GroupName      string
	Active         bool
	ModNo          int
	Permissions    map[string][]string
	CreatedBy      string
	CreatedOn      time.Time
	ApprovalStatus string
	ApprovedBy     string
	ApprovedOn     time.Time
}

type UserGroup struct {
	gorm.Model
	ModNo  int
	User   string `gorm:"column:username;index:idx_user_group,unique;size:255"`
	Group  string `gorm:"column:user_group;index:idx_user_group,unique;size:255"`
	Active bool
}

type UserDomain struct {
	gorm.Model
	User   string `gorm:"column:username;index:idx_user_domain,unique;size:255"`
	Domain string `gorm:"column:domain;index:idx_user_domain,unique;size:255"`
	Active bool
}

type AccessControl struct {
	gorm.Model
	ModNo     int
	Username  string
	Group     string `gorm:"index:idx_access_control,unique;size:255;column:user_group"`
	Service   string `gorm:"index:idx_access_control,unique;size:255"`
	Role      string `gorm:"index:idx_access_control,unique;size:255"`
	Domain    string `gorm:"index:idx_access_control,unique;size:255"`
	IsAllowed bool
}

type OneTimeUserAuthToken struct {
	ApiKey       string `json:"apikey"`
	GlobalUserID string `json:"global_user_id"`
}

type Service struct {
	gorm.Model
	ID               int64
	ServiceID        string `gorm:"uniqueIndex;size:255"`
	Domain           sql.NullString
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

func (s *Server) GetUserGroups(username string, logger *zap.SugaredLogger) []string {
	groups := make([]string, 1)

	// s.db.Raw("")

	s.db.Model(UserGroup{}).Select("user_group").Where("username = ? and active=1", username).Find(&groups)

	return groups
}

func (s *Server) GetUserPermissions(username string,
	logger *zap.SugaredLogger) map[string]map[string]bool {

	domainPermissions := make(map[string]map[string]bool)
	perm := make(map[string]bool)

	grps := s.GetUserGroups(username, logger)

	logger.With("groups", grps, "username", username).Info("fetching user permissions")

	dbPermissions := make([]AccessControl, 1)
	s.db.Model(AccessControl{}).Where("username = ? or user_group in (?)", username, grps).Find(&dbPermissions)

	for _, policy := range dbPermissions {
		if allowed, ok := perm[policy.Role]; ok {
			//We already have a setting for this role.
			//If the previous setting was to deny this role, then don't allow
			if !allowed {
				continue
			}
		}

		// perm[policy.Role] = policy.IsAllowed

		if _, ok := domainPermissions[policy.Domain]; !ok {
			domainPermissions[policy.Domain] = make(map[string]bool)
		}

		domainPermissions[policy.Domain][policy.Role] = policy.IsAllowed
	}

	return domainPermissions
}

func (s *Server) GetUserDomains(username string,
	logger *zap.SugaredLogger) []string {

	domains := []string{}
	userDomains := []UserDomain{}

	s.db.Model(UserDomain{}).Where("username = ? and active=1", username).Find(&userDomains)

	for _, domain := range userDomains {
		domains = append(domains, domain.Domain)
	}

	return domains
}

func (s *Server) MigrateDB() {

	s.db.AutoMigrate(authlib.User{})
	s.db.AutoMigrate(Service{})
	s.db.AutoMigrate(PasswordResetRequest{})
	s.db.AutoMigrate(AccessControl{})
	s.db.AutoMigrate(UserGroup{})
	s.db.AutoMigrate(UserDomain{})
	s.db.AutoMigrate(AppRole{})
	s.db.AutoMigrate(GroupMaster{})
	s.db.AutoMigrate(GroupDetail{})
}
