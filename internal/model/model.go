package model

import (
	"time"

	"github.com/sir-labs/sir-auth/internal/token"
	"gorm.io/gorm"
)

// User represents an authenticated user.
type User struct {
	ID           string `gorm:"column:id;primaryKey"`
	Email        string `gorm:"column:email;uniqueIndex;not null"`
	PasswordHash string `gorm:"column:password_hash;not null"`
	Salt         string `gorm:"column:salt;not null"`
	Role         string `gorm:"column:role;not null;default:user"`
	CreatedAt    int64  `gorm:"column:created_at;autoCreateTime:unix"`
	Approved     bool   `gorm:"column:approved;not null"`
	// SessionsValidAfter: cookies with iat before this unix time are rejected.
	SessionsValidAfter int64 `gorm:"column:sessions_valid_after;not null;default:0"`

	AuthCodes     []AuthCode     `gorm:"foreignKey:UserID"`
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		id, err := token.RandomString(16)
		if err != nil {
			return err
		}
		u.ID = id
	}
	return nil
}

// OAuthClient is a registered OAuth 2.0 client application.
type OAuthClient struct {
	ClientID     string `gorm:"column:client_id;primaryKey"`
	ClientSecret string `gorm:"column:client_secret;not null"`
	Name         string `gorm:"column:name;not null"`

	AuthCodes     []AuthCode     `gorm:"foreignKey:ClientID"`
	RefreshTokens []RefreshToken `gorm:"foreignKey:ClientID"`
}

func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// AuthCode is a single-use authorization code (expires in 10 minutes).
type AuthCode struct {
	Code        string `gorm:"column:code;primaryKey"`
	ClientID    string `gorm:"column:client_id;not null;index"`
	UserID      string `gorm:"column:user_id;not null;index"`
	RedirectURI string `gorm:"column:redirect_uri;not null"`
	Scope       string `gorm:"column:scope;not null"`
	ExpiresAt   int64  `gorm:"column:expires_at;not null"`
	Used        bool   `gorm:"column:used;not null;default:false"`

	User   User        `gorm:"foreignKey:UserID"`
	Client OAuthClient `gorm:"foreignKey:ClientID"`
}

func (ac *AuthCode) BeforeCreate(tx *gorm.DB) error {
	if ac.Code == "" {
		code, err := token.RandomString(32)
		if err != nil {
			return err
		}
		ac.Code = code
	}
	if ac.ExpiresAt == 0 {
		ac.ExpiresAt = time.Now().Add(token.AuthCodeTTL).Unix()
	}
	return nil
}

// RefreshToken is a long-lived token used to obtain new access tokens.
type RefreshToken struct {
	Token     string `gorm:"column:token;primaryKey"`
	UserID    string `gorm:"column:user_id;not null;index"`
	ClientID  string `gorm:"column:client_id;not null;index"`
	Scope     string `gorm:"column:scope;not null"`
	ExpiresAt int64  `gorm:"column:expires_at;not null"`
	Revoked   bool   `gorm:"column:revoked;not null;default:false"`

	User   User        `gorm:"foreignKey:UserID"`
	Client OAuthClient `gorm:"foreignKey:ClientID"`
}

func (rt *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if rt.Token == "" {
		raw, err := token.RandomString(48)
		if err != nil {
			return err
		}
		rt.Token = raw
	}
	if rt.ExpiresAt == 0 {
		rt.ExpiresAt = time.Now().Add(token.RefreshTokenTTL).Unix()
	}
	return nil
}

// SystemLog represents an administrative action taken in the system.
type SystemLog struct {
	ID        string `gorm:"column:id;primaryKey" json:"id"`
	Action    string `gorm:"column:action;not null" json:"action"`
	TargetID  string `gorm:"column:target_id;not null" json:"target_id"`
	AdminID   string `gorm:"column:admin_id;not null" json:"admin_id"`
	Details   string `gorm:"column:details" json:"details"`
	CreatedAt int64  `gorm:"column:created_at;autoCreateTime:unix" json:"created_at"`
}

func (l *SystemLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		id, err := token.RandomString(12)
		if err != nil {
			return err
		}
		l.ID = id
	}
	return nil
}

// APIToken is a personal access token (sirpat_…). Only its sha256 is stored.
type APIToken struct {
	ID         string `gorm:"column:id;primaryKey"`
	UserID     string `gorm:"column:user_id;not null"`
	Name       string `gorm:"column:name;not null"`
	TokenHash  string `gorm:"column:token_hash;not null"`
	Prefix     string `gorm:"column:prefix;not null"`
	CreatedAt  int64  `gorm:"column:created_at;autoCreateTime:unix"`
	ExpiresAt  *int64 `gorm:"column:expires_at"`
	RevokedAt  *int64 `gorm:"column:revoked_at"`
	LastUsedAt *int64 `gorm:"column:last_used_at"`
	LastUsedIP string `gorm:"column:last_used_ip;not null;default:''"`
}

func (t *APIToken) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		id, err := token.RandomString(12)
		if err != nil {
			return err
		}
		t.ID = id
	}
	return nil
}

// Active reports whether the token is neither revoked nor expired at now (unix).
func (t *APIToken) Active(now int64) bool {
	return t.RevokedAt == nil && (t.ExpiresAt == nil || *t.ExpiresAt > now)
}

// RequestLog is one request on a gated route, as seen by /session/verify.
type RequestLog struct {
	ID      int64     `gorm:"column:id;primaryKey"`
	TS      time.Time `gorm:"column:ts;not null"`
	Host    string    `gorm:"column:host;not null"`
	Method  string    `gorm:"column:method;not null"`
	Path    string    `gorm:"column:path;not null"`
	IP      string    `gorm:"column:ip;not null"`
	Cred    string    `gorm:"column:cred;not null"` // "session" | "token"
	TokenID *string   `gorm:"column:token_id"`
	UserID  string    `gorm:"column:user_id;not null"`
}

func (APIToken) TableName() string   { return "api_tokens" }
func (RequestLog) TableName() string { return "request_logs" }
