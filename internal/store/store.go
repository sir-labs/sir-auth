package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/syumai/workers/cloudflare/d1"

	"github.com/sir-labs/sir-auth/internal/model"
)

// Store wraps a GORM DB and provides auth data-access operations.
type Store struct {
	db *gorm.DB
}

// Open creates a new Store backed by the "DB" D1 binding.
func Open() (*Store, error) {
	connector, err := d1.OpenConnector("DB")
	if err != nil {
		return nil, err
	}
	sqlDB := sql.OpenDB(connector)
	gormDB, err := gorm.Open(newDialector(sqlDB), &gorm.Config{
		Logger:                 defaultLogger(),
		SkipDefaultTransaction: true,
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return &Store{db: gormDB}, nil
}

func defaultLogger() gormlogger.Interface {
	return gormlogger.Default.LogMode(gormlogger.Silent)
}

func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// ── Users ────────────────────────────────────────────────────────────────────

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	err := s.db.WithContext(ctx).Where("email = ?", email).Take(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &u, err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var u model.User
	err := s.db.WithContext(ctx).Where("id = ?", id).Take(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &u, err
}

func (s *Store) CreateUser(ctx context.Context, u model.User) error {
	return s.db.WithContext(ctx).Create(&u).Error
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	var users []model.User
	err := s.db.WithContext(ctx).
		Select("id, email, role, created_at").
		Order("created_at DESC").
		Find(&users).Error
	return users, err
}

func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&model.User{}).Count(&count).Error
	return count, err
}

func (s *Store) UpdateUser(ctx context.Context, u model.User) error {
	return s.db.WithContext(ctx).Save(&u).Error
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&model.User{}).Error
}

// ── System Logs ───────────────────────────────────────────────────────────────

func (s *Store) CreateSystemLog(ctx context.Context, log model.SystemLog) error {
	return s.db.WithContext(ctx).Create(&log).Error
}

func (s *Store) ListSystemLogs(ctx context.Context) ([]model.SystemLog, error) {
	var logs []model.SystemLog
	err := s.db.WithContext(ctx).Order("created_at DESC").Find(&logs).Error
	return logs, err
}

// ── OAuth Clients ─────────────────────────────────────────────────────────────

func (s *Store) GetClientByID(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	var c model.OAuthClient
	err := s.db.WithContext(ctx).Where("client_id = ?", clientID).Take(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

func (s *Store) CreateClient(ctx context.Context, c model.OAuthClient) error {
	return s.db.WithContext(ctx).Create(&c).Error
}

// ── Auth Codes ────────────────────────────────────────────────────────────────

func (s *Store) CreateAuthCode(ctx context.Context, clientID, userID, redirectURI, scope string) (*model.AuthCode, error) {
	ac := &model.AuthCode{
		ClientID:    clientID,
		UserID:      userID,
		RedirectURI: redirectURI,
		Scope:       scope,
	}
	if err := s.db.WithContext(ctx).Create(ac).Error; err != nil {
		return nil, err
	}
	return ac, nil
}

func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (*model.AuthCode, error) {
	var ac model.AuthCode
	err := s.db.WithContext(ctx).Where("code = ?", code).Take(&ac).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ac.Used || time.Now().Unix() > ac.ExpiresAt {
		return nil, errors.New("code invalid or expired")
	}
	if err := s.db.WithContext(ctx).Model(&ac).Update("used", true).Error; err != nil {
		return nil, err
	}
	return &ac, nil
}

// ── Refresh Tokens ────────────────────────────────────────────────────────────

func (s *Store) CreateRefreshToken(ctx context.Context, userID, clientID, scope string) (*model.RefreshToken, error) {
	rt := &model.RefreshToken{
		UserID:   userID,
		ClientID: clientID,
		Scope:    scope,
	}
	if err := s.db.WithContext(ctx).Create(rt).Error; err != nil {
		return nil, err
	}
	return rt, nil
}

func (s *Store) GetRefreshToken(ctx context.Context, rawToken string) (*model.RefreshToken, error) {
	var rt model.RefreshToken
	err := s.db.WithContext(ctx).Where("token = ?", rawToken).Take(&rt).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &rt, err
}

func (s *Store) RevokeRefreshToken(ctx context.Context, rawToken string) error {
	return s.db.WithContext(ctx).
		Model(&model.RefreshToken{}).
		Where("token = ?", rawToken).
		Update("revoked", true).Error
}
