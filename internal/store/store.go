package store

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"sync"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/sir-labs/sir-auth/internal/model"
)

// Store wraps a GORM DB and provides auth data-access operations.
type Store struct {
	db *gorm.DB
}

//go:embed schema.sql
var schema string

var (
	once    sync.Once
	shared  *Store
	openErr error
)

// Open returns the shared Store backed by the PostgreSQL pool at DATABASE_URL.
// The first call connects and migrates the schema.
func Open() (*Store, error) {
	once.Do(func() {
		var gormDB *gorm.DB
		gormDB, openErr = gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{
			Logger:                 gormlogger.Default.LogMode(gormlogger.Silent),
			SkipDefaultTransaction: true,
		})
		if openErr != nil {
			return
		}
		openErr = gormDB.Exec(schema).Error
		shared = &Store{db: gormDB}
	})
	return shared, openErr
}

// Close is a no-op: the pool is shared for the process lifetime.
func (s *Store) Close() error { return nil }

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
		Select("id, email, role, created_at, approved").
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

func (s *Store) SetUserApproved(ctx context.Context, id string, approved bool) error {
	return s.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Update("approved", approved).Error
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

func (s *Store) CountApprovedAdmins(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&model.User{}).Where("role = 'admin' AND approved").Count(&n).Error
	return n, err
}

// SetPassword stores a new password hash and ends every session issued before validAfter.
func (s *Store) SetPassword(ctx context.Context, id, hash, salt string, validAfter int64) error {
	return s.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).
		Updates(map[string]any{"password_hash": hash, "salt": salt, "sessions_valid_after": validAfter}).Error
}

// BumpSessions ends every cookie issued before validAfter and revokes the user's OAuth refresh tokens.
func (s *Store) BumpSessions(ctx context.Context, id string, validAfter int64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.User{}).Where("id = ?", id).Update("sessions_valid_after", validAfter).Error; err != nil {
			return err
		}
		return tx.Model(&model.RefreshToken{}).Where("user_id = ?", id).Update("revoked", true).Error
	})
}

// DeleteUserData deletes a user, their request logs and (via FK cascade) their tokens.
func (s *Store) DeleteUserData(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", id).Delete(&model.RequestLog{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.User{}).Error
	})
}

// ── API tokens (every call is scoped by user_id) ─────────────────────────────

func (s *Store) CreateAPIToken(ctx context.Context, t *model.APIToken) error {
	return s.db.WithContext(ctx).Create(t).Error
}

// GetAPITokenByHash returns the token with this sha256, or nil.
func (s *Store) GetAPITokenByHash(ctx context.Context, hash string) (*model.APIToken, error) {
	var t model.APIToken
	err := s.db.WithContext(ctx).Where("token_hash = ?", hash).Take(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &t, err
}

func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]model.APIToken, error) {
	var ts []model.APIToken
	err := s.db.WithContext(ctx).Where("user_id = ?", userID).
		Order("revoked_at IS NOT NULL, created_at DESC").Find(&ts).Error
	return ts, err
}

func (s *Store) CountActiveAPITokens(ctx context.Context, userID string, now int64) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&model.APIToken{}).
		Where("user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", userID, now).
		Count(&n).Error
	return n, err
}

// RenameAPIToken renames the user's token; found is false if it isn't theirs.
func (s *Store) RenameAPIToken(ctx context.Context, userID, id, name string) (found bool, err error) {
	res := s.db.WithContext(ctx).Model(&model.APIToken{}).Where("id = ? AND user_id = ?", id, userID).Update("name", name)
	return res.RowsAffected > 0, res.Error
}

// RevokeAPIToken revokes the user's token; found is false if it isn't theirs or is already revoked.
func (s *Store) RevokeAPIToken(ctx context.Context, userID, id string, now int64) (found bool, err error) {
	res := s.db.WithContext(ctx).Model(&model.APIToken{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).Update("revoked_at", now)
	return res.RowsAffected > 0, res.Error
}

// ── Request log stats (always over a [From, To) window) ──────────────────────

// LogFilter scopes request_logs queries. Empty strings mean "any".
type LogFilter struct {
	From, To time.Time
	UserID   string
	TokenID  string
	Host     string
}

func (s *Store) logs(ctx context.Context, f LogFilter) *gorm.DB {
	// Columns are qualified: callers join api_tokens/users, which also have user_id.
	q := s.db.WithContext(ctx).Table("request_logs").Where("request_logs.ts >= ? AND request_logs.ts < ?", f.From, f.To)
	if f.UserID != "" {
		q = q.Where("request_logs.user_id = ?", f.UserID)
	}
	if f.TokenID != "" {
		q = q.Where("request_logs.token_id = ?", f.TokenID)
	}
	if f.Host != "" {
		q = q.Where("request_logs.host = ?", f.Host)
	}
	return q
}

func (s *Store) CountLogs(ctx context.Context, f LogFilter) (int64, error) {
	var n int64
	err := s.logs(ctx, f).Count(&n).Error
	return n, err
}

// Bucket is one row of a grouped count.
type Bucket struct {
	Key   string
	Label string
	N     int64
}

// DailyCounts returns per-day counts (YYYY-MM-DD in tz) for the window.
func (s *Store) DailyCounts(ctx context.Context, f LogFilter, tz string) ([]Bucket, error) {
	var out []Bucket
	err := s.logs(ctx, f).
		Select("to_char(request_logs.ts AT TIME ZONE ?, 'YYYY-MM-DD') AS key, count(*) AS n", tz).
		Group("key").Order("key").Scan(&out).Error
	return out, err
}

// CountBy groups the window by host, token or user (with a readable label), largest first.
func (s *Store) CountBy(ctx context.Context, f LogFilter, by string, limit int) ([]Bucket, error) {
	q := s.logs(ctx, f)
	switch by {
	case "host":
		q = q.Select("request_logs.host AS key, request_logs.host AS label, count(*) AS n").Group("request_logs.host")
	case "token":
		q = q.Joins("LEFT JOIN api_tokens t ON t.id = request_logs.token_id").
			Select("COALESCE(request_logs.token_id, '') AS key, COALESCE(t.name, '') AS label, count(*) AS n").
			Group("request_logs.token_id, t.name")
	case "user":
		q = q.Joins("LEFT JOIN users u ON u.id = request_logs.user_id").
			Select("request_logs.user_id AS key, COALESCE(u.email, '') AS label, count(*) AS n").
			Group("request_logs.user_id, u.email")
	default:
		return nil, errors.New("bad group")
	}
	var out []Bucket
	err := q.Order("n DESC").Limit(limit).Scan(&out).Error
	return out, err
}

// LogRow is a request_logs row with the token name and user email joined in.
type LogRow struct {
	model.RequestLog
	TokenName string
	Email     string
}

func (s *Store) logRows(ctx context.Context, f LogFilter) *gorm.DB {
	return s.logs(ctx, f).
		Joins("LEFT JOIN api_tokens t ON t.id = request_logs.token_id").
		Joins("LEFT JOIN users u ON u.id = request_logs.user_id").
		Select("request_logs.*, COALESCE(t.name, '') AS token_name, COALESCE(u.email, '') AS email").
		Order("request_logs.ts DESC, request_logs.id DESC")
}

// RecentLogs returns one page of the newest rows in the window.
func (s *Store) RecentLogs(ctx context.Context, f LogFilter, limit, offset int) ([]LogRow, error) {
	var out []LogRow
	err := s.logRows(ctx, f).Limit(limit).Offset(offset).Scan(&out).Error
	return out, err
}

// EachLog streams every row in the window (newest first) to fn, for CSV export.
func (s *Store) EachLog(ctx context.Context, f LogFilter, fn func(LogRow) error) error {
	rows, err := s.logRows(ctx, f).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r LogRow
		if err := s.db.ScanRows(rows, &r); err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}
