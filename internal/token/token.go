package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenTTL  = 1 * time.Hour
	RefreshTokenTTL = 30 * 24 * time.Hour
	AuthCodeTTL     = 10 * time.Minute
)

type Claims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Scope string `json:"scope"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

func GenerateAccessToken(userID, email, role, scope, secret string) (string, error) {
	return GenerateToken(userID, email, role, scope, secret, AccessTokenTTL)
}

// GenerateToken is GenerateAccessToken with an explicit lifetime (used for browser sessions).
func GenerateToken(userID, email, role, scope, secret string, ttl time.Duration) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(Claims{
		Sub:   userID,
		Email: email,
		Role:  role,
		Scope: scope,
		Exp:   time.Now().Add(ttl).Unix(),
		Iat:   time.Now().Unix(),
	})
	if err != nil {
		return "", err
	}
	hp := b64(header) + "." + b64(payload)
	return hp + "." + signHS256(hp, secret), nil
}

func ValidateAccessToken(rawToken, secret string) (*Claims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	hp := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(signHS256(hp, secret)), []byte(parts[2])) {
		return nil, errors.New("invalid signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

func RandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashPassword returns a bcrypt hash. salt is always empty (bcrypt embeds its own);
// it is kept only so the users.salt column and call sites stay unchanged.
func HashPassword(password string) (hash, salt string, err error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), "", err
}

func VerifyPassword(password, hash, _ string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func signHS256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
