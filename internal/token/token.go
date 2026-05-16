package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
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
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(Claims{
		Sub:   userID,
		Email: email,
		Role:  role,
		Scope: scope,
		Exp:   time.Now().Add(AccessTokenTTL).Unix(),
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

func HashPassword(password string) (hash, salt string, err error) {
	saltBytes := make([]byte, 32)
	if _, err = rand.Read(saltBytes); err != nil {
		return
	}
	salt = base64.RawURLEncoding.EncodeToString(saltBytes)
	h := sha256.Sum256([]byte(salt + password))
	hash = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func VerifyPassword(password, hash, salt string) bool {
	h := sha256.Sum256([]byte(salt + password))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(hash)) == 1
}

func signHS256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
