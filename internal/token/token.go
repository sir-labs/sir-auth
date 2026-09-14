package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

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

// PATPrefix marks a personal access token.
const PATPrefix = "sirpat_"

// NewPAT returns a new personal access token, its sha256 hex and a 12-char display prefix.
func NewPAT() (raw, hash, prefix string, err error) {
	r, err := RandomString(32)
	if err != nil {
		return "", "", "", err
	}
	raw = PATPrefix + r
	return raw, HashPAT(raw), raw[:12], nil
}

// HashPAT returns the sha256 hex of a raw token (what the DB stores).
func HashPAT(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ParseBearerPAT returns the sirpat_ credential from an Authorization header value.
// "Bearer" and the sirpat_ prefix are matched case-insensitively and any whitespace
// separates them, so everything nginx might classify as a sirpat token is treated as
// one here (and fails closed if it is wrong). ok is false for anything else: no
// header, another scheme, or a non-sirpat bearer such as an OAuth access token.
func ParseBearerPAT(header string) (raw string, ok bool) {
	h := strings.TrimSpace(header)
	i := strings.IndexFunc(h, unicode.IsSpace)
	if i < 0 || !strings.EqualFold(h[:i], "Bearer") {
		return "", false
	}
	cred := strings.TrimSpace(h[i:])
	if len(cred) < len(PATPrefix) || !strings.EqualFold(cred[:len(PATPrefix)], PATPrefix) {
		return "", false
	}
	return cred, true
}
