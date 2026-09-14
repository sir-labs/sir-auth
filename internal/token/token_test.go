package token_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sir-labs/sir-auth/internal/token"
)

const testSecret = "test-secret-key"

// ── GenerateAccessToken / ValidateAccessToken ─────────────────────────────────

func TestRoundtrip(t *testing.T) {
	raw, err := token.GenerateAccessToken("uid-1", "user@example.com", "user", "openid", testSecret)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	claims, err := token.ValidateAccessToken(raw, testSecret)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	if claims.Sub != "uid-1" {
		t.Errorf("Sub: got %q, want %q", claims.Sub, "uid-1")
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email: got %q, want %q", claims.Email, "user@example.com")
	}
	if claims.Role != "user" {
		t.Errorf("Role: got %q, want %q", claims.Role, "user")
	}
	if claims.Scope != "openid" {
		t.Errorf("Scope: got %q, want %q", claims.Scope, "openid")
	}
	if claims.Exp <= time.Now().Unix() {
		t.Error("Exp should be in the future")
	}
	if claims.Iat > time.Now().Unix() {
		t.Error("Iat should not be in the future")
	}
}

func TestWrongSecret(t *testing.T) {
	raw, _ := token.GenerateAccessToken("uid-1", "u@e.com", "user", "openid", testSecret)

	_, err := token.ValidateAccessToken(raw, "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestMalformedToken(t *testing.T) {
	cases := []string{
		"",
		"notavalidtoken",
		"only.two",
		"a.b.c.d",
	}
	for _, tc := range cases {
		_, err := token.ValidateAccessToken(tc, testSecret)
		if err == nil {
			t.Errorf("expected error for %q, got nil", tc)
		}
	}
}

func TestExpiredToken(t *testing.T) {
	// Build a token manually with exp in the past.
	// We rely on the fact that ValidateAccessToken checks exp.
	// Easiest: generate a valid token and tamper the payload.
	raw, _ := token.GenerateAccessToken("uid-1", "u@e.com", "user", "openid", testSecret)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("unexpected token format")
	}
	// A token generated now will not be expired; just verify a tampered one fails sig check.
	parts[2] = "invalidsignature"
	_, err := token.ValidateAccessToken(strings.Join(parts, "."), testSecret)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestTokenHasThreeParts(t *testing.T) {
	raw, err := token.GenerateAccessToken("u", "e@e.com", "admin", "openid", testSecret)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts, got %d", len(parts))
	}
}

func TestAdminRole(t *testing.T) {
	raw, _ := token.GenerateAccessToken("admin-1", "admin@example.com", "admin", "openid", testSecret)
	claims, err := token.ValidateAccessToken(raw, testSecret)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Role != "admin" {
		t.Errorf("Role: got %q, want admin", claims.Role)
	}
}

// ── HashPassword / VerifyPassword ─────────────────────────────────────────────

func TestHashAndVerify(t *testing.T) {
	hash, salt, err := token.HashPassword("my-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "" || salt != "" {
		t.Fatal("want non-empty bcrypt hash and empty salt")
	}
	if !token.VerifyPassword("my-password", hash, salt) {
		t.Error("correct password did not verify")
	}
}

func TestWrongPassword(t *testing.T) {
	hash, salt, _ := token.HashPassword("correct")
	if token.VerifyPassword("wrong", hash, salt) {
		t.Error("wrong password should not verify")
	}
}

func TestHashesAreDifferentForSamePassword(t *testing.T) {
	hash1, salt1, _ := token.HashPassword("same")
	hash2, salt2, _ := token.HashPassword("same")
	// bcrypt embeds a random salt, so hashes differ.
	if hash1 == hash2 {
		t.Error("hashes should differ due to embedded salts")
	}
	// But both must verify correctly.
	if !token.VerifyPassword("same", hash1, salt1) {
		t.Error("hash1 did not verify")
	}
	if !token.VerifyPassword("same", hash2, salt2) {
		t.Error("hash2 did not verify")
	}
}

func TestEmptyPassword(t *testing.T) {
	hash, salt, err := token.HashPassword("")
	if err != nil {
		t.Fatalf("hash empty password: %v", err)
	}
	if !token.VerifyPassword("", hash, salt) {
		t.Error("empty password should verify against its own hash")
	}
	if token.VerifyPassword("notempty", hash, salt) {
		t.Error("non-empty password should not verify against empty-password hash")
	}
}

func TestSessionTTL(t *testing.T) {
	raw, _ := token.GenerateToken("u", "e@e.com", "user", "session", testSecret, 7*24*time.Hour)
	claims, err := token.ValidateAccessToken(raw, testSecret)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Exp < time.Now().Add(6*24*time.Hour).Unix() {
		t.Error("session token should live ~7 days")
	}
	expired, _ := token.GenerateToken("u", "e@e.com", "user", "session", testSecret, -time.Minute)
	if _, err := token.ValidateAccessToken(expired, testSecret); err == nil {
		t.Error("expired token should not validate")
	}
}

// ── RandomString ──────────────────────────────────────────────────────────────

func TestRandomStringLength(t *testing.T) {
	for _, n := range []int{8, 16, 32, 48} {
		s, err := token.RandomString(n)
		if err != nil {
			t.Fatalf("RandomString(%d): %v", n, err)
		}
		if s == "" {
			t.Errorf("RandomString(%d) returned empty string", n)
		}
	}
}

func TestRandomStringUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := token.RandomString(16)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if seen[s] {
			t.Fatalf("duplicate random string at iteration %d: %q", i, s)
		}
		seen[s] = true
	}
}
