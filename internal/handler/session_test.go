package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sir-labs/sir-auth/internal/token"
)

func TestSafeRedirect(t *testing.T) {
	t.Setenv("COOKIE_DOMAIN", ".sir-labs.com")
	cases := map[string]string{
		"https://sir-labs.com/x":            "https://sir-labs.com/x",
		"https://app.sir-labs.com/a?b=1":    "https://app.sir-labs.com/a?b=1",
		"https://evil.com":                  "/",
		"https://evil-sir-labs.com":         "/",
		"https://sir-labs.com.evil.com":     "/",
		"http://app.sir-labs.com":           "/",
		"//evil.com":                        "/",
		"":                                  "/",
		"https://app.sir-labs.com@evil.com": "/",
	}
	for in, want := range cases {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRawRD(t *testing.T) {
	cases := map[string]string{
		"rd=https://app.sir-labs.com/p?a=1&b=2":   "https://app.sir-labs.com/p?a=1&b=2",
		"x=1&rd=https://app.sir-labs.com/?q&rd=z": "https://app.sir-labs.com/?q&rd=z",
		"xrd=https://evil.com":                    "",
		"":                                        "",
	}
	for in, want := range cases {
		if got := rawRD(in); got != want {
			t.Errorf("rawRD(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifySession(t *testing.T) {
	t.Setenv("JWT_SECRET", "s")
	rec := httptest.NewRecorder()
	VerifySession(rec, httptest.NewRequest("GET", "/session/verify", nil))
	if rec.Code != http.StatusUnauthorized || rec.Body.Len() != 0 {
		t.Fatalf("no cookie: got %d %q", rec.Code, rec.Body.String())
	}

	jwt, _ := token.GenerateToken("u1", "a@b.c", "admin", "session", "s", sessionTTL())
	req := httptest.NewRequest("GET", "/session/verify", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: jwt})
	rec = httptest.NewRecorder()
	VerifySession(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Auth-Email") != "a@b.c" || rec.Header().Get("X-Auth-User-Id") != "u1" || rec.Header().Get("X-Auth-Role") != "admin" {
		t.Fatalf("valid cookie: got %d %v", rec.Code, rec.Header())
	}
}
