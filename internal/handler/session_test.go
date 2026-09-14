package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/sir-labs/sir-auth/internal/model"
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

func TestValidateRegistration(t *testing.T) {
	cases := []struct{ email, pw, confirm, want string }{
		{"a@b.co", "12345678", "12345678", ""},
		{"not-an-email", "12345678", "12345678", "Please enter a valid email address."},
		{"Bob <a@b.co>", "12345678", "12345678", "Please enter a valid email address."},
		{"a@b.co", "1234567", "1234567", "Password must be at least 8 characters."},
		{"a@b.co", "12345678", "12345679", "Passwords do not match."},
	}
	for _, c := range cases {
		if got := validateRegistration(c.email, c.pw, c.confirm); got != c.want {
			t.Errorf("validateRegistration(%q) = %q, want %q", c.email, got, c.want)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		origin, referer string
		want            bool
	}{
		{"https://auth.sir-labs.com", "", true},
		{"https://evil.com", "https://auth.sir-labs.com/admin", false},
		{"", "https://auth.sir-labs.com/admin", true},
		{"", "https://evil.com/auth.sir-labs.com", false},
		{"null", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "https://auth.sir-labs.com/admin/approve", nil)
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if c.referer != "" {
			req.Header.Set("Referer", c.referer)
		}
		if got := sameOrigin(req); got != c.want {
			t.Errorf("sameOrigin(origin=%q, referer=%q) = %v, want %v", c.origin, c.referer, got, c.want)
		}
	}
}

func TestCheckAdminAction(t *testing.T) {
	admin := model.User{ID: "a1", Role: "admin", Approved: true}
	other := model.User{ID: "a2", Role: "admin", Approved: true}
	pending := model.User{ID: "u1", Role: "user"}
	allowed := func(action string, target model.User, admins int) bool {
		return checkAdminAction(action, admin.ID, target, admins) == ""
	}
	if !allowed("approve", pending, 1) || !allowed("reject", pending, 1) {
		t.Error("approve/reject of pending user should be allowed")
	}
	if allowed("reject", other, 2) {
		t.Error("reject of approved user should be refused")
	}
	if allowed("delete", admin, 2) || allowed("revoke", admin, 2) {
		t.Error("acting on yourself should be refused")
	}
	if allowed("delete", other, 1) || allowed("revoke", other, 1) {
		t.Error("removing the last admin should be refused")
	}
	if !allowed("revoke", other, 2) || !allowed("delete", other, 2) {
		t.Error("removing a non-last admin should be allowed")
	}
	if allowed("bogus", pending, 1) {
		t.Error("unknown action should be refused")
	}
}
