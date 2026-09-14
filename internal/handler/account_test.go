package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/token"
)

func TestTTLCache(t *testing.T) {
	calls := 0
	var fail bool
	c := newTTLCache(50*time.Millisecond, 3, func(_ context.Context, k string) (*string, error) {
		calls++
		if fail {
			return nil, errors.New("db down")
		}
		if k == "missing" {
			return nil, nil
		}
		v := k + "!"
		return &v, nil
	})
	ctx := context.Background()

	if v, _ := c.Get(ctx, "a"); *v != "a!" {
		t.Fatal("wrong value")
	}
	c.Get(ctx, "a")
	if calls != 1 {
		t.Fatalf("hit should not reload: calls=%d", calls)
	}
	if v, _ := c.Get(ctx, "missing"); v != nil {
		t.Fatal("miss should be nil")
	}
	c.Get(ctx, "missing")
	if calls != 2 {
		t.Fatalf("miss should be cached: calls=%d", calls)
	}

	time.Sleep(60 * time.Millisecond)
	fail = true
	if v, err := c.Get(ctx, "a"); err != nil || *v != "a!" {
		t.Fatalf("expired + reload error should serve stale: %v %v", v, err)
	}
	if _, err := c.Get(ctx, "b"); err == nil {
		t.Fatal("error with nothing cached should be returned")
	}
	fail = false

	c.Get(ctx, "b") // a, missing, b → 3 entries
	c.Get(ctx, "c") // at cap: cleared, then c
	c.mu.Lock()
	n := len(c.m)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("cache should be cleared at cap, has %d", n)
	}

	c.Clear()
	before := calls
	c.Get(ctx, "c")
	if calls != before+1 {
		t.Fatal("Clear should force a reload")
	}
}

// stubAuth replaces the DB loaders for one test.
func stubAuth(t *testing.T, users map[string]*model.User, tokens map[string]*model.APIToken, dbErr bool) {
	oldU, oldT := loadUser, loadToken
	loadUser = func(_ context.Context, id string) (*model.User, error) {
		if dbErr {
			return nil, errors.New("db down")
		}
		if u := users[id]; u != nil {
			c := *u // copy, like a real DB read
			return &c, nil
		}
		return nil, nil
	}
	loadToken = func(_ context.Context, h string) (*model.APIToken, error) {
		if dbErr {
			return nil, errors.New("db down")
		}
		return tokens[h], nil
	}
	invalidateAuth()
	t.Cleanup(func() { loadUser, loadToken = oldU, oldT; invalidateAuth() })
}

func TestVerifyMatrix(t *testing.T) {
	t.Setenv("JWT_SECRET", "s")
	now := time.Now().Unix()
	past, future := now-10, now+3600
	users := map[string]*model.User{
		"u1":  {ID: "u1", Email: "a@b.c", Role: "admin", Approved: true},
		"u2":  {ID: "u2", Email: "p@b.c", Role: "user", Approved: false},
		"u3":  {ID: "u3", Email: "o@b.c", Role: "user", Approved: true, SessionsValidAfter: now + 60},
		"new": {ID: "new", Email: "new@b.c", Role: "user", Approved: true},
	}
	tok := func(id, user string, exp, rev *int64) (string, *model.APIToken) {
		raw := "sirpat_" + id
		return raw, &model.APIToken{ID: id, UserID: user, TokenHash: token.HashPAT(raw), ExpiresAt: exp, RevokedAt: rev}
	}
	tokens := map[string]*model.APIToken{}
	raws := map[string]string{}
	for _, tc := range []struct {
		id, user string
		exp, rev *int64
	}{{"good", "u1", &future, nil}, {"never", "u1", nil, nil}, {"expired", "u1", &past, nil}, {"revoked", "u1", nil, &past}, {"pending", "u2", nil, nil}} {
		raw, t := tok(tc.id, tc.user, tc.exp, tc.rev)
		tokens[t.TokenHash] = t
		raws[tc.id] = raw
	}
	jwt := func(sub string) string {
		j, _ := token.GenerateToken(sub, sub+"@jwt", "user", "session", "s", time.Hour)
		return j
	}

	cases := []struct {
		name   string
		cookie string
		auth   string
		dbErr  bool
		want   int
		wantID string
	}{
		{"nothing", "", "", false, 401, ""},
		{"valid cookie", jwt("u1"), "", false, 200, "u1"},
		{"bad cookie", "garbage", "", false, 401, ""},
		{"unapproved cookie", jwt("u2"), "", false, 401, ""},
		{"cookie before valid_after", jwt("u3"), "", false, 401, ""},
		{"deleted user cookie", jwt("gone"), "", false, 401, ""},
		{"db down cookie fails open", jwt("gone"), "", true, 200, "gone"},
		{"valid token", "", "Bearer " + raws["good"], false, 200, "u1"},
		{"lowercase bearer", "", "bearer " + raws["never"], false, 200, "u1"},
		{"expired token", "", "Bearer " + raws["expired"], false, 401, ""},
		{"revoked token", "", "Bearer " + raws["revoked"], false, 401, ""},
		{"unapproved owner", "", "Bearer " + raws["pending"], false, 401, ""},
		{"unknown token", "", "Bearer sirpat_nope", false, 401, ""},
		{"bad token + valid cookie", jwt("u1"), "Bearer sirpat_nope", false, 401, ""},
		{"db down token fails closed", "", "Bearer " + raws["good"], true, 401, ""},
		{"non-sirpat bearer uses cookie", jwt("u1"), "Bearer eyJ.x.y", false, 200, "u1"},
		{"non-sirpat bearer alone", "", "Bearer eyJ.x.y", false, 401, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubAuth(t, users, tokens, c.dbErr)
			req := httptest.NewRequest("GET", "/session/verify", nil)
			req.Header.Set("X-Original-URI", "/x?y=1")
			if c.cookie != "" {
				req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
			}
			if c.auth != "" {
				req.Header.Set("Authorization", c.auth)
			}
			rec := httptest.NewRecorder()
			VerifySession(rec, req)
			if rec.Code != c.want {
				t.Fatalf("got %d, want %d", rec.Code, c.want)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("body must be empty, got %q", rec.Body.String())
			}
			if got := rec.Header().Get("X-Auth-User-Id"); got != c.wantID {
				t.Fatalf("X-Auth-User-Id = %q, want %q", got, c.wantID)
			}
			if c.want == 200 && rec.Header().Get("X-Auth-Email") == "" {
				t.Fatal("missing X-Auth-Email")
			}
		})
	}
}

func TestVerifyInvalidation(t *testing.T) {
	t.Setenv("JWT_SECRET", "s")
	u := &model.User{ID: "u1", Email: "a@b.c", Role: "user", Approved: true}
	stubAuth(t, map[string]*model.User{"u1": u}, nil, false)
	j, _ := token.GenerateToken("u1", "a@b.c", "user", "session", "s", time.Hour)
	call := func() int {
		req := httptest.NewRequest("GET", "/session/verify", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: j})
		rec := httptest.NewRecorder()
		VerifySession(rec, req)
		return rec.Code
	}
	if call() != 200 {
		t.Fatal("first call should pass")
	}
	u.Approved = false // DB change; still cached
	if call() != 200 {
		t.Fatal("cached user should still pass")
	}
	invalidateAuth()
	if call() != 401 {
		t.Fatal("after invalidation the change must apply immediately")
	}
}

func TestRequestPath(t *testing.T) {
	cases := map[string]string{
		"/a/b?x=1&y=2": "/a/b",
		"/plain":       "/plain",
		"":             "/",
		"?only=query":  "/",
	}
	for in, want := range cases {
		if got := requestPath(in); got != want {
			t.Errorf("requestPath(%q) = %q, want %q", in, got, want)
		}
	}
	long := "/" + strings.Repeat("a", 600)
	if got := requestPath(long); len(got) != 512 {
		t.Errorf("long path len = %d, want 512", len(got))
	}
	utf := "/" + strings.Repeat("ก", 300) // 3 bytes each: cut must not leave a broken rune
	if got := requestPath(utf); len(got) > 512 || !strings.HasPrefix(utf, got) || strings.ContainsRune(got, '�') {
		t.Errorf("utf8 cap broken: len=%d", len(got))
	}
}

func TestRelTime(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		d    time.Duration
		want string
	}{
		{-10 * time.Second, "just now"},
		{-3 * time.Minute, "3 min ago"},
		{-5 * time.Hour, "5 h ago"},
		{-24 * time.Hour, "1 day ago"},
		{-3 * 24 * time.Hour, "3 days ago"},
		{-90 * 24 * time.Hour, "3 months ago"},
		{-800 * 24 * time.Hour, "2 years ago"},
		{5 * 24 * time.Hour, "in 5 days"},
		{30 * time.Minute, "in 30 min"},
	}
	for _, c := range cases {
		if got := relTime(now.Add(c.d), now); got != c.want {
			t.Errorf("relTime(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestCheckSelfDelete(t *testing.T) {
	admin := model.User{Role: "admin", Approved: true}
	if checkSelfDelete(admin, 1) != "last-admin" {
		t.Error("last approved admin must be refused")
	}
	if checkSelfDelete(admin, 2) != "" {
		t.Error("admin with another admin may delete")
	}
	if checkSelfDelete(model.User{Role: "user", Approved: true}, 1) != "" {
		t.Error("user may delete")
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct{ pw, confirm, want string }{
		{"12345678", "12345678", ""},
		{"1234567", "1234567", "pw-short"},
		{"12345678", "12345679", "pw-mismatch"},
	}
	for _, c := range cases {
		if got := validatePassword(c.pw, c.confirm); got != c.want {
			t.Errorf("validatePassword(%q,%q) = %q, want %q", c.pw, c.confirm, got, c.want)
		}
		if c.want != "" && flashErr[c.want] == "" {
			t.Errorf("no flash message for %q", c.want)
		}
	}
}

func TestParseExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for v, days := range map[string]int{"30": 30, "90": 90, "365": 365} {
		e, ok := parseExpiry(v, now)
		if !ok || e == nil || *e != now.AddDate(0, 0, days).Unix() {
			t.Errorf("parseExpiry(%q) = %v %v", v, e, ok)
		}
	}
	if e, ok := parseExpiry("never", now); !ok || e != nil {
		t.Error("never should be ok with nil expiry")
	}
	for _, bad := range []string{"", "7", "-1", "forever"} {
		if _, ok := parseExpiry(bad, now); ok {
			t.Errorf("parseExpiry(%q) should fail", bad)
		}
	}
}

func TestParseWindow(t *testing.T) {
	now := time.Date(2026, 9, 14, 5, 0, 0, 0, time.UTC)
	w := parseWindow(map[string][]string{"from": {"2025-09-01"}, "to": {"2025-09-02"}}, now)
	if w.Preset != "" || w.From.In(bkk).Format("2006-01-02 15") != "2025-09-01 00" || w.To.Sub(w.From) != 48*time.Hour {
		t.Errorf("date range: %+v", w)
	}
	if w := parseWindow(map[string][]string{"range": {"30d"}}, now); w.Preset != "30d" || now.Sub(w.From) != 30*24*time.Hour {
		t.Errorf("30d: %+v", w)
	}
	if w := parseWindow(map[string][]string{"from": {"2025-09-05"}, "to": {"2025-09-01"}}, now); w.Preset != "7d" {
		t.Errorf("reversed range should fall back to 7d: %+v", w)
	}
}
