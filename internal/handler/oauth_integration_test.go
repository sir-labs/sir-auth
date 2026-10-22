package handler

import (
	"context"
	"encoding/json"
	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestNativeOAuthIntegration(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("isolated PostgreSQL required")
	}
	t.Setenv("DATABASE_URL", os.Getenv("TEST_DATABASE_URL"))
	t.Setenv("JWT_SECRET", "integration-test-only-secret")
	s, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	hash, salt, _ := token.HashPassword("test-password")
	err = s.CreateUser(context.Background(), model.User{ID: "pkce-test", Email: "pkce@test.invalid", PasswordHash: hash, Salt: salt, Role: "user", Approved: true})
	if err != nil {
		t.Fatal(err)
	}
	post := func(handler http.HandlerFunc, values url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "https://auth.sir-labs.com/oauth/token", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}
	authorize := func() string {
		w := post(Authorize, url.Values{"client_id": {"note-app-desktop"}, "redirect_uri": {"http://127.0.0.1:12345/callback"}, "state": {"012345678901234567890123456789012345"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}, "email": {"pkce@test.invalid"}, "password": {"test-password"}})
		if w.Code != 302 {
			t.Fatalf("authorize status %d", w.Code)
		}
		u, _ := url.Parse(w.Header().Get("Location"))
		return u.Query().Get("code")
	}
	exchange := func(code, verifier string) *httptest.ResponseRecorder {
		return post(Token, url.Values{"grant_type": {"authorization_code"}, "client_id": {"note-app-desktop"}, "redirect_uri": {"http://127.0.0.1:12345/callback"}, "code": {code}, "code_verifier": {verifier}})
	}
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if exchange(authorize(), verifier+"x").Code != 400 {
		t.Fatal("bad proof accepted")
	}
	code := authorize()
	w := exchange(code, verifier)
	if w.Code != 200 {
		t.Fatalf("exchange %d", w.Code)
	}
	if exchange(code, verifier).Code != 400 {
		t.Fatal("code replay accepted")
	}
	var tokens map[string]any
	json.Unmarshal(w.Body.Bytes(), &tokens)
	raw := tokens["refresh_token"].(string)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- post(Token, url.Values{"grant_type": {"refresh_token"}, "client_id": {"note-app-desktop"}, "refresh_token": {raw}}).Code
		}()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 200 {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("refresh succeeded %d times", successes)
	}
	// Confidential clients still require their existing secret.
	if err := s.CreateClient(context.Background(), model.OAuthClient{ClientID: "legacy-test", ClientSecret: "secret", Name: "Legacy"}); err != nil {
		t.Fatal(err)
	}
	legacy, _ := s.CreateAuthCode(context.Background(), "legacy-test", "pkce-test", "http://127.0.0.1:1234/callback", "openid")
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {"legacy-test"}, "redirect_uri": {"http://127.0.0.1:1234/callback"}, "code": {legacy.Code}}
	if post(Token, values).Code != 401 {
		t.Fatal("legacy secret was optional")
	}
	values.Set("client_secret", "secret")
	if post(Token, values).Code != 200 {
		t.Fatal("legacy flow broken")
	}
}
