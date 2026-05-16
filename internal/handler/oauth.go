package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/syumai/workers/cloudflare"

	"github.com/sir-labs/sir-auth/internal/middleware"
	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
)

// Authorize handles GET /oauth/authorize (login form) and POST /oauth/authorize (submit).
func Authorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		showLoginForm(w, r)
	case http.MethodPost:
		processAuthorize(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func showLoginForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	scope := q.Get("scope")

	if responseType != "code" {
		middleware.WriteError(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}
	if clientID == "" || redirectURI == "" {
		middleware.WriteError(w, "invalid_request: missing client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if !isLoopbackURI(redirectURI) {
		middleware.WriteError(w, "invalid_request: redirect_uri must be a loopback address (RFC 8252 §8.3)", http.StatusBadRequest)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	client, err := s.GetClientByID(r.Context(), clientID)
	if err != nil || client == nil {
		middleware.WriteError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	if scope == "" {
		scope = "openid"
	}

	renderLoginForm(w, client.Name, clientID, redirectURI, state, scope, "")
}

func processAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		middleware.WriteError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := r.FormValue("scope")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if !isLoopbackURI(redirectURI) {
		middleware.WriteError(w, "invalid_request: invalid redirect_uri", http.StatusBadRequest)
		return
	}

	s, err := store.Open()
	if err != nil {
		redirectWithError(w, r, redirectURI, state, "server_error")
		return
	}
	defer s.Close()

	client, err := s.GetClientByID(r.Context(), clientID)
	if err != nil || client == nil {
		redirectWithError(w, r, redirectURI, state, "invalid_client")
		return
	}

	user, err := s.GetUserByEmail(r.Context(), email)
	if err != nil || user == nil || !token.VerifyPassword(password, user.PasswordHash, user.Salt) {
		renderLoginForm(w, client.Name, clientID, redirectURI, state, scope, "Incorrect email or password. Please try again.")
		return
	}

	if scope == "" {
		scope = "openid"
	}

	ac, err := s.CreateAuthCode(r.Context(), clientID, user.ID, redirectURI, scope)
	if err != nil {
		redirectWithError(w, r, redirectURI, state, "server_error")
		return
	}

	callbackURL := redirectURI + "?code=" + url.QueryEscape(ac.Code)
	if state != "" {
		callbackURL += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// Token handles POST /oauth/token
func Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		middleware.WriteOAuthError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		exchangeAuthCode(w, r)
	case "refresh_token":
		exchangeRefreshToken(w, r)
	default:
		middleware.WriteOAuthError(w, "unsupported_grant_type", http.StatusBadRequest)
	}
}

func exchangeAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if code == "" || redirectURI == "" || clientID == "" || clientSecret == "" {
		middleware.WriteOAuthError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	client, err := s.GetClientByID(r.Context(), clientID)
	if err != nil || client == nil || client.ClientSecret != clientSecret {
		middleware.WriteOAuthError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	ac, err := s.ConsumeAuthCode(r.Context(), code)
	if err != nil {
		if err.Error() == "code invalid or expired" {
			middleware.WriteOAuthError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}
	if ac == nil || time.Now().Unix() > ac.ExpiresAt || ac.ClientID != clientID {
		middleware.WriteOAuthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if !loopbackURIMatches(ac.RedirectURI, redirectURI) {
		middleware.WriteOAuthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	user, err := s.GetUserByID(r.Context(), ac.UserID)
	if err != nil || user == nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	accessToken, err := token.GenerateAccessToken(user.ID, user.Email, user.Role, ac.Scope, cloudflare.Getenv("JWT_SECRET"))
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	rt, err := s.CreateRefreshToken(r.Context(), user.ID, clientID, ac.Scope)
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	s.CreateSystemLog(r.Context(), model.SystemLog{
		Action:   "USER_LOGIN",
		TargetID: user.ID,
		AdminID:  user.ID,
		Details:  "User logged in via Authorization Code: " + user.Email,
	})

	writeTokenResponse(w, accessToken, rt.Token, ac.Scope)
}

func exchangeRefreshToken(w http.ResponseWriter, r *http.Request) {
	rawToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if rawToken == "" || clientID == "" || clientSecret == "" {
		middleware.WriteOAuthError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	client, err := s.GetClientByID(r.Context(), clientID)
	if err != nil || client == nil || client.ClientSecret != clientSecret {
		middleware.WriteOAuthError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	rt, err := s.GetRefreshToken(r.Context(), rawToken)
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}
	if rt == nil || rt.Revoked || rt.ClientID != clientID || time.Now().Unix() > rt.ExpiresAt {
		middleware.WriteOAuthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	user, err := s.GetUserByID(r.Context(), rt.UserID)
	if err != nil || user == nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	if err := s.RevokeRefreshToken(r.Context(), rawToken); err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	accessToken, err := token.GenerateAccessToken(user.ID, user.Email, user.Role, rt.Scope, cloudflare.Getenv("JWT_SECRET"))
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	newRT, err := s.CreateRefreshToken(r.Context(), user.ID, clientID, rt.Scope)
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	writeTokenResponse(w, accessToken, newRT.Token, rt.Scope)
}

// Revoke handles POST /oauth/revoke (RFC 7009)
func Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil || r.FormValue("token") == "" {
		middleware.WriteOAuthError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	_ = s.RevokeRefreshToken(r.Context(), r.FormValue("token"))
	w.WriteHeader(http.StatusOK)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func isLoopbackURI(rawURI string) bool {
	u, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		return h == "127.0.0.1" || h == "localhost" || h == "::1"
	}
	return false
}

func loopbackURIMatches(registered, request string) bool {
	reg, err1 := url.Parse(registered)
	req, err2 := url.Parse(request)
	if err1 != nil || err2 != nil {
		return false
	}
	if reg.Scheme == "https" {
		return registered == request
	}
	return reg.Scheme == req.Scheme &&
		strings.EqualFold(reg.Hostname(), req.Hostname()) &&
		reg.Path == req.Path
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode string) {
	u := redirectURI + "?error=" + url.QueryEscape(errCode)
	if state != "" {
		u += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func writeTokenResponse(w http.ResponseWriter, accessToken, refreshToken, scope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(token.AccessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
		"scope":         scope,
	})
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func renderLoginForm(w http.ResponseWriter, clientName, clientID, redirectURI, state, scope, errorMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`
		<div class="w-full p-4 mb-6 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm flex items-start gap-3 text-left">
		  <svg class="w-5 h-5 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
		  <span>%s</span>
		</div>`, htmlEscape(errorMsg))
	}

	fmt.Fprintf(w, loginFormHTML,
		htmlEscape(clientName),
		htmlEscape(clientName),
		errorHTML,
		htmlEscape(clientID),
		htmlEscape(redirectURI),
		htmlEscape(state),
		htmlEscape(scope),
	)
}

const loginFormHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sign in — %s</title>
  <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.2/dist/full.min.css" rel="stylesheet" type="text/css" />
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #020617; color: #f1f5f9; font-family: system-ui, -apple-system, sans-serif; overflow-x: hidden; }
    .glass-panel { background: rgba(15, 23, 42, 0.4); backdrop-filter: blur(24px); border: 1px solid rgba(255,255,255,0.1); box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
    .glass-btn { background: linear-gradient(to right, #7c3aed, #4f46e5); transition: all 0.3s; border: none; }
    .glass-btn:hover { transform: translateY(-2px); box-shadow: 0 0 20px rgba(99,102,241,0.6); }
    .ambient-orb { position: absolute; border-radius: 50%%; mix-blend-mode: screen; pointer-events: none; }
    @keyframes float { 0%%, 100%% { transform: translateY(0) scale(1); } 50%% { transform: translateY(-20px) scale(1.05); } }
    @keyframes slide-up { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .orb-1 { animation: float 10s infinite ease-in-out; }
    .orb-2 { animation: float 12s infinite ease-in-out reverse; }
    .animate-slide-up { animation: slide-up 0.5s ease-out forwards; }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center relative">
  <div class="ambient-orb orb-1 bg-violet-600/30 w-[500px] h-[500px] top-[-10%%] left-[-10%%] blur-[80px]"></div>
  <div class="ambient-orb orb-2 bg-indigo-600/20 w-[600px] h-[600px] bottom-[-20%%] right-[-10%%] blur-[100px]"></div>

  <div class="relative z-10 w-full max-w-md px-6 animate-slide-up">
    <div class="glass-panel rounded-3xl p-10 flex flex-col items-center text-center">
      <div class="w-20 h-20 mb-6 flex items-center justify-center rounded-3xl bg-gradient-to-tr from-violet-500/20 to-fuchsia-500/20 border border-white/20 shadow-[0_0_30px_rgba(139,92,246,0.3)]">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="w-10 h-10 text-white"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
      </div>

      <h1 class="text-3xl font-extrabold tracking-tight mb-2 bg-gradient-to-br from-white via-indigo-100 to-indigo-400 bg-clip-text text-transparent">Authorize Access</h1>
      <p class="text-slate-400 text-sm font-medium tracking-wide mb-8 uppercase">SIGN IN TO %s</p>

      %s

      <form method="POST" action="/oauth/authorize" class="w-full flex flex-col gap-5 text-left">
        <input type="hidden" name="client_id" value="%s">
        <input type="hidden" name="redirect_uri" value="%s">
        <input type="hidden" name="state" value="%s">
        <input type="hidden" name="scope" value="%s">

        <div class="form-control w-full">
          <div class="relative">
            <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <svg class="w-5 h-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" /></svg>
            </div>
            <input type="email" name="email" required placeholder="Email Address" class="input w-full pl-12 bg-slate-900/50 border border-white/10 text-white placeholder-slate-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all rounded-xl h-12">
          </div>
        </div>

        <div class="form-control w-full">
          <div class="relative">
            <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <svg class="w-5 h-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            </div>
            <input type="password" name="password" required placeholder="Password" class="input w-full pl-12 bg-slate-900/50 border border-white/10 text-white placeholder-slate-500 focus:border-fuchsia-500 focus:ring-1 focus:ring-fuchsia-500 transition-all rounded-xl h-12">
          </div>
        </div>

        <button type="submit" class="btn glass-btn w-full h-14 mt-2 rounded-2xl text-white font-semibold text-lg shadow-lg">Authenticate</button>
      </form>
    </div>
  </div>
</body>
</html>`
