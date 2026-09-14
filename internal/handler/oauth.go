package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	if !user.Approved {
		renderLoginForm(w, client.Name, clientID, redirectURI, state, scope, pendingMsg)
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

	accessToken, err := token.GenerateAccessToken(user.ID, user.Email, user.Role, ac.Scope, os.Getenv("JWT_SECRET"))
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
	if !user.Approved {
		middleware.WriteOAuthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	if err := s.RevokeRefreshToken(r.Context(), rawToken); err != nil {
		middleware.WriteOAuthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	accessToken, err := token.GenerateAccessToken(user.ID, user.Email, user.Role, rt.Scope, os.Getenv("JWT_SECRET"))
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
	hidden := fmt.Sprintf(`<input type="hidden" name="client_id" value="%s">
        <input type="hidden" name="redirect_uri" value="%s">
        <input type="hidden" name="state" value="%s">
        <input type="hidden" name="scope" value="%s">`,
		htmlEscape(clientID), htmlEscape(redirectURI), htmlEscape(state), htmlEscape(scope))
	renderForm(w, clientName, "/oauth/authorize", hidden, errorMsg)
}

// renderForm renders the shared sign-in page posting to action with the given hidden inputs.
func renderForm(w http.ResponseWriter, title, action, hiddenHTML, errorMsg string) {
	renderAuthForm(w, "Sign in — "+title, "Sign in to "+title, action, hiddenHTML, "", "Continue", "", errorMsg)
}

// renderAuthForm renders the email+password card; extraHTML goes after the password field,
// footerHTML (trusted markup) below the button.
func renderAuthForm(w http.ResponseWriter, title, heading, action, hiddenHTML, extraHTML, button, footerHTML, errorMsg string) {
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`
		<div class="w-full p-4 mb-6 rounded-[12px] bg-[#cf202f]/5 border border-[#cf202f]/20 text-[#cf202f] text-sm flex items-start gap-3 text-left">
		  <svg class="w-5 h-5 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
		  <span>%s</span>
		</div>`, htmlEscape(errorMsg))
	}
	renderPage(w, title, "max-w-[450px]", fmt.Sprintf(loginFormHTML,
		htmlEscape(heading), errorHTML, action, hiddenHTML, extraHTML, htmlEscape(button), footerHTML))
}

// renderPage writes the shared header/footer shell around a card containing bodyHTML (trusted markup).
func renderPage(w http.ResponseWriter, title, maxWidth, bodyHTML string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, pageHTML, htmlEscape(title), maxWidth, bodyHTML)
}

// showPasswordButton toggles every password field in its form between hidden and shown.
const showPasswordButton = `<button type="button" class="text-xs font-semibold text-[#0052ff] hover:underline" onclick="const f=this.closest('form'),show=this.textContent==='Show';f.querySelectorAll('input[name$=password]').forEach(i=>i.type=show?'text':'password');this.textContent=show?'Hide':'Show'">Show</button>`

// inputClass is the shared text-input style.
const inputClass = `w-full h-12 px-4 bg-white border border-[#dee1e6] rounded-[12px] text-[#0a0b0d] placeholder-[#7c828a] focus:border-[#0052ff] focus:ring-2 focus:ring-[#0052ff]/10 outline-none transition-all text-sm font-medium`

const loginFormHTML = `
      <!-- Headings -->
      <div class="text-center md:text-left mb-8">
        <h1 class="text-2xl font-semibold tracking-tight text-[#0a0b0d] mb-2">%s</h1>
        <p class="text-[#5b616e] text-sm">Use your email address and password to continue.</p>
      </div>

      <!-- Error Alert -->
      %s

      <!-- Login Form -->
      <form method="POST" action="%s" class="w-full flex flex-col gap-6">
        %s

        <div class="flex flex-col gap-2">
          <label class="text-xs font-semibold tracking-wide text-[#0a0b0d] uppercase">Email Address</label>
          <input type="email" name="email" required placeholder="name@example.com" class="` + inputClass + `">
        </div>

        <div class="flex flex-col gap-2">
          <div class="flex justify-between items-center">
            <label class="text-xs font-semibold tracking-wide text-[#0a0b0d] uppercase">Password</label>
            ` + showPasswordButton + `
          </div>
          <input type="password" name="password" required placeholder="Enter password" class="` + inputClass + `">
        </div>
        %s

        <button type="submit" class="w-full h-12 bg-[#0052ff] hover:bg-[#003ecc] text-white font-semibold rounded-full transition-all text-sm shadow-sm flex items-center justify-center gap-2 mt-2">
          %s
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>
        </button>
      </form>
      %s`

const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>%s</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background-color: #ffffff;
      color: #0a0b0d;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col justify-between">
  <!-- Header -->
  <header class="w-full h-16 border-b border-[#dee1e6] flex items-center justify-between px-6 md:px-12 bg-white">
    <div class="flex items-center gap-2">
      <div class="w-8 h-8 rounded-full bg-[#0052ff] flex items-center justify-center text-white shadow-sm">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
      </div>
      <span class="text-xl font-bold tracking-tight text-[#0a0b0d]">SIR</span>
    </div>
    <div class="text-sm font-medium text-[#5b616e]">
      Secure Authorization
    </div>
  </header>

  <!-- Main Content -->
  <main class="flex-grow flex items-center justify-center px-6 py-12 bg-[#f7f7f7]">
    <div class="w-full %s bg-white border border-[#dee1e6] rounded-[24px] p-8 md:p-10 shadow-[0_4px_12px_rgba(0,0,0,0.02)]">
%s
    </div>
  </main>

  <!-- Footer -->
  <footer class="w-full py-6 border-t border-[#dee1e6] flex flex-col md:flex-row items-center justify-between px-6 md:px-12 bg-white text-xs text-[#7c828a] gap-4">
    <div class="flex items-center gap-4">
      <span>© 2026 SIR Labs</span>
      <span class="w-1.5 h-1.5 rounded-full bg-[#dee1e6]"></span>
      <span>Regulated and Secured</span>
    </div>
    <div class="flex gap-6">
      <a href="#" class="hover:text-[#0052ff] transition-colors">Privacy Policy</a>
      <a href="#" class="hover:text-[#0052ff] transition-colors">Terms of Service</a>
    </div>
  </footer>
</body>
</html>`
