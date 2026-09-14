package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
)

const sessionCookie = "sir_session"

func cookieDomain() string {
	if d := os.Getenv("COOKIE_DOMAIN"); d != "" {
		return d
	}
	return ".sir-labs.com"
}

func sessionTTL() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("SESSION_TTL")); err == nil && d > 0 {
		return d
	}
	return 7 * 24 * time.Hour
}

// safeRedirect returns rd only if it is https on the cookie domain (apex or subdomain), else "/".
func safeRedirect(rd string) string {
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "https" {
		return "/"
	}
	apex := strings.TrimPrefix(cookieDomain(), ".")
	host := strings.ToLower(u.Hostname())
	if host == apex || strings.HasSuffix(host, "."+apex) {
		return rd
	}
	return "/"
}

// rawRD returns everything after the first "rd=" verbatim: nginx sends rd as the
// last, unencoded param (it may contain its own ? and &).
func rawRD(rawQuery string) string {
	i := strings.Index("&"+rawQuery, "&rd=")
	if i < 0 {
		return ""
	}
	return rawQuery[i+3:]
}

func sessionClaims(r *http.Request) *token.Claims {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	claims, err := token.ValidateAccessToken(c.Value, os.Getenv("JWT_SECRET"))
	if err != nil {
		return nil
	}
	return claims
}

func setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Domain:   cookieDomain(),
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Login handles GET /login?rd=<url> (form) and POST /login (email, password, rd).
func Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderSessionLogin(w, rawRD(r.URL.RawQuery), "")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		rd := r.FormValue("rd")
		s, err := store.Open()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		user, err := s.GetUserByEmail(r.Context(), r.FormValue("email"))
		if err != nil || user == nil || !token.VerifyPassword(r.FormValue("password"), user.PasswordHash, user.Salt) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			renderSessionLogin(w, rd, "Incorrect email or password. Please try again.")
			return
		}
		ttl := sessionTTL()
		jwt, err := token.GenerateToken(user.ID, user.Email, user.Role, "session", os.Getenv("JWT_SECRET"), ttl)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		setSessionCookie(w, jwt, int(ttl.Seconds()))
		http.Redirect(w, r, safeRedirect(rd), http.StatusFound)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func renderSessionLogin(w http.ResponseWriter, rd, errorMsg string) {
	renderForm(w, "SIR Labs", "/login", fmt.Sprintf(`<input type="hidden" name="rd" value="%s">`, htmlEscape(rd)), errorMsg)
}

// Logout handles GET/POST /logout: clears the session cookie.
func Logout(w http.ResponseWriter, r *http.Request) {
	setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// VerifySession handles GET /session/verify for nginx auth_request (no DB hit).
func VerifySession(w http.ResponseWriter, r *http.Request) {
	claims := sessionClaims(r)
	if claims == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("X-Auth-User-Id", claims.Sub)
	w.Header().Set("X-Auth-Email", claims.Email)
	w.Header().Set("X-Auth-Role", claims.Role)
	w.WriteHeader(http.StatusOK)
}

// Home handles GET /: shows the signed-in user or redirects to /login.
func Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	claims := sessionClaims(r)
	if claims == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SIR Labs</title></head>
<body style="font-family:Inter,-apple-system,sans-serif;padding:2rem">Logged in as %s — <a href="/logout">Log out</a></body></html>`, htmlEscape(claims.Email))
}
