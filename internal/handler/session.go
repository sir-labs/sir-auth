package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sir-labs/sir-auth/internal/model"
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
		if cookieIdentity(r) != nil { // already signed in
			http.Redirect(w, r, safeRedirect(rawRD(r.URL.RawQuery)), http.StatusFound)
			return
		}
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
		if !user.Approved {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			renderSessionLogin(w, rd, pendingMsg)
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

const pendingMsg = "Your account is waiting for admin approval."

func renderSessionLogin(w http.ResponseWriter, rd, errorMsg string) {
	footer := ""
	if registerAllowed() {
		footer = authLink("Don't have an account?", "/register?rd="+rd, "Register")
	}
	renderAuthForm(w, "Sign in — SIR Labs", "Sign in to SIR Labs", "/login", hiddenRD(rd), "", "Continue", footer, errorMsg)
}

func hiddenRD(rd string) string {
	return fmt.Sprintf(`<input type="hidden" name="rd" value="%s">`, htmlEscape(rd))
}

// authLink renders the "question? link" line under a card; href is escaped.
func authLink(text, href, label string) string {
	return fmt.Sprintf(`<p class="mt-6 text-sm text-center text-[#5b616e]">%s <a href="%s" class="font-semibold text-[#0052ff] hover:underline">%s</a></p>`,
		htmlEscape(text), htmlEscape(href), htmlEscape(label))
}

// Logout handles GET/POST /logout: clears the session cookie.
func Logout(w http.ResponseWriter, r *http.Request) {
	setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// sessionUser returns the signed-in user, re-checked against the DB (exists, approved,
// cookie not ended by sessions_valid_after). Otherwise it redirects to /login (or
// writes 500 if the DB fails) and returns nil.
func sessionUser(w http.ResponseWriter, r *http.Request, s *store.Store) *model.User {
	claims := sessionClaims(r)
	var u *model.User
	if claims != nil {
		var err error
		if u, err = s.GetUserByID(r.Context(), claims.Sub); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return nil
		}
	}
	if claims == nil || u == nil || !u.Approved || claims.Iat < u.SessionsValidAfter {
		rd := "/"
		if r.Method == http.MethodGet {
			rd = r.URL.RequestURI()
		}
		http.Redirect(w, r, "/login?rd=https://"+r.Host+rd, http.StatusFound)
		return nil
	}
	return u
}
