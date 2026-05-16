package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/syumai/workers/cloudflare"

	"github.com/sir-labs/sir-auth/internal/token"
)

type contextKey string

const claimsKey contextKey = "claims"

// AuthMiddleware validates the Bearer JWT and injects Claims into the request context.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			WriteError(w, "missing or invalid authorization header", http.StatusUnauthorized)
			return
		}
		rawToken := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := token.ValidateAccessToken(rawToken, cloudflare.Getenv("JWT_SECRET"))
		if err != nil {
			WriteError(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole allows the request only if the JWT role matches (admin bypasses all).
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromCtx(r.Context())
			if claims == nil {
				WriteError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if claims.Role != role && claims.Role != "admin" {
				WriteError(w, "forbidden: requires role "+role, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClaimsFromCtx extracts JWT claims injected by AuthMiddleware.
func ClaimsFromCtx(ctx context.Context) *token.Claims {
	c, _ := ctx.Value(claimsKey).(*token.Claims)
	return c
}

// Chain applies middlewares right-to-left so the first in the list runs first.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

func WriteError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func WriteOAuthError(w http.ResponseWriter, errCode string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": errCode})
}
