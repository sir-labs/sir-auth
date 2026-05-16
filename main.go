package main

import (
	"encoding/json"
	"net/http"

	"github.com/syumai/workers"

	"github.com/sir-labs/sir-auth/internal/handler"
	"github.com/sir-labs/sir-auth/internal/middleware"
)

func main() {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/health", handleHealth)

	// OAuth 2.0 Authorization Code Flow (RFC 8252)
	mux.HandleFunc("/oauth/authorize", handler.Authorize)
	mux.HandleFunc("/oauth/token", handler.Token)
	mux.HandleFunc("/oauth/revoke", handler.Revoke)

	// Initial setup: creates first admin user + default client (runs once)
	mux.HandleFunc("/setup", handler.Setup)

	// Public: self-registration
	mux.HandleFunc("/register", handler.Register)

	// Protected: any authenticated user
	mux.Handle("/api/me", middleware.Chain(
		http.HandlerFunc(handler.Me),
		middleware.AuthMiddleware,
	))

	mux.Handle("/api/users/", middleware.Chain(
		http.HandlerFunc(handler.GetUser),
		middleware.AuthMiddleware,
	))

	// Protected: admin only
	mux.Handle("/api/admin/users", middleware.Chain(
		http.HandlerFunc(handler.AdminUsers),
		middleware.AuthMiddleware,
	))

	mux.Handle("/api/admin/users/", middleware.Chain(
		http.HandlerFunc(handler.AdminUserDetail),
		middleware.AuthMiddleware,
	))

	mux.Handle("/api/admin/logs", middleware.Chain(
		http.HandlerFunc(handler.AdminLogs),
		middleware.AuthMiddleware,
	))

	workers.Serve(middleware.CORSMiddleware(mux))
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"name":    "sir-auth",
		"version": "1.0.0",
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
