package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/sir-labs/sir-auth/internal/handler"
	"github.com/sir-labs/sir-auth/internal/middleware"
	"github.com/sir-labs/sir-auth/internal/store"
)

func main() {
	// Connect + migrate at boot so a bad DATABASE_URL fails fast.
	if _, err := store.Open(); err != nil {
		log.Fatalf("database: %v", err)
	}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/", handler.Home)
	mux.HandleFunc("/health", handleHealth)

	// Browser session for *.sir-labs.com (nginx auth_request)
	mux.HandleFunc("/login", handler.Login)
	mux.HandleFunc("/logout", handler.Logout)
	mux.HandleFunc("/session/verify", handler.VerifySession)

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

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("sir-auth listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, middleware.CORSMiddleware(mux)))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
