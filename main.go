package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // Asia/Bangkok for stats; the alpine image has no zoneinfo

	"github.com/sir-labs/sir-auth/internal/handler"
	"github.com/sir-labs/sir-auth/internal/middleware"
	"github.com/sir-labs/sir-auth/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Connect + migrate at boot so a bad DATABASE_URL fails fast.
	s, err := store.Open()
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	store.StartUsage(s)

	mux := http.NewServeMux()

	// Dashboard (signed-in) and health
	mux.HandleFunc("/", handler.Home)
	mux.HandleFunc("/health", handleHealth)

	// Browser session for *.sir-labs.com (nginx auth_request)
	mux.HandleFunc("/login", handler.Login)
	mux.HandleFunc("/logout", handler.Logout)
	mux.HandleFunc("/session/verify", handler.VerifySession)

	// Account, personal access tokens, own usage (sir_session cookie)
	mux.HandleFunc("/account", handler.AccountPage)
	mux.HandleFunc("/account/password", handler.AccountPassword)
	mux.HandleFunc("/account/logout-all", handler.AccountLogoutAll)
	mux.HandleFunc("/account/delete", handler.AccountDelete)
	mux.HandleFunc("/account/tokens", handler.TokensPage)
	mux.HandleFunc("/account/tokens/rename", handler.TokenRename)
	mux.HandleFunc("/account/tokens/revoke", handler.TokenRevoke)
	mux.HandleFunc("/account/usage", handler.UsagePage)
	mux.HandleFunc("/account/usage.csv", handler.UsageCSV)

	// OAuth 2.0 Authorization Code Flow (RFC 8252)
	mux.HandleFunc("/oauth/authorize", handler.Authorize)
	mux.HandleFunc("/oauth/token", handler.Token)
	mux.HandleFunc("/oauth/revoke", handler.Revoke)

	// Initial setup: creates first admin user + default client (runs once)
	mux.HandleFunc("/setup", handler.Setup)

	// Public: self-registration
	mux.HandleFunc("/register", handler.Register)

	// Admin UI (sir_session cookie with role=admin): approve users, stats
	mux.HandleFunc("/admin", handler.AdminPage)
	mux.HandleFunc("/admin/", handler.AdminAction)
	mux.HandleFunc("/admin/routes", handler.AdminRoutes)
	mux.HandleFunc("/admin/stats", handler.AdminStats)
	mux.HandleFunc("/admin/stats.csv", handler.AdminStatsCSV)

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
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           middleware.CORSMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("sir-auth listening on :%s", port)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	store.CloseUsage() // flush buffered request logs
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
