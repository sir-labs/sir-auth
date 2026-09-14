package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/sir-labs/sir-auth/internal/middleware"
	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
)

// Setup seeds the first admin user and a default OAuth client.
// Requires the SETUP_SECRET env var to match the `secret` query param.
// Does nothing if users already exist.
func Setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	setupSecret := os.Getenv("SETUP_SECRET")
	if setupSecret == "" || r.URL.Query().Get("secret") != setupSecret {
		middleware.WriteError(w, "forbidden", http.StatusForbidden)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	count, err := s.CountUsers(r.Context())
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		middleware.WriteError(w, "already_initialized", http.StatusConflict)
		return
	}

	var req struct {
		AdminEmail    string `json:"admin_email"`
		AdminPassword string `json:"admin_password"`
		ClientID      string `json:"client_id"`
		ClientSecret  string `json:"client_secret"`
		ClientName    string `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if req.AdminEmail == "" || req.AdminPassword == "" || req.ClientID == "" || req.ClientSecret == "" {
		middleware.WriteError(w, "invalid_request: all fields required", http.StatusBadRequest)
		return
	}
	if req.ClientName == "" {
		req.ClientName = "Default Client"
	}

	hash, salt, err := token.HashPassword(req.AdminPassword)
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	adminID, err := token.RandomString(16)
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}

	if err := s.CreateUser(r.Context(), model.User{
		ID:           adminID,
		Email:        req.AdminEmail,
		PasswordHash: hash,
		Salt:         salt,
		Role:         "admin",
		CreatedAt:    time.Now().Unix(),
		Approved:     true,
	}); err != nil {
		middleware.WriteError(w, "server_error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.CreateClient(r.Context(), model.OAuthClient{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Name:         req.ClientName,
	}); err != nil {
		middleware.WriteError(w, "server_error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.CreateSystemLog(r.Context(), model.SystemLog{
		Action:   "SYSTEM_SETUP",
		TargetID: adminID,
		AdminID:  "SYSTEM",
		Details:  "Initial setup completed. Created admin: " + req.AdminEmail,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"admin_id":    adminID,
		"admin_email": req.AdminEmail,
		"client_id":   req.ClientID,
		"client_name": req.ClientName,
	})
}
