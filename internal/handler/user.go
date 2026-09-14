package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sir-labs/sir-auth/internal/middleware"
	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
)

// Register handles POST /register — public user self-registration.
func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if os.Getenv("ALLOW_REGISTER") == "false" {
		middleware.WriteError(w, "registration disabled", http.StatusForbidden)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		middleware.WriteError(w, "invalid_request: email and password required", http.StatusBadRequest)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	hash, salt, err := token.HashPassword(req.Password)
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	id, err := token.RandomString(16)
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}

	u := model.User{
		ID:           id,
		Email:        req.Email,
		PasswordHash: hash,
		Salt:         salt,
		Role:         "user",
		CreatedAt:    time.Now().Unix(),
	}
	if err := s.CreateUser(r.Context(), u); err != nil {
		middleware.WriteError(w, "conflict: email already exists", http.StatusConflict)
		return
	}

	s.CreateSystemLog(r.Context(), model.SystemLog{
		Action:   "REGISTER_USER",
		TargetID: u.ID,
		AdminID:  "SELF_REGISTER",
		Details:  "User registered via /register: " + u.Email,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"id":    u.ID,
		"email": u.Email,
		"role":  u.Role,
	})
}

// Me returns the authenticated user's profile.
func Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromCtx(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":    claims.Sub,
		"email": claims.Email,
		"role":  claims.Role,
		"scope": claims.Scope,
	})
}

// GetUser handles GET /api/users/{id}.
func GetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	targetID := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if targetID == "" {
		middleware.WriteError(w, "missing user id", http.StatusBadRequest)
		return
	}

	claims := middleware.ClaimsFromCtx(r.Context())
	if claims.Role != "admin" && claims.Sub != targetID {
		middleware.WriteError(w, "forbidden", http.StatusForbidden)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	u, err := s.GetUserByID(r.Context(), targetID)
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	if u == nil {
		middleware.WriteError(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":         u.ID,
		"email":      u.Email,
		"role":       u.Role,
		"created_at": u.CreatedAt,
	})
}

// AdminUsers handles GET /api/admin/users and POST /api/admin/users.
func AdminUsers(w http.ResponseWriter, r *http.Request) {
	s, err := store.Open()
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	switch r.Method {
	case http.MethodGet:
		users, err := s.ListUsers(r.Context())
		if err != nil {
			middleware.WriteError(w, "server_error", http.StatusInternalServerError)
			return
		}
		type userView struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			Role      string `json:"role"`
			CreatedAt int64  `json:"created_at"`
		}
		out := make([]userView, len(users))
		for i, u := range users {
			out[i] = userView{ID: u.ID, Email: u.Email, Role: u.Role, CreatedAt: u.CreatedAt}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)

	case http.MethodPost:
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
			middleware.WriteError(w, "invalid_request: email and password required", http.StatusBadRequest)
			return
		}
		if req.Role != "admin" && req.Role != "user" {
			req.Role = "user"
		}

		hash, salt, err := token.HashPassword(req.Password)
		if err != nil {
			middleware.WriteError(w, "server_error", http.StatusInternalServerError)
			return
		}
		id, err := token.RandomString(16)
		if err != nil {
			middleware.WriteError(w, "server_error", http.StatusInternalServerError)
			return
		}

		u := model.User{
			ID:           id,
			Email:        req.Email,
			PasswordHash: hash,
			Salt:         salt,
			Role:         req.Role,
			CreatedAt:    time.Now().Unix(),
		}
		if err := s.CreateUser(r.Context(), u); err != nil {
			middleware.WriteError(w, "conflict: email already exists", http.StatusConflict)
			return
		}

		claims := middleware.ClaimsFromCtx(r.Context())
		s.CreateSystemLog(r.Context(), model.SystemLog{
			Action:   "CREATE_USER_BY_ADMIN",
			TargetID: u.ID,
			AdminID:  claims.Sub,
			Details:  "Admin created new user via /api/admin/users: " + u.Email + " with role " + u.Role,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"id":    u.ID,
			"email": u.Email,
			"role":  u.Role,
		})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
