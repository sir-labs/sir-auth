package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sir-labs/sir-auth/internal/middleware"
	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
)

// AdminUserDetail handles PUT and DELETE for /api/admin/users/{id}
func AdminUserDetail(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromCtx(r.Context())
	if claims.Role != "admin" {
		middleware.WriteError(w, "forbidden", http.StatusForbidden)
		return
	}

	targetID := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	if targetID == "" || targetID == "/api/admin/users/" {
		middleware.WriteError(w, "missing user id", http.StatusBadRequest)
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

	switch r.Method {
	case http.MethodPut:
		var req struct {
			Email    string `json:"email"`
			Role     string `json:"role"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			middleware.WriteError(w, "invalid_request", http.StatusBadRequest)
			return
		}

		if req.Email != "" {
			u.Email = req.Email
		}
		if req.Role == "admin" || req.Role == "user" {
			u.Role = req.Role
		}
		if req.Password != "" {
			hash, salt, err := token.HashPassword(req.Password)
			if err != nil {
				middleware.WriteError(w, "server_error", http.StatusInternalServerError)
				return
			}
			u.PasswordHash = hash
			u.Salt = salt
		}

		if err := s.UpdateUser(r.Context(), *u); err != nil {
			middleware.WriteError(w, "server_error", http.StatusInternalServerError)
			return
		}

		s.CreateSystemLog(r.Context(), model.SystemLog{
			Action:   "UPDATE_USER",
			TargetID: u.ID,
			AdminID:  claims.Sub,
			Details:  "Admin updated user profile",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":         u.ID,
			"email":      u.Email,
			"role":       u.Role,
			"created_at": u.CreatedAt,
		})

	case http.MethodDelete:
		if err := s.DeleteUser(r.Context(), u.ID); err != nil {
			middleware.WriteError(w, "server_error", http.StatusInternalServerError)
			return
		}

		s.CreateSystemLog(r.Context(), model.SystemLog{
			Action:   "DELETE_USER",
			TargetID: u.ID,
			AdminID:  claims.Sub,
			Details:  "Admin deleted user",
		})

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// AdminLogs handles GET /api/admin/logs
func AdminLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := middleware.ClaimsFromCtx(r.Context())
	if claims.Role != "admin" {
		middleware.WriteError(w, "forbidden", http.StatusForbidden)
		return
	}

	s, err := store.Open()
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}
	defer s.Close()

	logs, err := s.ListSystemLogs(r.Context())
	if err != nil {
		middleware.WriteError(w, "server_error", http.StatusInternalServerError)
		return
	}

	users, _ := s.ListUsers(r.Context())
	emailMap := make(map[string]string)
	for _, u := range users {
		emailMap[u.ID] = u.Email
	}

	type LogView struct {
		ID        string `json:"id"`
		Action    string `json:"action"`
		Admin     string `json:"admin"`
		Target    string `json:"target"`
		Details   string `json:"details"`
		CreatedAt int64  `json:"created_at"`
	}

	var out []LogView
	for _, l := range logs {
		adminStr := l.AdminID
		if email, ok := emailMap[l.AdminID]; ok {
			adminStr = email
		}
		targetStr := l.TargetID
		if email, ok := emailMap[l.TargetID]; ok {
			targetStr = email
		}

		out = append(out, LogView{
			ID:        l.ID,
			Action:    l.Action,
			Admin:     adminStr,
			Target:    targetStr,
			Details:   l.Details,
			CreatedAt: l.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
