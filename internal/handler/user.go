package handler

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/sir-labs/sir-auth/internal/middleware"
	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
)

func registerAllowed() bool { return os.Getenv("ALLOW_REGISTER") != "false" }

// Register handles GET /register (HTML form) and POST /register — public self-registration.
// Form posts create an unapproved user; JSON posts keep the original API response.
// Either way the account cannot sign in until an admin approves it.
func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !registerAllowed() {
		middleware.WriteError(w, "registration disabled", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet {
		renderRegister(w, rawRD(r.URL.RawQuery), "")
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		registerForm(w, r)
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

func registerForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	rd := r.FormValue("rd")
	email := strings.TrimSpace(r.FormValue("email"))
	fail := func(code int, msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		renderRegister(w, rd, msg)
	}
	if msg := validateRegistration(email, r.FormValue("password"), r.FormValue("confirm_password")); msg != "" {
		fail(http.StatusBadRequest, msg)
		return
	}

	s, err := store.Open()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	hash, salt, err := token.HashPassword(r.FormValue("password"))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	id, err := token.RandomString(16)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	u := model.User{ID: id, Email: email, PasswordHash: hash, Salt: salt, Role: "user", CreatedAt: time.Now().Unix()}
	if err := s.CreateUser(r.Context(), u); err != nil {
		fail(http.StatusConflict, "An account with this email already exists.")
		return
	}
	s.CreateSystemLog(r.Context(), model.SystemLog{
		Action:   "REGISTER_USER",
		TargetID: u.ID,
		AdminID:  "SELF_REGISTER",
		Details:  "User registered via /register form (pending approval): " + u.Email,
	})

	renderPage(w, "Registered — SIR Labs", "max-w-[450px]", `
      <h1 class="text-2xl font-semibold tracking-tight text-[#0a0b0d] mb-2">Registered — waiting for admin approval</h1>
      <p class="text-[#5b616e] text-sm">Your account has been created. You can sign in once an administrator approves it.</p>`+
		authLink("Approved already?", "/login?rd="+rd, "Sign in"))
}

// validateRegistration returns a user-facing error for bad register form input, or "".
func validateRegistration(email, password, confirm string) string {
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		return "Please enter a valid email address."
	}
	if len(password) < 8 {
		return "Password must be at least 8 characters."
	}
	if password != confirm {
		return "Passwords do not match."
	}
	return ""
}

func renderRegister(w http.ResponseWriter, rd, errorMsg string) {
	confirm := `
        <div class="flex flex-col gap-2">
          <label class="text-xs font-semibold tracking-wide text-[#0a0b0d] uppercase">Confirm Password</label>
          <input type="password" name="confirm_password" required minlength="8" placeholder="Repeat password" class="` + inputClass + `">
        </div>`
	renderAuthForm(w, "Register — SIR Labs", "Create a SIR Labs account", "/register", hiddenRD(rd), confirm, "Register",
		authLink("Already have an account?", "/login?rd="+rd, "Sign in"), errorMsg)
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
			Approved  bool   `json:"approved"`
		}
		out := make([]userView, len(users))
		for i, u := range users {
			out[i] = userView{ID: u.ID, Email: u.Email, Role: u.Role, CreatedAt: u.CreatedAt, Approved: u.Approved}
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
			Approved:     true, // created by an admin
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
