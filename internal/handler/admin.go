package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// ── Admin UI (browser session) ──────────────────────────────────────────────

// sessionAdmin returns the signed-in admin, re-checked against the DB. Otherwise it
// redirects to /login (no session) or writes 403 (not an approved admin) and returns nil.
func sessionAdmin(w http.ResponseWriter, r *http.Request, s *store.Store) *model.User {
	claims := sessionClaims(r)
	if claims == nil {
		http.Redirect(w, r, "/login?rd=https://"+r.Host+"/admin", http.StatusFound)
		return nil
	}
	u, err := s.GetUserByID(r.Context(), claims.Sub)
	if err != nil || u == nil || u.Role != "admin" || !u.Approved {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil
	}
	return u
}

// sameOrigin reports whether the Origin (or, if absent, Referer) host equals the request Host.
func sameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Referer()
	}
	u, err := url.Parse(src)
	return err == nil && u.Host != "" && u.Host == r.Host
}

// checkAdminAction returns why action on target is not allowed, or "" if it is.
// approvedAdmins is the current number of approved admins.
func checkAdminAction(action, selfID string, target model.User, approvedAdmins int) string {
	switch action {
	case "approve":
		if target.Approved {
			return "User is already approved."
		}
	case "reject":
		if target.Approved {
			return "Only pending users can be rejected."
		}
	case "revoke", "delete":
		if target.ID == selfID {
			return "You cannot " + action + " your own account."
		}
		if action == "revoke" && !target.Approved {
			return "User is not approved."
		}
		if target.Role == "admin" && target.Approved && approvedAdmins <= 1 {
			return "You cannot " + action + " the last admin."
		}
	default:
		return "Unknown action."
	}
	return ""
}

// AdminPage handles GET /admin: lists pending and approved users.
func AdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	s, err := store.Open()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	me := sessionAdmin(w, r, s)
	if me == nil {
		return
	}
	users, err := s.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var pending, approved strings.Builder
	for _, u := range users {
		row := fmt.Sprintf(`<div class="flex flex-wrap items-center justify-between gap-3 py-3 border-b border-[#dee1e6]">
        <div class="text-sm"><div class="font-medium">%s</div><div class="text-xs text-[#7c828a]">%s · registered %s</div></div>
        <div class="flex gap-2">`, htmlEscape(u.Email), htmlEscape(u.Role), time.Unix(u.CreatedAt, 0).UTC().Format("2006-01-02"))
		switch {
		case !u.Approved:
			pending.WriteString(row + adminButton("approve", u.ID, "Approve", true) + adminButton("reject", u.ID, "Reject", false) + "</div></div>")
		case u.ID == me.ID:
			approved.WriteString(row + `<span class="text-xs text-[#7c828a]">you</span></div></div>`)
		default:
			approved.WriteString(row + adminButton("revoke", u.ID, "Revoke approval", false) + adminButton("delete", u.ID, "Delete", false) + "</div></div>")
		}
	}
	empty := `<p class="py-3 text-sm text-[#7c828a]">None.</p>`
	if pending.Len() == 0 {
		pending.WriteString(empty)
	}
	if approved.Len() == 0 {
		approved.WriteString(empty)
	}
	renderPage(w, "Admin — SIR Labs", "max-w-[720px]", fmt.Sprintf(`
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-semibold tracking-tight text-[#0a0b0d]">User approval</h1>
        <a href="/" class="text-sm text-[#0052ff] hover:underline">%s</a>
      </div>
      <h2 class="text-xs font-semibold tracking-wide uppercase text-[#5b616e] mt-2">Pending</h2>
      %s
      <h2 class="text-xs font-semibold tracking-wide uppercase text-[#5b616e] mt-8">Approved</h2>
      %s`, htmlEscape(me.Email), pending.String(), approved.String()))
}

func adminButton(action, id, label string, primary bool) string {
	style := "border border-[#dee1e6] text-[#0a0b0d] hover:border-[#cf202f] hover:text-[#cf202f]"
	if primary {
		style = "bg-[#0052ff] hover:bg-[#003ecc] text-white"
	}
	return fmt.Sprintf(`<form method="POST" action="/admin/%s"><input type="hidden" name="id" value="%s"><button type="submit" class="h-9 px-4 rounded-full text-xs font-semibold transition-all %s">%s</button></form>`,
		action, htmlEscape(id), style, htmlEscape(label))
}

// AdminAction handles POST /admin/{approve,reject,revoke,delete} with form field id.
func AdminAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "Forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	s, err := store.Open()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	me := sessionAdmin(w, r, s)
	if me == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/admin/")
	users, err := s.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var target *model.User
	approvedAdmins := 0
	for i, u := range users {
		if u.ID == r.FormValue("id") {
			target = &users[i]
		}
		if u.Role == "admin" && u.Approved {
			approvedAdmins++
		}
	}
	if target == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if msg := checkAdminAction(action, me.ID, *target, approvedAdmins); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	switch action {
	case "approve":
		err = s.SetUserApproved(r.Context(), target.ID, true)
	case "revoke":
		err = s.SetUserApproved(r.Context(), target.ID, false)
	default: // reject, delete
		err = s.DeleteUser(r.Context(), target.ID)
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.CreateSystemLog(r.Context(), model.SystemLog{
		Action:   strings.ToUpper(action) + "_USER",
		TargetID: target.ID,
		AdminID:  me.ID,
		Details:  "Admin " + action + " via /admin: " + target.Email,
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
