package handler

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/token"
)

const maxActiveTokens = 50

// AccountPage handles GET /account: profile, change password, log out everywhere, delete.
func AccountPage(w http.ResponseWriter, r *http.Request) {
	_, u := pageUser(w, r)
	if u == nil {
		return
	}
	pw := func(name, placeholder string) string {
		return fmt.Sprintf(`<input type="password" name="%s" required placeholder="%s" autocomplete="off" class="%s">`, name, placeholder, inputClass)
	}
	appPage(w, "Account — SIR Labs", u, "account", fmt.Sprintf(`
    <h1 class="text-2xl font-semibold tracking-tight mb-6">Account</h1>
    %s
    <section class="%s">
      <h2 class="%s">Profile</h2>
      <dl class="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
        <dt class="%s">Email</dt><dd class="font-medium break-all">%s</dd>
        <dt class="%s">Role</dt><dd>%s</dd>
        <dt class="%s">Member since</dt><dd>%s</dd>
      </dl>
    </section>
    <section class="%s">
      <h2 class="%s">Change password</h2>
      <p class="text-sm %s mb-4">Other browsers and devices are signed out. This browser stays signed in.</p>
      <form method="POST" action="/account/password" class="flex flex-col gap-4 max-w-md">
        %s %s %s
        <div class="flex items-center gap-4"><button type="submit" class="%s">Change password</button>%s</div>
      </form>
    </section>
    <section class="%s">
      <h2 class="%s">Log out everywhere</h2>
      <p class="text-sm %s mb-4">Ends every browser session, including this one, and revokes OAuth refresh tokens. Personal access tokens keep working; revoke them on the <a href="/account/tokens" class="text-[#0052ff] hover:underline">Tokens</a> page.</p>
      <form method="POST" action="/account/logout-all" %s data-confirm="Sign out of every browser and device?">
        <button type="submit" class="%s">Log out everywhere</button>
      </form>
    </section>
    <section class="%s border-[#cf202f]/30">
      <h2 class="%s text-[#cf202f]">Delete account</h2>
      <p class="text-sm %s mb-4">Permanently deletes your account, all your tokens and your request history. This cannot be undone.</p>
      <form method="POST" action="/account/delete" class="flex flex-col gap-4 max-w-md" %s data-confirm="Permanently delete your account? This cannot be undone.">
        %s
        <input type="text" name="confirm" required placeholder="Type DELETE to confirm" autocomplete="off" class="%s">
        <div><button type="submit" class="%s">Delete my account</button></div>
      </form>
    </section>`,
		flashHTML(r),
		cardClass, h2Class,
		mutedClass, htmlEscape(u.Email), mutedClass, htmlEscape(u.Role), mutedClass, fmtTime(u.CreatedAt),
		cardClass, h2Class, mutedClass,
		pw("current_password", "Current password"), pw("new_password", "New password (at least 8 characters)"), pw("confirm_password", "Repeat new password"),
		btnPrimary, showPasswordButton,
		cardClass, h2Class, mutedClass, confirmAttr, btnDanger,
		cardClass, h2Class, mutedClass, confirmAttr, pw("password", "Your password"), inputClass, btnDanger))
}

// AccountPassword handles POST /account/password.
func AccountPassword(w http.ResponseWriter, r *http.Request) {
	s, u := postUser(w, r)
	if u == nil {
		return
	}
	back := func(q string) { http.Redirect(w, r, "/account?"+q, http.StatusSeeOther) }
	if !token.VerifyPassword(r.FormValue("current_password"), u.PasswordHash, u.Salt) {
		back("err=bad-password")
		return
	}
	if code := validatePassword(r.FormValue("new_password"), r.FormValue("confirm_password")); code != "" {
		back("err=" + code)
		return
	}
	hash, salt, err := token.HashPassword(r.FormValue("new_password"))
	if err != nil {
		back("err=server")
		return
	}
	now := time.Now().Unix()
	if err := s.SetPassword(r.Context(), u.ID, hash, salt, now); err != nil {
		back("err=server")
		return
	}
	if err := s.BumpSessions(r.Context(), u.ID, now); err != nil {
		back("err=server")
		return
	}
	invalidateAuth()
	// New cookie (iat == now >= sessions_valid_after) keeps this browser signed in.
	ttl := sessionTTL()
	if jwt, err := token.GenerateToken(u.ID, u.Email, u.Role, "session", os.Getenv("JWT_SECRET"), ttl); err == nil {
		setSessionCookie(w, jwt, int(ttl.Seconds()))
	}
	s.CreateSystemLog(r.Context(), model.SystemLog{Action: "CHANGE_PASSWORD", TargetID: u.ID, AdminID: u.ID, Details: "User changed password via /account"})
	back("ok=password")
}

// AccountLogoutAll handles POST /account/logout-all.
func AccountLogoutAll(w http.ResponseWriter, r *http.Request) {
	s, u := postUser(w, r)
	if u == nil {
		return
	}
	if err := s.BumpSessions(r.Context(), u.ID, time.Now().Unix()); err != nil {
		http.Redirect(w, r, "/account?err=server", http.StatusSeeOther)
		return
	}
	invalidateAuth()
	s.CreateSystemLog(r.Context(), model.SystemLog{Action: "LOGOUT_ALL", TargetID: u.ID, AdminID: u.ID, Details: "User logged out everywhere"})
	setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// checkSelfDelete returns a flash error code if u may not delete their own account.
func checkSelfDelete(u model.User, approvedAdmins int64) string {
	if u.Role == "admin" && u.Approved && approvedAdmins <= 1 {
		return "last-admin"
	}
	return ""
}

// AccountDelete handles POST /account/delete (password + typed DELETE).
func AccountDelete(w http.ResponseWriter, r *http.Request) {
	s, u := postUser(w, r)
	if u == nil {
		return
	}
	back := func(code string) { http.Redirect(w, r, "/account?err="+code, http.StatusSeeOther) }
	if r.FormValue("confirm") != "DELETE" {
		back("confirm")
		return
	}
	if !token.VerifyPassword(r.FormValue("password"), u.PasswordHash, u.Salt) {
		back("bad-password")
		return
	}
	admins, err := s.CountApprovedAdmins(r.Context())
	if err != nil {
		back("server")
		return
	}
	if code := checkSelfDelete(*u, admins); code != "" {
		back(code)
		return
	}
	if err := s.DeleteUserData(r.Context(), u.ID); err != nil {
		back("server")
		return
	}
	invalidateAuth()
	s.CreateSystemLog(r.Context(), model.SystemLog{Action: "DELETE_SELF", TargetID: u.ID, AdminID: u.ID, Details: "User deleted own account: " + u.Email})
	setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── Personal access tokens ───────────────────────────────────────────────────

// tokenLifetimes are the choices offered when creating a token ("never" = no expiry).
var tokenLifetimes = []struct{ value, label string }{{"30", "30 days"}, {"90", "90 days"}, {"365", "1 year"}, {"never", "Never expires"}}

// parseExpiry turns a lifetime choice into expires_at (nil = never).
func parseExpiry(v string, now time.Time) (expiresAt *int64, ok bool) {
	switch v {
	case "never":
		return nil, true
	case "30", "90", "365":
		days := map[string]int{"30": 30, "90": 90, "365": 365}[v]
		e := now.AddDate(0, 0, days).Unix()
		return &e, true
	}
	return nil, false
}

func validTokenName(name string) bool {
	n := utf8.RuneCountInString(name)
	return n >= 1 && n <= 64
}

// TokensPage handles GET /account/tokens (list + create form) and POST /account/tokens (create).
func TokensPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		createToken(w, r)
		return
	}
	s, u := pageUser(w, r)
	if u == nil {
		return
	}
	tokens, err := s.ListAPITokens(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	var rows strings.Builder
	for _, t := range tokens {
		status := `<span class="` + badgeGrey + `">Never expires</span>`
		switch {
		case t.RevokedAt != nil:
			status = `<span class="` + badgeGrey + `">Revoked ` + timeTag(*t.RevokedAt) + `</span>`
		case t.ExpiresAt != nil && *t.ExpiresAt <= now.Unix():
			status = `<span class="` + badgeRed + `">Expired ` + timeTag(*t.ExpiresAt) + `</span>`
		case t.ExpiresAt != nil && *t.ExpiresAt-now.Unix() < 7*24*3600:
			status = `<span class="` + badgeAmber + `">Expires ` + timeTag(*t.ExpiresAt) + `</span>`
		case t.ExpiresAt != nil:
			status = `<span class="` + badgeGreen + `">Expires ` + timeTag(*t.ExpiresAt) + `</span>`
		}
		lastUsed := `<span class="` + mutedClass + `">Never used</span>`
		if t.LastUsedAt != nil {
			lastUsed = timeTag(*t.LastUsedAt) + `<div class="text-xs ` + mutedClass + `">` + htmlEscape(t.LastUsedIP) + `</div>`
		}
		name := `<div class="font-medium break-all">` + htmlEscape(t.Name) + `</div>`
		actions := ""
		if t.RevokedAt == nil {
			name = fmt.Sprintf(`<form method="POST" action="/account/tokens/rename" class="flex gap-2 items-center">
          <input type="hidden" name="id" value="%s">
          <input type="text" name="name" value="%s" required maxlength="64" aria-label="Token name" class="%s w-40">
          <button type="submit" class="%s">Rename</button></form>`, htmlEscape(t.ID), htmlEscape(t.Name), smallInput, btnSmall)
			actions = fmt.Sprintf(`<form method="POST" action="/account/tokens/revoke" %s data-confirm="Revoke this token? Anything using it stops working immediately.">
          <input type="hidden" name="id" value="%s"><button type="submit" class="%s hover:!border-[#cf202f] hover:!text-[#cf202f]">Revoke</button></form>`, confirmAttr, htmlEscape(t.ID), btnSmall)
		}
		fmt.Fprintf(&rows, `<tr><td class="%s">%s</td><td class="%s font-mono text-xs whitespace-nowrap">%s…</td><td class="%s whitespace-nowrap">%s</td><td class="%s">%s</td><td class="%s whitespace-nowrap">%s</td><td class="%s"><a href="/account/usage?token=%s" class="text-[#0052ff] hover:underline text-xs">Usage</a></td><td class="%s">%s</td></tr>`,
			tdClass, name, tdClass, htmlEscape(t.Prefix), tdClass, timeTag(t.CreatedAt), tdClass, status, tdClass, lastUsed, tdClass, htmlEscape(t.ID), tdClass, actions)
	}
	table := `<p class="text-sm ` + mutedClass + `">You have no tokens yet.</p>`
	if len(tokens) > 0 {
		table = fmt.Sprintf(`<div class="overflow-x-auto"><table class="%s"><thead><tr><th class="%s">Name</th><th class="%s">Token</th><th class="%s">Created</th><th class="%s">Status</th><th class="%s">Last used</th><th class="%s"></th><th class="%s"></th></tr></thead><tbody>%s</tbody></table></div>`,
			tableClass, thClass, thClass, thClass, thClass, thClass, thClass, thClass, rows.String())
	}
	var opts strings.Builder
	for _, l := range tokenLifetimes {
		sel := ""
		if l.value == "90" {
			sel = " selected"
		}
		fmt.Fprintf(&opts, `<option value="%s"%s>%s</option>`, l.value, sel, l.label)
	}
	appPage(w, "Tokens — SIR Labs", u, "tokens", fmt.Sprintf(`
    <h1 class="text-2xl font-semibold tracking-tight mb-2">Personal access tokens</h1>
    <p class="text-sm %s mb-6">A token lets scripts and tools call any sign-in protected service as you, without a browser. Send it as <code class="font-mono text-xs bg-[#eef0f3] px-1 py-0.5 rounded">Authorization: Bearer sirpat_…</code>. Tokens do not work on this site's own <code class="font-mono text-xs">/api/*</code>.</p>
    %s
    <section class="%s">
      <h2 class="%s">Create a token</h2>
      <form method="POST" action="/account/tokens" class="flex flex-wrap items-end gap-3">
        <label class="flex flex-col gap-2"><span class="%s">Name</span><input type="text" name="name" required maxlength="64" placeholder="e.g. laptop backup script" class="%s w-64"></label>
        <label class="flex flex-col gap-2"><span class="%s">Lifetime</span><select name="expires" class="%s">%s</select></label>
        <button type="submit" class="%s">Create token</button>
      </form>
    </section>
    <section class="%s"><h2 class="%s">Your tokens</h2>%s</section>`,
		mutedClass, flashHTML(r), cardClass, h2Class, labelClass, smallInput, labelClass, smallInput, opts.String(), btnPrimary, cardClass, h2Class, table))
}

func createToken(w http.ResponseWriter, r *http.Request) {
	s, u := postUser(w, r)
	if u == nil {
		return
	}
	back := func(code string) { http.Redirect(w, r, "/account/tokens?err="+code, http.StatusSeeOther) }
	name := strings.TrimSpace(r.FormValue("name"))
	if !validTokenName(name) {
		back("token-name")
		return
	}
	now := time.Now()
	expiresAt, ok := parseExpiry(r.FormValue("expires"), now)
	if !ok {
		back("token-expiry")
		return
	}
	// ponytail: count-then-insert isn't atomic; two parallel creates can reach 51. Harmless.
	if n, err := s.CountActiveAPITokens(r.Context(), u.ID, now.Unix()); err != nil {
		back("server")
		return
	} else if n >= maxActiveTokens {
		back("token-limit")
		return
	}
	raw, hash, prefix, err := token.NewPAT()
	if err != nil {
		back("server")
		return
	}
	t := &model.APIToken{UserID: u.ID, Name: name, TokenHash: hash, Prefix: prefix, CreatedAt: now.Unix(), ExpiresAt: expiresAt}
	if err := s.CreateAPIToken(r.Context(), t); err != nil {
		back("server")
		return
	}
	invalidateAuth() // drop a cached "not found" for this hash
	s.CreateSystemLog(r.Context(), model.SystemLog{Action: "CREATE_TOKEN", TargetID: t.ID, AdminID: u.ID, Details: "User created token " + prefix})

	expiry := "never expires"
	if expiresAt != nil {
		expiry = "expires " + fmtTime(*expiresAt) + " (Asia/Bangkok)"
	}
	example := fmt.Sprintf(`curl -H "Authorization: Bearer %s" https://your-app%s/`, raw, cookieDomain())
	w.Header().Set("Cache-Control", "no-store")
	appPage(w, "New token — SIR Labs", u, "tokens", fmt.Sprintf(`
    <section class="%s">
      <h1 class="text-2xl font-semibold tracking-tight mb-2">Token created</h1>
      <p class="text-sm %s mb-4"><span class="font-semibold">%s</span> · %s</p>
      <div class="p-4 mb-4 rounded-[12px] bg-[#f5a623]/10 border border-[#f5a623]/30 text-[#7a4d00] text-sm">Copy it now. This is the only time it is shown; only a hash is stored.</div>
      <div class="flex gap-2 mb-6">
        <input id="tok" type="text" readonly value="%s" class="%s font-mono" onclick="this.select()">
        <button type="button" class="%s shrink-0" onclick="copyText('tok', this)">Copy</button>
      </div>
      <h2 class="%s">Example</h2>
      <div class="flex gap-2 items-start">
        <pre id="ex" class="flex-1 min-w-0 overflow-x-auto p-4 rounded-[12px] bg-[#0a0b0d] text-white text-xs">%s</pre>
        <button type="button" class="%s shrink-0" onclick="copyText('ex', this)">Copy</button>
      </div>
      <p class="text-sm %s mt-3">Replace <code class="font-mono">your-app</code> with the service you want to call. A missing, wrong, expired or revoked token gets <code class="font-mono">401 {"error":"invalid_token"}</code>.</p>
      <a href="/account/tokens" class="inline-block mt-6 %s leading-10">Done</a>
    </section>
    <script>
      function copyText(id, btn) {
        const el = document.getElementById(id);
        navigator.clipboard.writeText(el.value || el.textContent).then(() => { btn.textContent = 'Copied'; setTimeout(() => btn.textContent = 'Copy', 1500); });
      }
    </script>`, cardClass, mutedClass, htmlEscape(name), expiry, htmlEscape(raw), inputClass, btnPrimary, h2Class, htmlEscape(example), btnSmall, mutedClass, btnPrimary))
}

// TokenRename handles POST /account/tokens/rename (id, name).
func TokenRename(w http.ResponseWriter, r *http.Request) {
	s, u := postUser(w, r)
	if u == nil {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !validTokenName(name) {
		http.Redirect(w, r, "/account/tokens?err=token-name", http.StatusSeeOther)
		return
	}
	found, err := s.RenameAPIToken(r.Context(), u.ID, r.FormValue("id"), name)
	switch {
	case err != nil:
		http.Redirect(w, r, "/account/tokens?err=server", http.StatusSeeOther)
	case !found:
		http.Redirect(w, r, "/account/tokens?err=token-missing", http.StatusSeeOther)
	default:
		invalidateAuth()
		http.Redirect(w, r, "/account/tokens?ok=token-renamed", http.StatusSeeOther)
	}
}

// TokenRevoke handles POST /account/tokens/revoke (id).
func TokenRevoke(w http.ResponseWriter, r *http.Request) {
	s, u := postUser(w, r)
	if u == nil {
		return
	}
	found, err := s.RevokeAPIToken(r.Context(), u.ID, r.FormValue("id"), time.Now().Unix())
	switch {
	case err != nil:
		http.Redirect(w, r, "/account/tokens?err=server", http.StatusSeeOther)
	case !found:
		http.Redirect(w, r, "/account/tokens?err=token-missing", http.StatusSeeOther)
	default:
		invalidateAuth()
		s.CreateSystemLog(r.Context(), model.SystemLog{Action: "REVOKE_TOKEN", TargetID: r.FormValue("id"), AdminID: u.ID, Details: "User revoked token"})
		http.Redirect(w, r, "/account/tokens?ok=token-revoked", http.StatusSeeOther)
	}
}
