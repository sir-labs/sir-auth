package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
)

// bkk is the display timezone for pages and stats.
var bkk = func() *time.Location {
	if l, err := time.LoadLocation("Asia/Bangkok"); err == nil {
		return l
	}
	return time.FixedZone("ICT", 7*3600)
}()

// Flash messages: pages redirect with ?ok=<code> or ?err=<code> and show the fixed
// string for that code, so user input is never echoed back.
var flashOK = map[string]string{
	"password":      "Password changed. Your other sessions were signed out.",
	"token-renamed": "Token renamed.",
	"token-revoked": "Token revoked. Requests using it are refused from now on.",
}

var flashErr = map[string]string{
	"bad-password":  "Current password is incorrect.",
	"pw-short":      "Password must be at least 8 characters.",
	"pw-mismatch":   "Passwords do not match.",
	"confirm":       "Type DELETE (in capitals) to confirm.",
	"last-admin":    "You are the last approved admin, so you cannot delete your account.",
	"token-name":    "Token name must be 1–64 characters.",
	"token-limit":   "You already have 50 active tokens. Revoke one first.",
	"token-expiry":  "Choose a valid token lifetime.",
	"token-missing": "Token not found (or already revoked).",
	"server":        "Something went wrong. Please try again.",
}

func flashHTML(r *http.Request) string {
	if m, ok := flashOK[r.URL.Query().Get("ok")]; ok {
		return `<div class="p-4 mb-6 rounded-[12px] bg-[#098551]/5 border border-[#098551]/20 text-[#098551] text-sm">` + htmlEscape(m) + `</div>`
	}
	if m, ok := flashErr[r.URL.Query().Get("err")]; ok {
		return `<div class="p-4 mb-6 rounded-[12px] bg-[#cf202f]/5 border border-[#cf202f]/20 text-[#cf202f] text-sm">` + htmlEscape(m) + `</div>`
	}
	return ""
}

// relTime renders t relative to now: "just now", "3 min ago", "in 5 days".
func relTime(t, now time.Time) string {
	d := now.Sub(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		s = fmt.Sprintf("%d min", int(d/time.Minute))
	case d < 24*time.Hour:
		s = fmt.Sprintf("%d h", int(d/time.Hour))
	case d < 60*24*time.Hour:
		s = plural(int(d/(24*time.Hour)), "day")
	case d < 365*24*time.Hour:
		s = plural(int(d/(30*24*time.Hour)), "month")
	default:
		s = plural(int(d/(365*24*time.Hour)), "year")
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func fmtTime(unix int64) string {
	return time.Unix(unix, 0).In(bkk).Format("2006-01-02 15:04")
}

// timeTag is a relative time with the absolute Bangkok time on hover.
func timeTag(unix int64) string {
	return fmt.Sprintf(`<span title="%s (Asia/Bangkok)">%s</span>`, fmtTime(unix), relTime(time.Unix(unix, 0), time.Now()))
}

const (
	cardClass   = "bg-white border border-[#dee1e6] rounded-[24px] p-6 md:p-8 shadow-[0_4px_12px_rgba(0,0,0,0.02)] mb-6"
	h2Class     = "text-lg font-semibold tracking-tight mb-4"
	btnPrimary  = "h-10 px-5 rounded-full text-sm font-semibold bg-[#0052ff] hover:bg-[#003ecc] text-white transition-all"
	btnDanger   = "h-10 px-5 rounded-full text-sm font-semibold border border-[#cf202f] text-[#cf202f] hover:bg-[#cf202f] hover:text-white transition-all"
	btnSmall    = "h-8 px-3 rounded-full text-xs font-semibold border border-[#dee1e6] hover:border-[#0052ff] hover:text-[#0052ff] transition-all"
	tableClass  = "w-full text-sm text-left"
	thClass     = "py-2 pr-4 text-xs font-semibold uppercase tracking-wide text-[#5b616e] whitespace-nowrap"
	tdClass     = "py-2 pr-4 border-t border-[#dee1e6] align-top"
	labelClass  = "text-xs font-semibold tracking-wide text-[#0a0b0d] uppercase"
	mutedClass  = "text-[#5b616e]"
	smallInput  = "h-10 px-3 bg-white border border-[#dee1e6] rounded-[12px] text-sm focus:border-[#0052ff] outline-none"
	badgeClass  = "inline-block px-2 py-0.5 rounded-full text-xs font-semibold"
	badgeGrey   = badgeClass + " bg-[#eef0f3] text-[#5b616e]"
	badgeRed    = badgeClass + " bg-[#cf202f]/10 text-[#cf202f]"
	badgeAmber  = badgeClass + " bg-[#f5a623]/15 text-[#a86b00]"
	badgeGreen  = badgeClass + " bg-[#098551]/10 text-[#098551]"
	badgeBlue   = badgeClass + " bg-[#0052ff]/10 text-[#0052ff]"
	confirmAttr = `onsubmit="return confirm(this.dataset.confirm)"`
)

// appPage renders the signed-in shell (nav bar) around bodyHTML (trusted markup).
func appPage(w http.ResponseWriter, title string, u *model.User, active, bodyHTML string) {
	links := [][3]string{{"home", "/", "Home"}, {"account", "/account", "Account"}, {"tokens", "/account/tokens", "Tokens"}, {"usage", "/account/usage", "Usage"}}
	if u.Role == "admin" {
		links = append(links, [3]string{"admin", "/admin", "Admin"})
	}
	var nav strings.Builder
	for _, l := range links {
		cls := "text-[#5b616e] hover:text-[#0a0b0d]"
		if l[0] == active {
			cls = "text-[#0052ff] font-semibold"
		}
		fmt.Fprintf(&nav, `<a href="%s" class="whitespace-nowrap %s">%s</a>`, l[1], cls, l[2])
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, appHTML, htmlEscape(title), nav.String(), htmlEscape(u.Email), bodyHTML)
}

const appHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>%s</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>body { font-family: 'Inter', -apple-system, sans-serif; background-color: #f7f7f7; color: #0a0b0d; }</style>
</head>
<body class="min-h-screen">
  <header class="w-full border-b border-[#dee1e6] bg-white">
    <div class="max-w-5xl mx-auto px-4 md:px-6 py-3 flex flex-wrap items-center gap-x-6 gap-y-2">
      <a href="/" class="flex items-center gap-2">
        <div class="w-8 h-8 rounded-full bg-[#0052ff] flex items-center justify-center text-white shadow-sm">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <span class="text-xl font-bold tracking-tight">SIR</span>
      </a>
      <nav class="flex gap-5 text-sm overflow-x-auto">%s</nav>
      <div class="ml-auto flex items-center gap-4 text-sm">
        <span class="text-[#5b616e] truncate max-w-[16rem]">%s</span>
        <a href="/logout" class="font-semibold text-[#0052ff] hover:underline">Log out</a>
      </div>
    </div>
  </header>
  <main class="max-w-5xl mx-auto px-4 md:px-6 py-8">
%s
  </main>
</body>
</html>`

// ── Dashboard ────────────────────────────────────────────────────────────────

type watcherRoute struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
	Auth     bool   `json:"auth"`
}

var watcherClient = &http.Client{Timeout: 2 * time.Second}

func watcherURL() string {
	if u := os.Getenv("WATCHER_URL"); u != "" {
		return u
	}
	return "http://sir-watcher:8080/routes"
}

// loadRoutes fetches the proxy's route list. A variable so tests can stub it.
var loadRoutes = func(ctx context.Context, url string) ([]watcherRoute, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := watcherClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	var rs []watcherRoute
	err = json.NewDecoder(resp.Body).Decode(&rs)
	return rs, err
}

var routesCache = newTTLCache(60*time.Second, 10, func(ctx context.Context, url string) ([]watcherRoute, error) { return loadRoutes(ctx, url) })

// Home handles GET /: the signed-in dashboard (services, recent usage, quick links).
func Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s, u := pageUser(w, r)
	if u == nil {
		return
	}
	now := time.Now()
	n24, _ := s.CountLogs(r.Context(), store.LogFilter{From: now.Add(-24 * time.Hour), To: now.Add(time.Minute), UserID: u.ID})
	nTok, _ := s.CountActiveAPITokens(r.Context(), u.ID, now.Unix())

	routes, err := routesCache.Get(r.Context(), watcherURL())
	var cards strings.Builder
	switch {
	case err != nil:
		cards.WriteString(`<p class="text-sm text-[#5b616e]">The service list is unavailable right now.</p>`)
	case len(routes) == 0:
		cards.WriteString(`<p class="text-sm text-[#5b616e]">No services are registered.</p>`)
	default:
		sort.Slice(routes, func(i, j int) bool { return routes[i].Hostname < routes[j].Hostname })
		cards.WriteString(`<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">`)
		for _, rt := range routes {
			link := rt.URL
			if link == "" {
				link = "https://" + rt.Hostname
			}
			link = "https://" + strings.TrimPrefix(strings.TrimPrefix(link, "http://"), "https://")
			badge := `<span class="` + badgeGreen + `">public</span>`
			if rt.Auth {
				badge = `<span class="` + badgeBlue + `">sign-in</span>`
			}
			fmt.Fprintf(&cards, `<a href="%s" class="block p-4 rounded-[16px] border border-[#dee1e6] hover:border-[#0052ff] transition-all">
        <div class="flex items-center justify-between gap-2"><span class="font-semibold truncate">%s</span>%s</div>
        <div class="text-xs text-[#5b616e] truncate mt-1">%s</div></a>`, htmlEscape(link), htmlEscape(rt.Name), badge, htmlEscape(rt.Hostname))
		}
		cards.WriteString(`</div>`)
	}

	appPage(w, "SIR Labs", u, "home", fmt.Sprintf(`
    <h1 class="text-2xl font-semibold tracking-tight mb-6">Welcome back</h1>
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
      <a href="/account/usage?range=24h" class="%s !mb-0 block hover:border-[#0052ff]"><div class="text-xs uppercase font-semibold %s">Your requests, last 24h</div><div class="text-3xl font-semibold mt-1">%d</div></a>
      <a href="/account/tokens" class="%s !mb-0 block hover:border-[#0052ff]"><div class="text-xs uppercase font-semibold %s">Active tokens</div><div class="text-3xl font-semibold mt-1">%d</div></a>
      <a href="/account" class="%s !mb-0 block hover:border-[#0052ff]"><div class="text-xs uppercase font-semibold %s">Signed in as</div><div class="text-base font-semibold mt-2 truncate">%s</div></a>
    </div>
    <section class="%s"><h2 class="%s">Services</h2>%s</section>`,
		cardClass, mutedClass, n24, cardClass, mutedClass, nTok, cardClass, mutedClass, htmlEscape(u.Email),
		cardClass, h2Class, cards.String()))
}

// pageUser opens the store and returns the signed-in user for a GET page, or nil
// after writing the response (405, 500 or a redirect to /login).
func pageUser(w http.ResponseWriter, r *http.Request) (*store.Store, *model.User) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return nil, nil
	}
	s, err := store.Open()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, nil
	}
	return s, sessionUser(w, r, s)
}

// postUser is pageUser for form POSTs: also requires a same-origin request and parses the form.
func postUser(w http.ResponseWriter, r *http.Request) (*store.Store, *model.User) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return nil, nil
	}
	if !sameOrigin(r) {
		http.Error(w, "Forbidden: cross-origin request", http.StatusForbidden)
		return nil, nil
	}
	s, err := store.Open()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, nil
	}
	u := sessionUser(w, r, s)
	if u == nil {
		return nil, nil
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return nil, nil
	}
	return s, u
}
