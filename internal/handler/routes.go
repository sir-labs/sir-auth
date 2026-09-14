package handler

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
)

// authHostName is sir-auth's own host (never gated, not manageable).
func authHostName() string { return "auth." + strings.TrimPrefix(cookieDomain(), ".") }

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// adminTabs is the Users · Routes · Stats switcher shown on admin pages.
func adminTabs(active string) string {
	var b strings.Builder
	b.WriteString(`<div class="flex gap-2">`)
	for _, t := range [][3]string{{"users", "/admin", "Users"}, {"routes", "/admin/routes", "Routes"}, {"stats", "/admin/stats", "Stats"}} {
		cls := btnSmall + " inline-flex items-center"
		if t[0] == active {
			cls += " !border-[#0052ff] !text-[#0052ff]"
		}
		fmt.Fprintf(&b, `<a href="%s" class="%s">%s</a>`, t[1], cls, t[2])
	}
	b.WriteString(`</div>`)
	return b.String()
}

// policyMap returns host → public for every policy row (nil map if the DB fails).
func policyMap(r *http.Request, s *store.Store) map[string]bool {
	ps, err := s.ListRoutePolicies(r.Context())
	if err != nil {
		return nil
	}
	m := make(map[string]bool, len(ps))
	for _, p := range ps {
		m[p.Host] = p.Public
	}
	return m
}

// AdminRoutes handles GET /admin/routes (per-host login/public policy) and
// POST /admin/routes (host, action=public|login|delete).
func AdminRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		setRoutePolicy(w, r)
		return
	}
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
	ctx := r.Context()
	policies, err := s.ListRoutePolicies(ctx)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	pol := map[string]model.RoutePolicy{}
	for _, p := range policies {
		pol[p.Host] = p
	}
	now := time.Now()
	counts := map[string]int64{}
	if bs, err := s.CountBy(ctx, store.LogFilter{From: now.Add(-30 * 24 * time.Hour), To: now.Add(time.Minute)}, "host", 10000); err == nil {
		for _, b := range bs {
			counts[b.Key] = b.N
		}
	}
	routes, rerr := routesCache.Get(ctx, watcherURL())
	sort.Slice(routes, func(i, j int) bool { return routes[i].Hostname < routes[j].Hostname })

	toggle := func(host string) string {
		if pol[host].Public {
			return fmt.Sprintf(`<span class="%s">Public</span> <form method="POST" action="/admin/routes" class="inline"><input type="hidden" name="host" value="%s"><input type="hidden" name="action" value="login"><button type="submit" class="%s">Require login</button></form>`,
				badgeGreen, htmlEscape(host), btnSmall)
		}
		return fmt.Sprintf(`<span class="%s">Login required</span> <form method="POST" action="/admin/routes" class="inline" %s data-confirm="Make %s public? Anyone on the internet can open it without signing in."><input type="hidden" name="host" value="%s"><input type="hidden" name="action" value="public"><button type="submit" class="%s">Make public</button></form>`,
			badgeBlue, confirmAttr, htmlEscape(host), htmlEscape(host), btnSmall)
	}
	deleteBtn := func(host string) string {
		return fmt.Sprintf(` <form method="POST" action="/admin/routes" class="inline" %s data-confirm="Delete the policy for %s?"><input type="hidden" name="host" value="%s"><input type="hidden" name="action" value="delete"><button type="submit" class="%s hover:!border-[#cf202f] hover:!text-[#cf202f]">Delete</button></form>`,
			confirmAttr, htmlEscape(host), htmlEscape(host), btnSmall)
	}
	row := func(host, name, state string) string {
		return fmt.Sprintf(`<tr><td class="%s font-medium break-all">%s</td><td class="%s break-all %s">%s</td><td class="%s text-right tabular-nums">%d</td><td class="%s">%s</td></tr>`,
			tdClass, htmlEscape(host), tdClass, mutedClass, htmlEscape(name), tdClass, counts[host], tdClass, state)
	}

	var rows strings.Builder
	seen := map[string]bool{}
	for _, rt := range routes {
		h := strings.ToLower(rt.Hostname)
		seen[h] = true
		switch {
		case h == authHostName():
			rows.WriteString(row(h, rt.Name, `<span class="`+badgeGrey+`">sir-auth · always public</span>`))
		case !rt.Auth:
			rows.WriteString(row(h, rt.Name, `<span class="`+badgeGreen+`">Public (container label)</span><div class="text-xs mt-1 `+mutedClass+`">Locked: remove the <code class="font-mono">proxy.auth=false</code> label to manage it here.</div>`))
		default:
			rows.WriteString(row(h, rt.Name, toggle(h)))
		}
	}
	for _, p := range policies {
		if seen[p.Host] {
			continue
		}
		if rerr == nil {
			rows.WriteString(row(p.Host, "", `<span class="`+badgeAmber+`">stale · no current route</span>`+deleteBtn(p.Host)))
		} else {
			rows.WriteString(row(p.Host, "", toggle(p.Host)+deleteBtn(p.Host)))
		}
	}
	note := ""
	if rerr != nil {
		note = `<div class="p-4 mb-6 rounded-[12px] bg-[#f5a623]/10 border border-[#f5a623]/30 text-[#7a4d00] text-sm">The route list is unavailable right now, so only hosts with a saved policy are shown.</div>`
	}
	table := `<p class="text-sm ` + mutedClass + `">No routes.</p>`
	if rows.Len() > 0 {
		table = fmt.Sprintf(`<div class="overflow-x-auto"><table class="%s"><thead><tr><th class="%s">Host</th><th class="%s">Container</th><th class="%s text-right">Requests, 30 days</th><th class="%s">Access</th></tr></thead><tbody>%s</tbody></table></div>`,
			tableClass, thClass, thClass, thClass, thClass, rows.String())
	}
	appPage(w, "Routes — SIR Labs", me, "admin", fmt.Sprintf(`
    <div class="flex flex-wrap items-center justify-between gap-3 mb-6">
      <h1 class="text-2xl font-semibold tracking-tight">Route access</h1>%s
    </div>
    %s%s
    <section class="%s">
      <p class="text-sm %s mb-4">New routes require login. A public route lets anyone in without signing in; signed-in users and tokens are still recognised, and a wrong token is still refused. Changes apply immediately. Public routes still pass through sir-auth, so they fail (500) while sir-auth is down.</p>
      %s
    </section>`, adminTabs("routes"), flashHTML(r), note, cardClass, mutedClass, table))
}

func setRoutePolicy(w http.ResponseWriter, r *http.Request) {
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
	back := func(q string) { http.Redirect(w, r, "/admin/routes?"+q, http.StatusSeeOther) }
	host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
	if !validHost(host) || host == authHostName() {
		back("err=route-host")
		return
	}
	action := r.FormValue("action")
	switch action {
	case "public", "login":
		err = s.SetRoutePolicy(r.Context(), model.RoutePolicy{Host: host, Public: action == "public", UpdatedAt: time.Now().Unix(), UpdatedBy: me.ID})
	case "delete":
		err = s.DeleteRoutePolicy(r.Context(), host)
	default:
		back("err=route-host")
		return
	}
	if err != nil {
		back("err=server")
		return
	}
	invalidateAuth()
	s.CreateSystemLog(r.Context(), model.SystemLog{Action: "ROUTE_" + strings.ToUpper(action), TargetID: host, AdminID: me.ID, Details: "Admin set route policy via /admin/routes: " + host + " → " + action})
	back("ok=route-" + action)
}
