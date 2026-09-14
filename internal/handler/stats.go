package handler

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
)

const logsPerPage = 50

// statsWindow is the time window a stats page or CSV covers: a preset (range=24h|7d|30d)
// or a from/to date range (YYYY-MM-DD, both inclusive, Asia/Bangkok). Default 7d.
type statsWindow struct {
	From, To time.Time
	Preset   string // "" for a date range
	FromDay  string // YYYY-MM-DD for the date inputs
	ToDay    string
}

func parseWindow(q url.Values, now time.Time) statsWindow {
	if f, errF := time.ParseInLocation("2006-01-02", q.Get("from"), bkk); errF == nil {
		if t, errT := time.ParseInLocation("2006-01-02", q.Get("to"), bkk); errT == nil && !t.Before(f) {
			return statsWindow{From: f, To: t.AddDate(0, 0, 1), FromDay: q.Get("from"), ToDay: q.Get("to")}
		}
	}
	presets := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}
	p := q.Get("range")
	if _, ok := presets[p]; !ok {
		p = "7d"
	}
	from := now.Add(-presets[p])
	to := now.Add(time.Minute) // include rows written in the last instant
	return statsWindow{From: from, To: to, Preset: p, FromDay: from.In(bkk).Format("2006-01-02"), ToDay: now.In(bkk).Format("2006-01-02")}
}

// query returns the window (plus extra params) as a query string for links.
func (sw statsWindow) query(extra url.Values) string {
	v := url.Values{}
	if sw.Preset != "" {
		v.Set("range", sw.Preset)
	} else {
		v.Set("from", sw.FromDay)
		v.Set("to", sw.ToDay)
	}
	for k, vs := range extra {
		for _, x := range vs {
			if x != "" {
				v.Set(k, x)
			}
		}
	}
	return v.Encode()
}

// UsagePage handles GET /account/usage: the signed-in user's own request stats.
func UsagePage(w http.ResponseWriter, r *http.Request) {
	s, u := pageUser(w, r)
	if u == nil {
		return
	}
	renderStats(w, r, s, u, false)
}

// AdminStats handles GET /admin/stats: everyone's request stats.
func AdminStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	s, err := store.Open()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if u := sessionAdmin(w, r, s); u != nil {
		renderStats(w, r, s, u, true)
	}
}

func renderStats(w http.ResponseWriter, r *http.Request, s *store.Store, u *model.User, admin bool) {
	ctx := r.Context()
	q := r.URL.Query()
	now := time.Now()
	win := parseWindow(q, now)
	base, active, title := "/account/usage", "usage", "Your usage"
	scope := store.LogFilter{UserID: u.ID}
	if admin {
		base, active, title = "/admin/stats", "admin", "Request stats (all users)"
		scope.UserID = q.Get("user")
	}
	f := scope
	f.From, f.To = win.From, win.To
	fail := func(err error) {
		log.Printf("stats: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	// Tiles: fixed windows relative to now.
	var tiles strings.Builder
	for _, t := range []struct {
		label string
		d     time.Duration
	}{{"Last 24h", 24 * time.Hour}, {"Last 7 days", 7 * 24 * time.Hour}, {"Last 30 days", 30 * 24 * time.Hour}} {
		tf := scope
		tf.From, tf.To = now.Add(-t.d), now.Add(time.Minute)
		n, err := s.CountLogs(ctx, tf)
		if err != nil {
			fail(err)
			return
		}
		fmt.Fprintf(&tiles, `<div class="%s !mb-0"><div class="text-xs uppercase font-semibold %s">%s</div><div class="text-3xl font-semibold mt-1">%d</div></div>`, cardClass, mutedClass, t.label, n)
	}
	if admin {
		fmt.Fprintf(&tiles, `<div class="%s !mb-0"><div class="text-xs uppercase font-semibold %s" title="Events lost because the log buffer was full or a write failed, since this process started">Dropped since start</div><div class="text-3xl font-semibold mt-1">%d</div></div>`, cardClass, mutedClass, store.UsageDropped())
	}

	total, err := s.CountLogs(ctx, f)
	if err != nil {
		fail(err)
		return
	}
	daily, err := s.DailyCounts(ctx, f, "Asia/Bangkok")
	if err != nil {
		fail(err)
		return
	}
	byHost, err := s.CountBy(ctx, f, "host", 50)
	if err != nil {
		fail(err)
		return
	}
	byToken, err := s.CountBy(ctx, f, "token", 50)
	if err != nil {
		fail(err)
		return
	}
	var byUser []store.Bucket
	if admin {
		if byUser, err = s.CountBy(ctx, f, "user", 100); err != nil {
			fail(err)
			return
		}
	}

	// Recent requests: filters + pagination.
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	rf := f
	rf.Host, rf.TokenID = q.Get("host"), q.Get("token")
	recent, err := s.RecentLogs(ctx, rf, logsPerPage+1, (page-1)*logsPerPage)
	if err != nil {
		fail(err)
		return
	}
	hasNext := len(recent) > logsPerPage
	if hasNext {
		recent = recent[:logsPerPage]
	}

	filters := url.Values{"host": {rf.Host}, "token": {rf.TokenID}}
	if admin {
		filters.Set("user", scope.UserID)
	}

	// Window picker.
	var presets strings.Builder
	for _, p := range []string{"24h", "7d", "30d"} {
		cls := btnSmall + " inline-flex items-center"
		if win.Preset == p {
			cls = btnSmall + " inline-flex items-center !border-[#0052ff] !text-[#0052ff]"
		}
		pw := statsWindow{Preset: p}
		fmt.Fprintf(&presets, `<a href="%s?%s" class="%s">%s</a>`, base, htmlEscape(pw.query(filters)), cls, p)
	}
	hidden := ""
	for k, vs := range filters {
		if vs[0] != "" {
			hidden += fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, k, htmlEscape(vs[0]))
		}
	}
	picker := fmt.Sprintf(`<div class="flex flex-wrap items-end gap-3 mb-6">
      <div class="flex gap-2">%s</div>
      <form method="GET" action="%s" class="flex flex-wrap items-end gap-2">%s
        <label class="flex flex-col gap-1"><span class="%s">From</span><input type="date" name="from" value="%s" required class="%s"></label>
        <label class="flex flex-col gap-1"><span class="%s">To</span><input type="date" name="to" value="%s" required class="%s"></label>
        <button type="submit" class="%s">Apply</button>
      </form>
      <a href="%s.csv?%s" class="%s inline-flex items-center ml-auto">Download CSV</a>
    </div>`, presets.String(), base, hidden, labelClass, win.FromDay, smallInput, labelClass, win.ToDay, smallInput, btnSmall, base, htmlEscape(win.query(filters)), btnSmall)

	body := fmt.Sprintf(`
    <div class="flex flex-wrap items-center justify-between gap-3 mb-6">
      <h1 class="text-2xl font-semibold tracking-tight">%s</h1>%s
    </div>
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">%s</div>
    %s
    <section class="%s"><h2 class="%s">Requests per day <span class="text-sm font-normal %s">· %d in %s · Asia/Bangkok</span></h2>%s</section>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <section class="%s"><h2 class="%s">By service</h2>%s</section>
      <section class="%s"><h2 class="%s">By credential</h2>%s</section>
    </div>
    %s
    <section class="%s"><h2 class="%s">Recent requests</h2>%s</section>
    <p class="text-xs %s">Only requests to sign-in protected services are counted (public services are not). The backend's response status is not recorded.</p>`,
		title, adminStatsNote(admin, scope.UserID),
		tiles.String(), picker,
		cardClass, h2Class, mutedClass, total, windowLabel(win), dailyChart(daily, win),
		cardClass, h2Class, bucketTable(byHost, "Service", base, win, filters, "host"),
		cardClass, h2Class, bucketTable(byToken, "Credential", base, win, filters, "token"),
		userTable(admin, byUser, base, win, filters),
		cardClass, h2Class, recentTable(recent, admin, page, hasNext, base, win, filters),
		mutedClass)
	appPage(w, title+" — SIR Labs", u, active, body)
}

func adminStatsNote(admin bool, userID string) string {
	if !admin {
		return ""
	}
	if userID != "" {
		return `<div class="flex items-center gap-3"><a href="/admin/stats" class="text-sm text-[#0052ff] hover:underline">Showing one user · show all</a>` + adminTabs("stats") + `</div>`
	}
	return adminTabs("stats")
}

func windowLabel(win statsWindow) string {
	if win.Preset != "" {
		return "the last " + win.Preset
	}
	return win.FromDay + " – " + win.ToDay
}

// dailyChart is a plain-CSS bar chart with one bar per Bangkok day in the window.
func dailyChart(daily []store.Bucket, win statsWindow) string {
	counts := map[string]int64{}
	var max int64 = 1
	for _, b := range daily {
		counts[b.Key] = b.N
		if b.N > max {
			max = b.N
		}
	}
	start := win.From.In(bkk)
	start = time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, bkk)
	var days []string
	for d := start; d.Before(win.To) && len(days) < 400; d = d.AddDate(0, 0, 1) {
		days = append(days, d.Format("2006-01-02"))
	}
	var bars strings.Builder
	for _, d := range days {
		n := counts[d]
		h := float64(n) / float64(max) * 100
		fmt.Fprintf(&bars, `<div class="flex-1 flex flex-col justify-end h-full min-w-[3px]" title="%s: %d"><div class="bg-[#0052ff] rounded-t-sm" style="height:%.1f%%;min-height:%dpx"></div></div>`,
			d, n, h, map[bool]int{true: 1, false: 0}[n > 0])
	}
	first, last := "", ""
	if len(days) > 0 {
		first, last = days[0], days[len(days)-1]
	}
	return fmt.Sprintf(`<div class="overflow-x-auto"><div class="flex items-end gap-[2px] h-40 min-w-[240px] border-b border-[#dee1e6]">%s</div></div>
      <div class="flex justify-between text-xs %s mt-1"><span>%s</span><span>max %d/day</span><span>%s</span></div>`, bars.String(), mutedClass, first, max, last)
}

func bucketTable(bs []store.Bucket, head, base string, win statsWindow, filters url.Values, param string) string {
	if len(bs) == 0 {
		return `<p class="text-sm ` + mutedClass + `">No requests in this window.</p>`
	}
	var rows strings.Builder
	for _, b := range bs {
		label := b.Label
		if param == "token" {
			if b.Key == "" && label == "anonymous" {
				label = "Anonymous (public route)"
			} else if b.Key == "" {
				label = "Browser session"
			} else if label == "" {
				label = "Token " + b.Key
			}
		}
		link := ""
		if b.Key != "" {
			f := url.Values{}
			for k, v := range filters {
				f[k] = v
			}
			f.Set(param, b.Key)
			f.Del("page")
			link = fmt.Sprintf(` <a href="%s?%s" class="text-xs text-[#0052ff] hover:underline">filter</a>`, base, htmlEscape(win.query(f)))
		}
		fmt.Fprintf(&rows, `<tr><td class="%s break-all">%s%s</td><td class="%s text-right tabular-nums">%d</td></tr>`, tdClass, htmlEscape(label), link, tdClass, b.N)
	}
	return fmt.Sprintf(`<div class="overflow-x-auto"><table class="%s"><thead><tr><th class="%s">%s</th><th class="%s text-right">Requests</th></tr></thead><tbody>%s</tbody></table></div>`,
		tableClass, thClass, head, thClass, rows.String())
}

func userTable(admin bool, bs []store.Bucket, base string, win statsWindow, filters url.Values) string {
	if !admin {
		return ""
	}
	for i := range bs {
		if bs[i].Key == "" {
			bs[i].Label = "anonymous"
		} else if bs[i].Label == "" {
			bs[i].Label = "deleted user " + bs[i].Key
		}
	}
	return fmt.Sprintf(`<section class="%s"><h2 class="%s">By user</h2>%s</section>`, cardClass, h2Class, bucketTable(bs, "User", base, win, filters, "user"))
}

func recentTable(rows []store.LogRow, admin bool, page int, hasNext bool, base string, win statsWindow, filters url.Values) string {
	var active []string
	if filters.Get("host") != "" {
		active = append(active, "service "+htmlEscape(filters.Get("host")))
	}
	if filters.Get("token") != "" {
		active = append(active, "token "+htmlEscape(filters.Get("token")))
	}
	clear := ""
	if len(active) > 0 {
		f := url.Values{"user": {filters.Get("user")}}
		clear = fmt.Sprintf(`<p class="text-sm mb-3">Filtered by %s · <a href="%s?%s" class="text-[#0052ff] hover:underline">clear</a></p>`, strings.Join(active, ", "), base, htmlEscape(win.query(f)))
	}
	if len(rows) == 0 {
		return clear + `<p class="text-sm ` + mutedClass + `">No requests.</p>`
	}
	var b strings.Builder
	userHead := ""
	if admin {
		userHead = `<th class="` + thClass + `">User</th>`
	}
	for _, r := range rows {
		cred := r.Cred
		if r.TokenID != nil {
			cred = "token: " + r.TokenName
			if r.TokenName == "" {
				cred = "token " + *r.TokenID
			}
		}
		userCell := ""
		if admin {
			email := r.Email
			if r.UserID == "" {
				email = "anonymous"
			}
			userCell = fmt.Sprintf(`<td class="%s break-all">%s</td>`, tdClass, htmlEscape(email))
		}
		fmt.Fprintf(&b, `<tr><td class="%s whitespace-nowrap">%s</td>%s<td class="%s">%s</td><td class="%s font-mono text-xs">%s</td><td class="%s font-mono text-xs break-all">%s</td><td class="%s">%s</td><td class="%s whitespace-nowrap">%s</td></tr>`,
			tdClass, timeTag(r.TS.Unix()), userCell, tdClass, htmlEscape(r.Host), tdClass, htmlEscape(r.Method), tdClass, htmlEscape(r.Path), tdClass, htmlEscape(cred), tdClass, htmlEscape(r.IP))
	}
	pager := func(p int, label string) string {
		f := url.Values{}
		for k, v := range filters {
			f[k] = v
		}
		f.Set("page", strconv.Itoa(p))
		return fmt.Sprintf(`<a href="%s?%s" class="%s inline-flex items-center">%s</a>`, base, htmlEscape(win.query(f)), btnSmall, label)
	}
	nav := ""
	if page > 1 {
		nav += pager(page-1, "← Newer")
	}
	if hasNext {
		nav += pager(page+1, "Older →")
	}
	return fmt.Sprintf(`%s<div class="overflow-x-auto"><table class="%s"><thead><tr><th class="%s">When</th>%s<th class="%s">Service</th><th class="%s">Method</th><th class="%s">Path</th><th class="%s">Credential</th><th class="%s">IP</th></tr></thead><tbody>%s</tbody></table></div>
      <div class="flex items-center gap-2 mt-4 text-sm %s">Page %d %s</div>`,
		clear, tableClass, thClass, userHead, thClass, thClass, thClass, thClass, thClass, b.String(), mutedClass, page, nav)
}

// UsageCSV handles GET /account/usage.csv (own rows in the window).
func UsageCSV(w http.ResponseWriter, r *http.Request) {
	s, u := pageUser(w, r)
	if u == nil {
		return
	}
	writeCSV(w, r, s, u.ID, "usage")
}

// AdminStatsCSV handles GET /admin/stats.csv (everyone's rows in the window).
func AdminStatsCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	s, err := store.Open()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if sessionAdmin(w, r, s) != nil {
		writeCSV(w, r, s, r.URL.Query().Get("user"), "requests")
	}
}

func writeCSV(w http.ResponseWriter, r *http.Request, s *store.Store, userID, name string) {
	q := r.URL.Query()
	win := parseWindow(q, time.Now())
	f := store.LogFilter{From: win.From, To: win.To, UserID: userID, Host: q.Get("host"), TokenID: q.Get("token")}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s-to-%s.csv"`, name, win.FromDay, win.ToDay))
	cw := csv.NewWriter(w)
	cw.Write([]string{"time", "host", "method", "path", "ip", "credential", "token_id", "token_name", "user_id", "email"})
	err := s.EachLog(r.Context(), f, func(l store.LogRow) error {
		tok := ""
		if l.TokenID != nil {
			tok = *l.TokenID
		}
		return cw.Write([]string{l.TS.In(bkk).Format(time.RFC3339), l.Host, l.Method, l.Path, l.IP, l.Cred, tok, l.TokenName, l.UserID, l.Email})
	})
	cw.Flush()
	if err != nil {
		// Headers are already sent; a truncated file is the best we can signal.
		log.Printf("csv export: %v", err)
		fmt.Fprintf(w, "# export failed: %v\n", err)
	}
}
