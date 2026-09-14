#!/usr/bin/env bash
# End-to-end test: nginx (config mirroring the watcher's output) + sir-auth + postgres
# + traefik/whoami, in the isolated compose project "sirauth-e2e".
# Usage: e2e/run.sh        KEEP=1 e2e/run.sh leaves the stack running.
set -uo pipefail
cd "$(dirname "$0")"

P=sirauth-e2e
PORT=${E2E_PORT:-18080}
B="http://127.0.0.1:$PORT"
AUTH=auth.e2e.test
APP=app.e2e.test
PUB=pub.e2e.test
T=$(mktemp -d)

dc() { docker compose -p "$P" -f compose.yaml "$@"; }
sql() { dc exec -T db psql -U sirauth -d sirauth -tAc "$1"; }
cleanup() {
	[ "${KEEP:-}" = 1 ] || docker compose -p "$P" -f compose.yaml down -v >/dev/null 2>&1
	rm -rf "$T"
}
trap cleanup EXIT

echo "building and starting $P ..."
if ! dc up -d --build --wait >"$T/up.log" 2>&1; then
	cat "$T/up.log"
	dc logs --tail 50
	exit 1
fi

# ── helpers ──────────────────────────────────────────────────────────────────
R=()
F=0
check() { # name condition
	if eval "$2" >/dev/null 2>&1; then R+=("PASS|$1"); else
		R+=("FAIL|$1")
		F=$((F + 1))
		echo "FAIL: $1   (code=$CODE)" >&2
	fi
}
CODE=
# hit HOST PATH [curl args...] → $CODE, body in $T/body, headers in $T/hdr
hit() {
	local host=$1 path=$2
	shift 2
	CODE=$(curl -s -o "$T/body" -D "$T/hdr" -w '%{http_code}' -H "Host: $host" "$@" "$B$path")
}
body_has() { grep -qF -- "$1" "$T/body"; }
hdr_has() { tr -d '\r' <"$T/hdr" | grep -qiF -- "$1"; }
loc() { tr -d '\r' <"$T/hdr" | sed -n 's/^[Ll]ocation: //p'; }
setck() { tr -d '\r' <"$T/hdr" | sed -n 's/^[Ss]et-[Cc]ookie: sir_session=\([^;]*\).*/\1/p' | head -1; }
ck() { printf 'Cookie: sir_session=%s' "$1"; } # curl drops Secure cookies over http, so pass it by hand
bearer() { printf 'Authorization: Bearer %s' "$1"; }
ORIGIN="Origin: http://$AUTH"
post() { # PATH COOKIE [curl -d args...]
	local path=$1 c=$2
	shift 2
	hit "$AUTH" "$path" -H "$ORIGIN" -H "$(ck "$c")" "$@"
}
login() { # EMAIL PASSWORD → cookie value
	hit "$AUTH" /login --data-urlencode "email=$1" --data-urlencode "password=$2"
	setck
}
register() { # EMAIL PASSWORD → user id (JSON API)
	curl -s -H "Host: $AUTH" -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"$2\"}" "$B/register" |
		python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])'
}
newtoken() { # COOKIE NAME LIFETIME → raw token
	post /account/tokens "$1" --data-urlencode "name=$2" -d "expires=$3"
	grep -o 'sirpat_[A-Za-z0-9_-]*' "$T/body" | head -1
}
tokid() { sql "SELECT id FROM api_tokens WHERE token_hash = encode(sha256('$1'::bytea), 'hex')"; }

# ── setup ────────────────────────────────────────────────────────────────────
hit "$AUTH" "/setup?secret=e2e-setup-secret" -H 'Content-Type: application/json' \
	-d '{"admin_email":"admin@e2e.test","admin_password":"admin-pass-1","client_id":"sir-cli","client_secret":"cli-secret","client_name":"SIR CLI"}'
check "setup: first admin created (201)" '[ "$CODE" = 201 ]'
ADMIN_ID=$(sql "SELECT id FROM users WHERE email='admin@e2e.test'")
A=$(login admin@e2e.test admin-pass-1)
check "login: admin gets a sir_session cookie" '[ -n "$A" ]'

# ── cookie gate ──────────────────────────────────────────────────────────────
hit "$APP" /
check "no cookie → 302 to login" '[ "$CODE" = 302 ] && loc | grep -qF "https://$AUTH/login?rd=https://$APP/"'
hit "$APP" /hello -H "$(ck "$A")" -H "X-Auth-Email: spoofed@evil"
check "cookie → 200, backend sees X-Auth-* (client value overwritten)" '[ "$CODE" = 200 ] && body_has "X-Auth-Email: admin@e2e.test" && body_has "X-Auth-Role: admin" && ! body_has spoofed'
hit "$APP" / -X OPTIONS
check "OPTIONS without cookie is not let through" '[ "$CODE" != 200 ]'
hit "$APP" / -H "$(ck "$A")" -H "Authorization: Bearer abc.def.ghi"
check "non-sirpat Bearer reaches backend unchanged" '[ "$CODE" = 200 ] && body_has "Authorization: Bearer abc.def.ghi"'

# ── tokens ───────────────────────────────────────────────────────────────────
TOK=$(newtoken "$A" "ci script" 30)
check "create token: shown once, no-store" '[ "$CODE" = 200 ] && [ -n "$TOK" ] && hdr_has "Cache-Control: no-store"'
hit "$APP" "/api/data?x=1" -H "$(bearer "$TOK")" -H "CF-Connecting-IP: 203.0.113.7"
check "valid sirpat → 200, identity headers set" '[ "$CODE" = 200 ] && body_has "X-Auth-Email: admin@e2e.test"'
check "valid sirpat never reaches the backend" '! body_has sirpat_ && ! body_has "Authorization:"'
hit "$APP" / -H "Authorization: bearer $TOK"
check "lowercase 'bearer' sirpat → 200" '[ "$CODE" = 200 ]'
hit "$PUB" / -H "$(bearer "$TOK")"
check "public route: sirpat stripped" '[ "$CODE" = 200 ] && ! body_has sirpat_'
hit "$PUB" / -H "Authorization: Basic Zm9vOmJhcg=="
check "public route: other Authorization unchanged" 'body_has "Authorization: Basic Zm9vOmJhcg=="'

hit "$APP" / -H "Authorization: Bearer sirpat_garbage"
check "garbage sirpat → 401 JSON + WWW-Authenticate (not 302)" '[ "$CODE" = 401 ] && body_has "{\"error\":\"invalid_token\"}" && hdr_has "WWW-Authenticate: Bearer" && hdr_has "application/json"'
hit "$APP" / -H "Authorization: Bearer sirpat_garbage" -H "$(ck "$A")"
check "garbage sirpat + valid cookie → 401 (no cookie fallback)" '[ "$CODE" = 401 ]'

TOKE=$(newtoken "$A" expiring 30)
sql "UPDATE api_tokens SET expires_at = extract(epoch FROM now())::bigint - 60 WHERE id = '$(tokid "$TOKE")'" >/dev/null
hit "$APP" / -H "$(bearer "$TOKE")"
check "expired sirpat → 401" '[ "$CODE" = 401 ]'

TOKR=$(newtoken "$A" revokeme never)
hit "$APP" / -H "$(bearer "$TOKR")"
check "token works before revoke (now cached)" '[ "$CODE" = 200 ]'
post /account/tokens/revoke "$A" -d "id=$(tokid "$TOKR")"
check "revoke → 303 with flash" '[ "$CODE" = 303 ] && loc | grep -q ok=token-revoked'
hit "$APP" / -H "$(bearer "$TOKR")"
check "revoked token fails on the very next request" '[ "$CODE" = 401 ]'

post /account/tokens/rename "$A" -d "id=$(tokid "$TOK")" --data-urlencode "name=renamed <b>"
check "rename token" '[ "$CODE" = 303 ] && [ "$(sql "SELECT name FROM api_tokens WHERE id='"'"'$(tokid "$TOK")'"'"'")" = "renamed <b>" ]'
hit "$AUTH" /account/tokens -H "$(ck "$A")"
check "tokens page escapes names, shows badges" '[ "$CODE" = 200 ] && body_has "renamed &lt;b&gt;" && body_has Revoked && body_has Expired'

# ── admin revoke, unapproved owner ───────────────────────────────────────────
BOB=$(register bob@e2e.test bob-pass-1)
check "JSON register → id" '[ -n "$BOB" ]'
hit "$AUTH" /login --data-urlencode email=bob@e2e.test --data-urlencode password=bob-pass-1
check "pending user cannot log in (403)" '[ "$CODE" = 403 ]'
post /admin/approve "$A" -d "id=$BOB"
check "admin approve" '[ "$CODE" = 303 ]'
B1=$(login bob@e2e.test bob-pass-1)
BT=$(newtoken "$B1" bobtok 90)
hit "$APP" / -H "$(ck "$B1")"
C1=$CODE
hit "$APP" / -H "$(bearer "$BT")"
check "approved user: cookie and token work" '[ "$C1" = 200 ] && [ "$CODE" = 200 ]'
post /admin/revoke "$A" -d "id=$BOB"
hit "$APP" / -H "$(ck "$B1")"
C1=$CODE
hit "$APP" / -H "$(bearer "$BT")"
check "admin revoke: cookie → 302 and token → 401 at once" '[ "$C1" = 302 ] && [ "$CODE" = 401 ]'
post /admin/approve "$A" -d "id=$BOB"

# ── log out everywhere ───────────────────────────────────────────────────────
CAROL=$(register carol@e2e.test carol-pass-1)
post /admin/approve "$A" -d "id=$CAROL"
K1=$(login carol@e2e.test carol-pass-1)
K2=$(login carol@e2e.test carol-pass-1)
sleep 1.2 # sessions_valid_after has 1s resolution
post /account/logout-all "$K2" -X POST
check "logout-all → 303 to /login, cookie cleared" '[ "$CODE" = 303 ] && [ "$(loc)" = /login ] && hdr_has "Max-Age=0"'
hit "$APP" / -H "$(ck "$K1")"
C1=$CODE
hit "$APP" / -H "$(ck "$K2")"
check "logout-all: every earlier cookie fails at once" '[ "$C1" = 302 ] && [ "$CODE" = 302 ]'

# ── password change ──────────────────────────────────────────────────────────
DAVE=$(register dave@e2e.test dave-pass-1)
post /admin/approve "$A" -d "id=$DAVE"
D1=$(login dave@e2e.test dave-pass-1)
D2=$(login dave@e2e.test dave-pass-1)
sleep 1.2
post /account/password "$D2" -d current_password=wrong -d new_password=dave-pass-2 -d confirm_password=dave-pass-2
check "password change with wrong current password refused" '[ "$CODE" = 303 ] && loc | grep -q err=bad-password'
post /account/password "$D2" -d current_password=dave-pass-1 -d new_password=dave-pass-2 -d confirm_password=dave-pass-2
D3=$(setck)
check "password change → 303 + new cookie" '[ "$CODE" = 303 ] && loc | grep -q ok=password && [ -n "$D3" ]'
hit "$APP" / -H "$(ck "$D1")"
C1=$CODE
hit "$APP" / -H "$(ck "$D2")"
C2=$CODE
hit "$APP" / -H "$(ck "$D3")"
check "password change: other cookies end, this browser stays in" '[ "$C1" = 302 ] && [ "$C2" = 302 ] && [ "$CODE" = 200 ]'
hit "$AUTH" /login --data-urlencode email=dave@e2e.test --data-urlencode password=dave-pass-1
C1=$CODE
N=$(login dave@e2e.test dave-pass-2)
check "old password refused, new password works" '[ "$C1" = 401 ] && [ -n "$N" ]'

# ── origin checks, verify from outside ───────────────────────────────────────
hit "$AUTH" /account/tokens -H "$(ck "$A")" -d name=x -d expires=30
check "POST without Origin → 403" '[ "$CODE" = 403 ]'
hit "$AUTH" /account/logout-all -H "$(ck "$A")" -H "Origin: http://evil.test" -X POST
check "POST with foreign Origin → 403" '[ "$CODE" = 403 ]'
hit "$AUTH" /session/verify -H "$(ck "$A")"
check "auth host /session/verify from outside → 404" '[ "$CODE" = 404 ]'

# ── request_logs ────────────────────────────────────────────────────────────
sleep 2.5
check "log row: host, method, path (query stripped), CF IP, cred=token" \
	'[ "$(sql "SELECT count(*) FROM request_logs WHERE host='"'$APP'"' AND method='"'GET'"' AND path='"'/api/data'"' AND ip='"'203.0.113.7'"' AND cred='"'token'"' AND user_id='"'$ADMIN_ID'"'")" -ge 1 ]'
check "log row: session request logged with cred=session" \
	'[ "$(sql "SELECT count(*) FROM request_logs WHERE path='"'/hello'"' AND cred='"'session'"' AND token_id IS NULL")" -ge 1 ]'
TID=$(tokid "$TOK")
check "token last_used_at / last_used_ip = its newest log row" \
	'[ "$(sql "SELECT count(*) FROM api_tokens t WHERE id='"'$TID'"' AND (t.last_used_at, t.last_used_ip) = (SELECT extract(epoch FROM date_trunc('"'second'"', ts))::bigint, ip FROM request_logs WHERE token_id='"'$TID'"' ORDER BY ts DESC LIMIT 1)")" = 1 ]'
check "failed requests are not logged" '[ "$(sql "SELECT count(*) FROM request_logs WHERE cred='"'token'"' AND token_id IS NULL")" = 0 ]'

hit "$APP" /flush-probe -H "$(ck "$A")"
dc stop -t 10 sir-auth >/dev/null 2>&1
check "docker stop flushes buffered rows" '[ "$(sql "SELECT count(*) FROM request_logs WHERE path='"'/flush-probe'"'")" = 1 ]'
dc up -d --wait sir-auth >/dev/null 2>&1
hit "$APP" / -H "$(ck "$A")"
check "sir-auth back after restart" '[ "$CODE" = 200 ]'

# ── delete account ───────────────────────────────────────────────────────────
B2=$(login bob@e2e.test bob-pass-1)
hit "$APP" /bob-was-here -H "$(ck "$B2")"
sleep 2.5
check "bob has logs and tokens before delete" '[ "$(sql "SELECT count(*) FROM request_logs WHERE user_id='"'$BOB'"'")" -ge 1 ] && [ "$(sql "SELECT count(*) FROM api_tokens WHERE user_id='"'$BOB'"'")" = 1 ]'
post /account/delete "$B2" -d password=bob-pass-1 -d confirm=delete
check "delete needs typed DELETE" '[ "$CODE" = 303 ] && loc | grep -q err=confirm'
post /account/delete "$B2" -d password=bob-pass-1 -d confirm=DELETE
check "delete account → 303 /login" '[ "$CODE" = 303 ] && [ "$(loc)" = /login ]'
hit "$APP" / -H "$(bearer "$BT")"
check "deleted user's token → 401" '[ "$CODE" = 401 ]'
check "delete removes user, tokens and logs" '[ "$(sql "SELECT (SELECT count(*) FROM users WHERE id='"'$BOB'"') + (SELECT count(*) FROM api_tokens WHERE user_id='"'$BOB'"') + (SELECT count(*) FROM request_logs WHERE user_id='"'$BOB'"')")" = 0 ]'
post /account/delete "$A" -d password=admin-pass-1 -d confirm=DELETE
check "last admin cannot delete themselves" '[ "$CODE" = 303 ] && loc | grep -q err=last-admin && [ "$(sql "SELECT count(*) FROM users WHERE id='"'$ADMIN_ID'"'")" = 1 ]'

# ── stats, CSV, old rows ─────────────────────────────────────────────────────
sql "INSERT INTO request_logs (ts, host, method, path, ip, cred, user_id) VALUES (now() - interval '1 year', '$APP', 'GET', '/old-row', '192.0.2.1', 'session', '$ADMIN_ID')" >/dev/null
OLD_DAY=$(sql "SELECT to_char((now() - interval '1 year') AT TIME ZONE 'Asia/Bangkok', 'YYYY-MM-DD')")
TODAY=$(sql "SELECT to_char(now() AT TIME ZONE 'Asia/Bangkok', 'YYYY-MM-DD')")
hit "$AUTH" /account/usage.csv -H "$(ck "$A")"
N7=$(sql "SELECT count(*) FROM request_logs WHERE user_id='$ADMIN_ID' AND ts >= now() - interval '7 days'")
check "CSV (default 7d) parses, row count matches, old row excluded" \
	'[ "$CODE" = 200 ] && hdr_has "text/csv" && python3 -c "import csv,sys; r=list(csv.reader(open(sys.argv[1]))); assert r[0][:3]==[\"time\",\"host\",\"method\"]; assert len(r)-1==int(sys.argv[2]), (len(r)-1, sys.argv[2]); assert not any(x[3]==\"/old-row\" for x in r[1:])" "$T/body" "$N7"'
hit "$AUTH" "/account/usage.csv?from=$OLD_DAY&to=$OLD_DAY" -H "$(ck "$A")"
check "CSV with a date range a year back contains the old row only" \
	'[ "$CODE" = 200 ] && python3 -c "import csv,sys; r=list(csv.reader(open(sys.argv[1]))); assert [x[3] for x in r[1:]]==[\"/old-row\"], r" "$T/body"'
check "old row is still in the table" '[ "$(sql "SELECT count(*) FROM request_logs WHERE path='"'/old-row'"'")" = 1 ]'
hit "$AUTH" /account/usage -H "$(ck "$A")"
C1=$CODE
cp "$T/body" "$T/usage7d"
hit "$AUTH" "/account/usage?from=$OLD_DAY&to=$OLD_DAY" -H "$(ck "$A")"
check "usage page: old row only when the range covers it" '[ "$C1" = 200 ] && ! grep -qF /old-row "$T/usage7d" && [ "$CODE" = 200 ] && body_has /old-row'
hit "$AUTH" "/account/usage?range=24h&host=$APP&page=1" -H "$(ck "$A")"
check "usage page with filters renders" '[ "$CODE" = 200 ] && body_has "Recent requests" && body_has "/api/data"'
hit "$AUTH" "/admin/stats?from=$OLD_DAY&to=$TODAY" -H "$(ck "$A")"
check "admin stats: 200, per-user table, dropped counter" '[ "$CODE" = 200 ] && body_has "By user" && body_has "Dropped since start" && body_has dave@e2e.test'
hit "$AUTH" /admin/stats.csv -H "$(ck "$A")"
check "admin CSV" '[ "$CODE" = 200 ] && head -1 "$T/body" | grep -q "^time,host"'
hit "$AUTH" /admin/stats -H "$(ck "$D3")"
check "admin stats forbidden for non-admin" '[ "$CODE" = 403 ]'

# ── pages and unchanged flows ────────────────────────────────────────────────
hit "$AUTH" / -H "$(ck "$A")"
check "dashboard renders with watcher unreachable" '[ "$CODE" = 200 ] && body_has "service list is unavailable"'
hit "$AUTH" /account -H "$(ck "$A")"
check "account page" '[ "$CODE" = 200 ] && body_has "Change password" && body_has "Delete account"'
hit "$AUTH" /account
check "account page without cookie → login" '[ "$CODE" = 302 ] && loc | grep -q "^/login?rd="'
hit "$AUTH" "/login?rd=https://$APP/x" -H "$(ck "$A")"
check "GET /login while signed in → redirect to rd" '[ "$CODE" = 302 ] && [ "$(loc)" = "https://$APP/x" ]'
hit "$AUTH" /login
check "login form has show-password toggle" '[ "$CODE" = 200 ] && body_has ">Show</button>"'
hit "$AUTH" /login -H "$(ck "$K1")"
check "GET /login with an ended cookie shows the form (no loop)" '[ "$CODE" = 200 ]'

hit "$AUTH" "/oauth/authorize?response_type=code&client_id=sir-cli&redirect_uri=http://127.0.0.1:9999/cb&state=s1"
C1=$CODE
hit "$AUTH" /oauth/authorize -d client_id=sir-cli -d redirect_uri=http://127.0.0.1:9999/cb -d state=s1 -d scope=openid \
	--data-urlencode email=admin@e2e.test -d password=admin-pass-1
CODEV=$(loc | sed -n 's/.*code=\([^&]*\).*/\1/p')
AT=$(curl -s -H "Host: $AUTH" -d grant_type=authorization_code -d "code=$CODEV" -d redirect_uri=http://127.0.0.1:9999/cb \
	-d client_id=sir-cli -d client_secret=cli-secret "$B/oauth/token" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
check "OAuth loopback flow issues an access token" '[ "$C1" = 200 ] && [ -n "$AT" ]'
hit "$AUTH" /api/me -H "$(bearer "$AT")"
check "/api/me with OAuth bearer (passes through nginx)" '[ "$CODE" = 200 ] && body_has admin@e2e.test'
hit "$AUTH" /api/me -H "$(bearer "$TOK")"
check "/api/me refuses a sirpat token" '[ "$CODE" = 401 ]'
EVE=$(register eve@e2e.test eve-pass-1)
post /admin/reject "$A" -d "id=$EVE"
check "admin reject deletes pending user" '[ "$CODE" = 303 ] && [ "$(sql "SELECT count(*) FROM users WHERE id='"'$EVE'"'")" = 0 ]'

# ── report ───────────────────────────────────────────────────────────────────
echo
printf '%-6s %s\n' RESULT CASE
printf '%-6s %s\n' ------ ----
for r in "${R[@]}"; do printf '%-6s %s\n' "${r%%|*}" "${r#*|}"; done
echo
echo "$((${#R[@]} - F))/${#R[@]} passed"
if [ "$F" -gt 0 ]; then
	echo "--- sir-auth logs ---"
	dc logs --tail 30 sir-auth
fi
exit $((F > 0))
