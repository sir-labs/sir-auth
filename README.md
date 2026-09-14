# sir-auth

Self-hosted Go auth service for SIR Labs, served at `https://auth.sir-labs.com`.
Backed by PostgreSQL. The schema is migrated automatically at startup (gorm AutoMigrate).

## Run

```sh
cp .env.example .env   # fill in real values
docker compose up --build -d                                  # standalone
docker compose -f compose.yaml -f compose.sir.yaml up -d      # behind sir-server (joins sir-server_sir-net)
```

CI (`.github/workflows/deploy-self-hosted.yml`) deploys on push to `main` using a self-hosted runner.
You need the repo secrets `DATABASE_URL`, `JWT_SECRET`, `SETUP_SECRET` and `POSTGRES_PASSWORD`.

## Environment

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | – | e.g. `postgres://sirauth:PW@sir-auth-db:5432/sirauth?sslmode=disable`; PW must equal `POSTGRES_PASSWORD` |
| `POSTGRES_PASSWORD` | – | used by the `sir-auth-db` container |
| `JWT_SECRET` | – | HS256 key for access tokens and session cookies |
| `SETUP_SECRET` | – | guards `POST /setup` |
| `COOKIE_DOMAIN` | `.sir-labs.com` | session cookie domain; also bounds allowed `rd` redirects |
| `SESSION_TTL` | `168h` | Go duration (`7d` is invalid) |
| `ALLOW_REGISTER` | `true` | set `false` to disable `GET`/`POST /register` |
| `WATCHER_URL` | `http://sir-watcher:8080/routes` | route list for the dashboard's service cards (2s timeout, cached 60s; the page still renders if it is down) |
| `PORT` | `8080` | |

## First-time setup

Seed the first admin and the default OAuth client (this only works while the users table is empty):

```sh
curl -X POST "https://auth.sir-labs.com/setup?secret=$SETUP_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"admin_email":"you@example.com","admin_password":"...","client_id":"sir-cli","client_secret":"...","client_name":"SIR CLI"}'
```

## Browser session contract (nginx `auth_request`)

- Cookie `sir_session`: HS256 JWT, `Domain=$COOKIE_DOMAIN; Path=/; HttpOnly; Secure; SameSite=Lax`, lifetime `SESSION_TTL`.
- `GET /login?rd=<url>` shows the form. `POST /login` (`email`, `password`, `rd`) sets the cookie and returns a 302 to `rd`.
  nginx sends `rd` as the last, unencoded param (`/login?rd=https://$host$request_uri`); everything after the first `rd=` is taken verbatim.
  `rd` must be `https://` on the cookie apex or a subdomain of it. Any other `rd` redirects to `/`.
- `GET|POST /logout` clears the cookie and returns a 302 to `/login`.
- `GET /session/verify` returns 200 with `X-Auth-User-Id`, `X-Auth-Email` and `X-Auth-Role`, or 401 with an empty body. Nothing else.
  - nginx sends `Cookie`, `Authorization`, `X-Original-URI`, `X-Original-Host`, `X-Original-Method` and `X-Real-IP` (client IP: `CF-Connecting-IP`, else the peer).
  - With `Authorization: Bearer sirpat_…` ("Bearer" is case-insensitive), only the token is checked. It must exist, not be revoked or expired, and its owner must be approved. A bad token is a 401 **even if a valid cookie is also sent**.
  - Otherwise the cookie is checked: valid JWT, user still exists and is approved, and the cookie's `iat` is not before `users.sessions_valid_after`.
  - Users and tokens are cached in-process for 30s (misses too; a stale entry is served if the DB fails). If the DB is down and nothing is cached, cookies fall back to the JWT alone (fail open) and tokens are refused (fail closed).
  - Every 200 is queued for `request_logs` (see Request log).
  - `auth.<domain>/session/verify` answers 404 from outside (nginx); only the internal `auth_request` subrequest reaches it.
- `GET /` is the dashboard: service cards from `WATCHER_URL`, your requests in the last 24h and quick links. Without a session it redirects to `/login`.
- `GET /login` while already signed in redirects straight to `rd`.

Existing APIs are unchanged: the loopback OAuth flow (`/oauth/authorize`, `/oauth/token`, `/oauth/revoke`), `POST /register`, `POST /setup` and `/api/*`.

## Registration and admin approval

A session cookie gets you into every `*.sir-labs.com` site, so new accounts must be approved by an admin first.

- `users.approved` (default `false`) is added at startup. Every startup also runs `UPDATE users SET approved = TRUE WHERE role = 'admin'`,
  so admins can never be locked out. As a side effect, revoking another admin's approval is undone on the next restart.
- `GET /register?rd=<url>` shows the sign-up form (email, password, confirm password; password must be at least 8 characters). The form `POST /register`
  creates an unapproved `user` and shows "Registered — waiting for admin approval". `POST /register` with a JSON body keeps the original
  JSON API (201 `{id,email,role}`), but that account is also unapproved. Both respect `ALLOW_REGISTER=false`.
- Unapproved users are refused with "Your account is waiting for admin approval." at `POST /login` (no cookie) and `POST /oauth/authorize` (no code).
  Their refresh tokens are rejected (`invalid_grant`). Accounts created by `/setup` or by an admin via `POST /api/admin/users` are approved.
- `GET /admin` is the admin UI. It needs a `sir_session` cookie for an approved admin: with no session it redirects to `/login?rd=https://<host>/admin`,
  and for a logged-in non-admin it returns 403. It lists pending users (Approve / Reject) and approved users (Revoke approval / Delete).
  The form posts are `POST /admin/approve|reject|revoke|delete` with field `id`. Reject deletes a pending user.
  You cannot revoke or delete yourself or the last approved admin. Besides `SameSite=Lax`, these posts need an `Origin` host (or `Referer`
  host if `Origin` is missing) equal to the request `Host`. Every action is written to `system_logs`.
- **Revoke, delete, approve and every account change take effect immediately.** Each clears the verify cache in the same process
  (there is one container), so a revoked or deleted user's cookies and tokens get 401 on their next request. Re-approving a user
  makes their existing cookies work again. Admin delete/reject also deletes the user's request logs.
- `GET /admin/stats` (+ `/admin/stats.csv`) shows everyone's request stats, a per-user table and the dropped-events counter.

## Account (`/account`)

Every page needs a `sir_session` cookie (else a 302 to `/login?rd=…`). Every POST needs a same-origin `Origin`/`Referer` (else 403) and is checked against the DB.

- Nav bar: Home · Account · Tokens · Usage · Admin (admins) · email · Log out.
- `POST /account/password` (`current_password`, `new_password`, `confirm_password`): sets `sessions_valid_after = now` and revokes
  OAuth refresh tokens, so every other browser is signed out. This browser gets a fresh cookie and stays signed in.
- `POST /account/logout-all`: the same without the password change, including this browser. Personal access tokens are not affected.
- `POST /account/delete` (`password`, `confirm=DELETE`): deletes the user, their tokens and their request logs. The last approved admin is refused.
- Results come back as `?ok=<code>` / `?err=<code>` and are shown as fixed strings (no user input is echoed).

## Personal access tokens (`/account/tokens`)

For scripts and tools that call `*.sir-labs.com` services without a browser:

```sh
curl -H "Authorization: Bearer sirpat_…" https://your-app.sir-labs.com/
```

- Format: `sirpat_` + 43 random URL-safe characters. Only the sha256 and a 12-character prefix are stored. The token is shown once, on a `Cache-Control: no-store` page.
- A token works on every gated service and acts as its owner (the backend sees the owner's `X-Auth-*` headers). nginx removes it before the request reaches any backend.
  Any other `Authorization` header (e.g. an OAuth access token) is passed through unchanged.
- A missing, wrong, expired or revoked token (or an unapproved owner) gets `401 {"error":"invalid_token"}` with `WWW-Authenticate: Bearer`, never a login redirect.
- Lifetime is picked at creation: 30, 90 or 365 days, or never. Name up to 64 characters, at most 50 active tokens per user.
  Rename and revoke on the page; revoking keeps the row so old log entries still show the token's name.
- Tokens do **not** work on sir-auth's own `/api/*` (those take OAuth access tokens).

## Request log and stats

- Every request that passes `/session/verify` becomes a `request_logs` row: time, host, method, path (query stripped, at most 512 bytes), client IP,
  credential (`session`/`token`), token and user. Rows are buffered in memory (10k) and written every 2s or 500 rows. Shutdown (SIGTERM) flushes the buffer.
  If the buffer is full, events are dropped and counted (`/admin/stats`).
- `/account/usage` (own) and `/admin/stats` (everyone): 24h/7d/30d tiles, requests per day (Asia/Bangkok), per-service and per-credential tables
  (per-user for admins), and recent requests (50 per page, filter by service or token). CSV export at `/account/usage.csv` and `/admin/stats.csv`.
  Pages and CSV always cover one window: `range=24h|7d|30d` (default 7d) or `from=YYYY-MM-DD&to=YYYY-MM-DD` (inclusive, Bangkok days).
- Limits: only gated routes are counted (public routes never reach sir-auth), and the backend's response status is unknown to `auth_request`.
  `CF-Connecting-IP` can be faked by anyone who reaches the gateway directly, so the IP is informational.
- **Logs are kept forever.** Nothing purges them. Every request on a gated site, static assets included, adds a row, so the Postgres volume grows with traffic.
  The `(ts)`, `(user_id, ts)` and `(token_id, ts)` indexes keep windowed queries fast. Watch the volume size; monthly partitions or archiving old rows is the upgrade path.

## Tests

```sh
go test ./...   # unit tests
e2e/run.sh      # nginx (mirrors the watcher config) + sir-auth + postgres + whoami in compose project sirauth-e2e on 127.0.0.1:18080
```

`e2e/run.sh` builds the image, runs every case, prints a PASS/FAIL table and removes the stack (`KEEP=1` keeps it).
