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
- `GET /session/verify` returns 200 with `X-Auth-User-Id`, `X-Auth-Email` and `X-Auth-Role` for a valid cookie, and 401 with an empty body otherwise. It does not query the database.
- `GET /` shows the signed-in user (with an `Admin` link for admins), or redirects to `/login`.

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
- **Revoking or deleting does not end existing sessions.** `/session/verify` checks only the JWT and never the database, so a cookie that has already been issued
  stays valid until it expires (`SESSION_TTL`, default 7 days). Rotate `JWT_SECRET` to force everyone out immediately.
