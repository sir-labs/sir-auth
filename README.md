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
| `ALLOW_REGISTER` | `true` | set `false` to disable `POST /register` |
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
- `GET /` shows the signed-in user, or redirects to `/login`.

Existing APIs are unchanged: the loopback OAuth flow (`/oauth/authorize`, `/oauth/token`, `/oauth/revoke`), `POST /register`, `POST /setup` and `/api/*`.
