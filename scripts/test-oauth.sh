#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tag="sir-auth-pkce-test-$$"
cleanup(){ docker rm -f "$tag" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$tag" --tmpfs /var/lib/postgresql/data -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine >/dev/null
for attempt in $(seq 1 30); do
 if docker exec "$tag" pg_isready -U postgres >/dev/null 2>&1; then break; fi
 sleep 1
done
db_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$tag")
TEST_DATABASE_URL="postgres://postgres:test@$db_ip/test" go test -count=1 ./...
