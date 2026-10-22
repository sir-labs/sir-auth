# Note App native authentication

Adds public client `note-app-desktop` with S256 PKCE and loopback callback
`http://127.0.0.1:<ephemeral-port>/callback`. No secret is distributed with the app.
Public authorization requires a 32–200 character state; the desktop verifies it.
Redirect query/userinfo/fragment and other hosts/paths are rejected. The token
exchange requires the exact redirect used to issue the code.

A signed-in browser can explicitly connect this first-party client using a
same-origin confirmation form. Otherwise the existing password sign-in form is
used. Approved-user checks remain in place. Native requests carry the access JWT
as the existing `sir_session` credential to the gateway; they do not change the
PAT or gateway trust boundary.

Code consumption and refresh-token claims use conditional database updates to
prevent concurrent reuse. Existing confidential clients still require their
secret. Schema changes are additive and keep existing rows confidential.

Run `bash scripts/test-oauth.sh` for isolated PostgreSQL integration coverage:
PKCE invalid proof, code replay, concurrent refresh and confidential-client
compatibility. It creates/removes a temporary database container; no host ports
or persistent volumes are used. `go test ./...` alone skips that integration test
without TEST_DATABASE_URL. CI runs the isolated script before deployment.

Revocation invalidates the refresh token; issued access JWTs remain valid until
their existing short expiration. This does not introduce an access-token denylist.
