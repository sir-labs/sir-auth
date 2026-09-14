package handler

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sir-labs/sir-auth/internal/model"
	"github.com/sir-labs/sir-auth/internal/store"
	"github.com/sir-labs/sir-auth/internal/token"
)

// ttlCache caches loader results per key for ttl, including nil ("not found") results.
// A failed reload serves the stale value if there is one. The map is cleared when it
// reaches maxEntries.
type ttlCache[T any] struct {
	mu   sync.Mutex
	ttl  time.Duration
	max  int
	m    map[string]cacheEntry[T]
	load func(ctx context.Context, key string) (T, error)
}

type cacheEntry[T any] struct {
	v  T
	at time.Time
}

func newTTLCache[T any](ttl time.Duration, max int, load func(context.Context, string) (T, error)) *ttlCache[T] {
	return &ttlCache[T]{ttl: ttl, max: max, m: map[string]cacheEntry[T]{}, load: load}
}

func (c *ttlCache[T]) Get(ctx context.Context, key string) (T, error) {
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if ok && time.Since(e.at) < c.ttl {
		return e.v, nil
	}
	v, err := c.load(ctx, key)
	if err != nil {
		if ok {
			return e.v, nil // stale beats down
		}
		return v, err
	}
	c.mu.Lock()
	if len(c.m) >= c.max {
		c.m = map[string]cacheEntry[T]{}
	}
	c.m[key] = cacheEntry[T]{v: v, at: time.Now()}
	c.mu.Unlock()
	return v, nil
}

func (c *ttlCache[T]) Clear() {
	c.mu.Lock()
	c.m = map[string]cacheEntry[T]{}
	c.mu.Unlock()
}

// Loaders are variables so tests can stub the database.
var (
	loadUser = func(ctx context.Context, id string) (*model.User, error) {
		s, err := store.Open()
		if err != nil {
			return nil, err
		}
		return s.GetUserByID(ctx, id)
	}
	loadToken = func(ctx context.Context, hash string) (*model.APIToken, error) {
		s, err := store.Open()
		if err != nil {
			return nil, err
		}
		return s.GetAPITokenByHash(ctx, hash)
	}

	loadPolicy = func(ctx context.Context, host string) (*model.RoutePolicy, error) {
		s, err := store.Open()
		if err != nil {
			return nil, err
		}
		return s.GetRoutePolicy(ctx, host)
	}

	policyCache = newTTLCache(30*time.Second, 10000, func(ctx context.Context, h string) (*model.RoutePolicy, error) { return loadPolicy(ctx, h) })
	userCache   = newTTLCache(30*time.Second, 10000, func(ctx context.Context, id string) (*model.User, error) { return loadUser(ctx, id) })
	tokCache    = newTTLCache(30*time.Second, 10000, func(ctx context.Context, h string) (*model.APIToken, error) { return loadToken(ctx, h) })
)

// invalidateAuth drops every cached user and token. Called after any change that
// affects who may pass /session/verify, so it takes effect immediately (single process).
func invalidateAuth() {
	userCache.Clear()
	tokCache.Clear()
	policyCache.Clear()
}

// hostPublic reports whether an admin made host public. Unknown (DB down, nothing
// cached) means login required: fail closed.
func hostPublic(ctx context.Context, host string) bool {
	p, err := policyCache.Get(ctx, strings.ToLower(host))
	return err == nil && p != nil && p.Public
}

type identity struct {
	ID, Email, Role string
	TokenID         *string
}

// cookieIdentity checks the sir_session cookie: valid JWT, user approved and the cookie
// not older than sessions_valid_after. If the DB is unreachable and nothing is cached,
// the JWT claims alone are trusted (fail open, as before this check existed).
func cookieIdentity(r *http.Request) *identity {
	claims := sessionClaims(r)
	if claims == nil {
		return nil
	}
	u, err := userCache.Get(r.Context(), claims.Sub)
	if err != nil {
		return &identity{ID: claims.Sub, Email: claims.Email, Role: claims.Role}
	}
	if u == nil || !u.Approved || claims.Iat < u.SessionsValidAfter {
		return nil
	}
	return &identity{ID: u.ID, Email: u.Email, Role: u.Role}
}

// tokenIdentity checks a raw sirpat_ token. Any doubt (DB down included) is a refusal.
func tokenIdentity(ctx context.Context, raw string) *identity {
	t, err := tokCache.Get(ctx, token.HashPAT(raw))
	if err != nil || t == nil || !t.Active(time.Now().Unix()) {
		return nil
	}
	u, err := userCache.Get(ctx, t.UserID)
	if err != nil || u == nil || !u.Approved {
		return nil
	}
	id := t.ID
	return &identity{ID: u.ID, Email: u.Email, Role: u.Role, TokenID: &id}
}

// requestPath strips the query from X-Original-URI and caps it at 512 bytes.
func requestPath(uri string) string {
	p, _, _ := strings.Cut(uri, "?")
	if len(p) > 512 {
		p = strings.ToValidUTF8(p[:512], "")
	}
	if p == "" {
		p = "/"
	}
	return p
}

func capLen(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "")
	}
	return s
}

// VerifySession handles GET /session/verify for nginx auth_request: 200 with
// X-Auth-User-Id/Email/Role, or 401 with an empty body. A sirpat_ bearer token is
// checked instead of the cookie, never in addition to it. On a host an admin made
// public, a request without valid credentials is 200 with no X-Auth-* headers
// (anonymous), but a bad sirpat token is still 401.
func VerifySession(w http.ResponseWriter, r *http.Request) {
	var id *identity
	cred := "session"
	host := r.Header.Get("X-Original-Host")
	if raw, ok := token.ParseBearerPAT(r.Header.Get("Authorization")); ok {
		if id = tokenIdentity(r.Context(), raw); id == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		cred = "token"
	} else {
		id = cookieIdentity(r)
	}
	if id == nil {
		if !hostPublic(r.Context(), host) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		id, cred = &identity{}, "anonymous"
	}
	logRequest(r, host, cred, id)
	if cred != "anonymous" {
		w.Header().Set("X-Auth-User-Id", id.ID)
		w.Header().Set("X-Auth-Email", id.Email)
		w.Header().Set("X-Auth-Role", id.Role)
	}
	w.WriteHeader(http.StatusOK)
}

func logRequest(r *http.Request, host, cred string, id *identity) {
	store.LogUsage(model.RequestLog{
		TS:      time.Now(),
		Host:    capLen(host, 255),
		Method:  capLen(r.Header.Get("X-Original-Method"), 16),
		Path:    requestPath(r.Header.Get("X-Original-URI")),
		IP:      capLen(r.Header.Get("X-Real-IP"), 64),
		Cred:    cred,
		TokenID: id.TokenID,
		UserID:  id.ID,
	})
}
