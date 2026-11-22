package stonewrit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type compactFixture struct {
	refreshFixture
	owner                 User
	queries               int
	denied                bool
	policyErr, backendErr error
}

func (f *compactFixture) AllowSessionCookieCache(context.Context) (bool, error) {
	return !f.denied, f.policyErr
}
func (f *compactFixture) Session(ctx context.Context, token string) (StoredSession, User, error) {
	f.queries++
	if f.backendErr != nil {
		return StoredSession{}, User{}, f.backendErr
	}
	row, _, err := f.refreshFixture.Session(ctx, token)
	return row, f.owner, err
}

func TestCompactSessionLifetimeAndBinding(t *testing.T) {
	cleanConfigEnv(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	issued := now
	store := &compactFixture{
		refreshFixture: refreshFixture{row: StoredSession{Session: Session{ID: "s", Token: "signed-in", UserID: "u", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour)}}},
		owner:          User{ID: "u", Name: "Original", Email: "account@example.test", CreatedAt: now, UpdatedAt: now},
	}
	const origin = "https://auth.example.test"
	oldKey, nextKey := strings.Repeat("a", 32), strings.Repeat("b", 32)
	opts := Options{BaseURL: origin, Secret: oldKey, Store: store, SessionCookieCache: &SessionCookieCacheOptions{MaxAge: 90 * time.Second}}
	host := func(o Options) *Auth {
		t.Helper()
		a, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		a.now = func() time.Time { return now }
		return a
	}
	a := host(opts)
	token := a.SessionCookie(store.row.Token, true)
	read := func(server *Auth, query string, cookies ...*http.Cookie) (*SessionResult, *httptest.ResponseRecorder) {
		t.Helper()
		r := httptest.NewRequest("GET", origin+"/api/auth/get-session"+query, nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		var result *SessionResult
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("session response %d %s", w.Code, w.Body)
		}
		return result, w
	}
	dataName := a.prefixedCookieName("session_data")
	cacheCookie := func(w *httptest.ResponseRecorder) *http.Cookie {
		t.Helper()
		for _, c := range w.Result().Cookies() {
			if c.Name == dataName && c.MaxAge >= 0 {
				return c
			}
		}
		t.Fatal("snapshot cookie missing")
		return nil
	}
	_, w := read(a, "", token)
	cache := cacheCookie(w)
	if cache.MaxAge != 90 || !cache.HttpOnly || !cache.Secure {
		t.Fatal("cache attributes")
	}
	store.owner.Name = "Live"
	queries := store.queries
	for _, q := range []string{"", "?disableCookieCache=", "?disableRefresh=true"} {
		got, w := read(a, q, token, cache)
		if got == nil || got.User.Name != "Original" || store.queries != queries || len(w.Result().Cookies()) != 0 {
			t.Fatal("cache hit read storage or renewed", q)
		}
	}
	if none, _ := read(a, "", cache); none != nil {
		t.Fatal("snapshot without a signed session credential")
	}
	for _, q := range []string{"?disableCookieCache=true", "?disableCookieCache=false"} {
		got, w := read(a, q, token, cache)
		if got.User.Name != "Live" || len(w.Result().Cookies()) != 1 || cacheCookie(w).Value == cache.Value {
			t.Fatal("forced refresh emitted duplicate or stale cache headers", q)
		}
	}
	opts.Secrets = []VersionedSecret{{Version: 2, Value: nextKey}, {Version: 1, Value: oldKey}}
	rotated := host(opts)
	if got, _ := read(rotated, "", token, cache); got == nil || got.User.Name != "Original" {
		t.Fatal("retained rotation key failed")
	}
	opts.Secrets = opts.Secrets[:1]
	removed := host(opts)
	if got, _ := read(removed, "", token, cache); got != nil {
		t.Fatal("removed credential signing key")
	}
	if got, _ := read(removed, "", removed.SessionCookie(store.row.Token, true), cache); got == nil || got.User.Name != "Live" {
		t.Fatal("removed snapshot signing key")
	}
	opts.Secrets = nil
	opts.SessionCookieCache = &SessionCookieCacheOptions{Version: "new"}
	if got, _ := read(host(opts), "", token, cache); got.User.Name != "Live" {
		t.Fatal("cache version did not invalidate")
	}
	// A public cached view can remain available within its finite window after revocation.
	store.deleted = true
	if got, _ := read(a, "", token, cache); got == nil {
		t.Fatal("cache expired too soon")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(token)
	req.AddCookie(cache)
	if live, err := a.GetSession(t.Context(), req.Header); err != nil || live != nil {
		t.Fatal("native authorization used a cached session")
	}
	now = issued.Add(90 * time.Second)
	if got, _ := read(a, "", token, cache); got != nil {
		t.Fatal("outer expiry ignored")
	}
	now = issued
	data := SessionResult{Session: store.row.Session, User: store.owner}
	snapshot := func(change func(*SessionResult)) *http.Cookie {
		t.Helper()
		copy := data
		change(&copy)
		raw, err := json.Marshal(sessionCachePayload{Session: copy.Session, User: copy.User, UpdatedAt: now.UnixMilli(), Version: "1"})
		if err != nil {
			t.Fatal(err)
		}
		envelope := compactSessionEnvelope{Payload: raw, ExpiresAt: now.Add(time.Minute).UnixMilli()}
		envelope.Signature = base64.RawURLEncoding.EncodeToString(sessionCacheMAC(oldKey, envelope.signingInput()))
		wire, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: cache.Name, Value: base64.RawURLEncoding.EncodeToString(wire)}
	}
	for _, c := range []*http.Cookie{
		snapshot(func(s *SessionResult) { s.Session.ExpiresAt = now }),
		snapshot(func(s *SessionResult) { s.Session.UserID = "other" }),
		snapshot(func(s *SessionResult) { s.Session.ID = "" }),
		snapshot(func(s *SessionResult) { s.Session.Token = "other-token" }),
		snapshot(func(s *SessionResult) { s.User.Email = "" }),
		{Name: cache.Name, Value: cache.Value[:len(cache.Value)/2]},
		{Name: cache.Name, Value: strings.Repeat("x", maxSessionChunkSize+1)},
	} {
		if got, _ := read(a, "", token, c); got != nil {
			t.Fatal("invalid snapshot supplied a session")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(cache.Value)
	if err != nil {
		t.Fatal(err)
	}
	var envelope compactSessionEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	missing := envelope
	var required map[string]json.RawMessage
	if err := json.Unmarshal(missing.Payload, &required); err != nil {
		t.Fatal(err)
	}
	var user map[string]any
	if err := json.Unmarshal(required["user"], &user); err != nil {
		t.Fatal(err)
	}
	delete(user, "emailVerified")
	required["user"], err = json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	missing.Payload, err = json.Marshal(required)
	if err != nil {
		t.Fatal(err)
	}
	missing.Signature = base64.RawURLEncoding.EncodeToString(sessionCacheMAC(oldKey, missing.signingInput()))
	partial, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := read(a, "", token, &http.Cookie{Name: cache.Name, Value: base64.RawURLEncoding.EncodeToString(partial)}); got != nil {
		t.Fatal("signed partial profile accepted")
	}
	envelope.ExpiresAt++
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	tampered := &http.Cookie{Name: cache.Name, Value: base64.RawURLEncoding.EncodeToString(raw)}
	if got, _ := read(a, "", token, token, cache); got != nil {
		t.Fatal("ambiguous signed credential cookies activated the cache")
	}
	if got, _ := read(a, "", token, tampered); got != nil {
		t.Fatal("tampered expiry accepted")
	}
	short := testSessionCache(t, a, data, false)[0]
	if short.MaxAge != 0 {
		t.Fatal("nonpersistent cache became persistent")
	}
	now = issued.Add(time.Minute)
	if got, _ := read(a, "", token, short); got != nil {
		t.Fatal("nonpersistent cache exceeded one minute")
	}
	now = issued
	store.deleted = false
	store.denied = true
	if got, _ := read(a, "", token, cache); got == nil || got.User.Name != "Live" {
		t.Fatal("store revocation policy bypassed")
	}
	store.denied = false
	store.policyErr = errors.New("policy temporarily unavailable")
	if got, _ := read(a, "", token, cache); got.User.Name != "Live" {
		t.Fatal("failed cache eligibility fell back to stale data")
	}
	store.backendErr = errors.New("private store detail")
	errorRequest := httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
	errorRequest.AddCookie(token)
	errorRequest.AddCookie(cache)
	failed := httptest.NewRecorder()
	a.ServeHTTP(failed, errorRequest)
	if failed.Code != 500 || strings.Contains(failed.Body.String(), "private store detail") || len(failed.Result().Cookies()) != 0 {
		t.Fatal("failed live lookup emitted cached data or credentials")
	}
	store.policyErr = nil
	store.backendErr = nil
	immediate := time.Duration(0)
	opts.SessionUpdateAge = &immediate
	opts.SessionCookieCache = &SessionCookieCacheOptions{}
	due := host(opts)
	queries = store.queries
	_, w = read(due, "?disableCookieCache=true", token, cache)
	if store.queries != queries+1 || store.refreshes != 1 {
		t.Fatal("sliding refresh double-read the session")
	}
}

func TestCompactSessionChunksAndRequestCredentials(t *testing.T) {
	now := time.Now().UTC()
	f := &compactFixture{
		refreshFixture: refreshFixture{row: StoredSession{Session: Session{ID: "s", Token: "token", UserID: "u", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}},
		owner:          User{ID: "u", Name: "Original", Email: "a@example.test", CreatedAt: now, UpdatedAt: now},
	}
	opts := Options{BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 32), Store: f, SessionCookieCache: &SessionCookieCacheOptions{}, CrossSubDomainCookies: &CrossSubDomainCookiesOptions{Domain: "example.test"}}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	data := SessionResult{Session: f.row.Session, User: f.owner}
	image := strings.Repeat("z", 11000)
	data.User.Image = &image
	chunks := testSessionCache(t, a, data, true)
	if len(chunks) < 2 {
		t.Fatal("large profile must be chunked")
	}
	request := func(cookies ...*http.Cookie) *http.Request {
		r := httptest.NewRequest("GET", opts.BaseURL+"/api/auth/get-session", nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		return r
	}
	token := a.SessionCookie(f.row.Token, true)
	base := a.prefixedCookieName("session_data")
	complete := append([]*http.Cookie{token}, chunks...)
	if got, err := a.cachedSessionView(request(complete...), f.row.Token); err != nil || got == nil || *got.User.Image != image {
		t.Fatal("complete chunked cache lost")
	}
	for _, pieces := range [][]*http.Cookie{
		chunks[1:], chunks[:len(chunks)-1],
		append(append([]*http.Cookie{}, chunks...), chunks[0]),
		append(append([]*http.Cookie{}, chunks...), &http.Cookie{Name: base, Value: "other"}),
		{&http.Cookie{Name: base + ".100", Value: "x"}},
	} {
		if got, err := a.cachedSessionView(request(append([]*http.Cookie{token}, pieces...)...), f.row.Token); err != nil || got != nil {
			t.Fatal("ambiguous or incomplete chunked cache")
		}
	}
	for _, c := range chunks {
		if len(c.String()) > 4050 || c.Domain != "example.test" {
			t.Fatal("chunk exceeded cookie scope or size")
		}
	}
	shrunk := data
	shrunk.User.Image = nil
	h := make(http.Header)
	a.writeCachedSessionView(h, request(complete...), shrunk, true)
	rows := (&http.Response{Header: h}).Cookies()
	if len(rows) != 2*len(chunks)+1 {
		t.Fatal("old chunks were not retired in both host/domain scopes", len(rows))
	}
	for _, c := range rows {
		if c.Name != base && c.MaxAge != -1 {
			t.Fatal("obsolete chunk still live")
		}
	}
	oversize := strings.Repeat("x", maxSessionChunkSize*maxSessionChunks)
	data.User.Image = &oversize
	if testSessionCache(t, a, data, true) != nil {
		t.Fatal("oversized profile partially issued")
	}
	delegated := "admin"
	shrunk.Session.ImpersonatedBy = &delegated
	if testSessionCache(t, a, shrunk, true) != nil {
		t.Fatal("delegated session entered browser cache")
	}
	shrunk.Session.ImpersonatedBy = nil
	shrunk.Session.CredentialType = "application"
	if testSessionCache(t, a, shrunk, true) != nil {
		t.Fatal("application credential entered browser cache")
	}
	f.owner.Name = "Live"
	hookCalls := 0
	opts.Plugins = []Plugin{{ID: "current-view", OnReadSession: func(_ context.Context, s *SessionResult) error { hookCalls++; s.User.Name = "Hook"; return nil }}}
	withHook, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	withHook.ServeHTTP(w, request(complete...))
	if hookCalls != 1 || !strings.Contains(w.Body.String(), `"name":"Hook"`) {
		t.Fatal("snapshot skipped a live read hook")
	}
	opts.Plugins = []Plugin{{ID: "principal", CredentialSessions: &CredentialSessionResolver{
		Matches: func(h http.Header) bool { return h.Get("X-App-Key") != "" }, Resolve: func(_ context.Context, h http.Header, _ RequestMeta, _ time.Duration) (*CredentialSession, error) {
			if h.Get("X-App-Key") != "issued" {
				return nil, errors.New("invalid fixture credential")
			}
			return &CredentialSession{Identity: SessionResult{User: User{ID: "service"}, Session: Session{UserID: "service"}}}, nil
		},
	}}}
	withKey, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, mixed := range []bool{false, true} {
		r := request(chunks...)
		if mixed {
			r.AddCookie(token)
		}
		r.Header.Set("X-App-Key", "issued")
		w := httptest.NewRecorder()
		withKey.ServeHTTP(w, r)
		if mixed && w.Code != 400 || !mixed && (w.Code != 200 || !strings.Contains(w.Body.String(), `"credentialType":"application"`) || strings.Contains(w.Body.String(), "Original")) {
			t.Fatal("cache overrode application credentials", w.Code)
		}
	}
}

func TestCompactSessionConfiguration(t *testing.T) {
	cache := &SessionCookieCacheOptions{}
	opts := Options{BaseURL: "https://cache.example.test", Store: &compactFixture{}, Secret: strings.Repeat("s", 32), SessionCookieCache: cache}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	cache.Version = "other"
	if a.opts.SessionCookieCache.Version != "1" || a.opts.SessionCookieCache.MaxAge != 5*time.Minute {
		t.Fatal("cache settings were changed outside the host")
	}
	for _, invalid := range []time.Duration{-time.Second, 500 * time.Millisecond} {
		cache.MaxAge = invalid
		if _, err := New(opts); err == nil {
			t.Fatal("invalid cookie cache max age accepted")
		}
	}
}

func testSessionCache(t *testing.T, a *Auth, data SessionResult, persistent bool) []*http.Cookie {
	t.Helper()
	cookies, err := a.prepareSessionCache(t.Context(), data, persistent)
	if err != nil {
		t.Fatal(err)
	}
	return cookies
}
