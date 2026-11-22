package plainauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionCacheVersionCallbackBoundaries(t *testing.T) {
	cleanConfigEnv(t)
	for _, strategy := range []SessionCookieCacheStrategy{SessionCacheCompact, SessionCacheJWT, SessionCacheJWE} {
		t.Run(string(strategy), func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			avatar := "https://example.test/image"
			row := Session{ID: "session", Token: "local-token", UserID: "owner", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour)}
			user := User{ID: row.UserID, Name: "Profile", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now, Image: &avatar}
			store := &compactFixture{refreshFixture: refreshFixture{row: StoredSession{Session: row}}, owner: user}
			type modeKey struct{}
			entered := make(chan struct{})
			expected := "epoch"
			calls := 0
			version := func(ctx context.Context, s Session, u User) (string, error) {
				if s.Token != row.Token || s.UserID != u.ID || u.Email != user.Email {
					t.Errorf("version received unbound identity")
				}
				*u.Image = "private callback copy"
				switch ctx.Value(modeKey{}) {
				case "wait":
					close(entered)
					<-ctx.Done()
					return "", ctx.Err()
				case "panic":
					panic("private callback panic")
				case "public":
					return "", &APIError{409, "REVISION_UNAVAILABLE", "Revision unavailable"}
				}
				calls++
				return expected, nil
			}
			opts := Options{BaseURL: "https://auth.example.test", Store: store, Secret: strings.Repeat("s", 32),
				SessionCookieCache: &SessionCookieCacheOptions{Strategy: strategy, Version: "static", VersionFor: version}}
			if _, err := New(opts); err == nil {
				t.Fatal("accepted competing fixed and callback versions")
			}
			opts.SessionCookieCache.Version = ""
			a, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			out := testSessionCache(t, a, SessionResult{Session: row, User: user}, true)
			token := a.SessionCookie(row.Token, true)
			read := func(ctx context.Context, query string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequestWithContext(ctx, "GET", opts.BaseURL+"/api/auth/get-session"+query, nil)
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			if len(out) != 1 {
				t.Fatal("missing snapshot")
			}
			cached := out[0]
			get := func(ctx context.Context) *httptest.ResponseRecorder { return read(ctx, "", token, cached) }
			if w := get(t.Context()); w.Code != 200 || !strings.Contains(w.Body.String(), avatar) ||
				strings.Contains(w.Body.String(), "private callback copy") || store.queries != 0 || calls != 2 {
				t.Fatal("version resolution altered snapshot fields or consumed a store lookup", w.Body.String(), calls, store.queries)
			}
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), modeKey{}, "wait"))
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- get(ctx) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("callback did not start")
			}
			if w := get(t.Context()); w.Code != 200 {
				t.Fatal("one pending revision blocked another request")
			}
			cancel()
			select {
			case w := <-done:
				if w.Code != 500 || !strings.Contains(w.Body.String(), "FAILED_TO_GET_SESSION") || len(w.Result().Cookies()) != 0 {
					t.Fatal("canceled lookup disclosed or refreshed a session", w.Code, w.Body.String())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("VersionFor did not receive request cancellation")
			}
			w := get(context.WithValue(t.Context(), modeKey{}, "panic"))
			if w.Code != 500 || strings.Contains(w.Body.String(), "private callback panic") {
				t.Fatal("private panic escaped", w.Body.String())
			}
			w = get(context.WithValue(t.Context(), modeKey{}, "public"))
			if w.Code != 409 || !strings.Contains(w.Body.String(), "REVISION_UNAVAILABLE") {
				t.Fatal("public callback error lost", w.Body.String())
			}

			// A forced live read without cookie issuance never needs the version function.
			for _, cs := range [][]*http.Cookie{
				{cached}, {a.SessionCookie("foreign-token", true), cached}, {token, token, cached}, {token, {Name: cached.Name, Value: "invalid"}},
			} {
				w := read(context.WithValue(t.Context(), modeKey{}, "panic"), "?disableRefresh=true", cs...)
				if w.Code != 200 {
					t.Fatalf("unbound cookie invoked VersionFor: %d", w.Code)
				}
			}
			expected = "revised"
			store.deleted = true
			if w := get(t.Context()); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "null" {
				t.Fatal("a changed version served a removed session", w.Code, w.Body.String())
			}
		})
	}
}

func TestSessionCacheVersionErrorReporting(t *testing.T) {
	private := errors.New("private version source failure")
	if !errors.Is(sessionVersionReadError(private), private) || !errors.Is(sessionVersionIssueError(private), private) {
		t.Fatal("host error reporters lost the callback cause")
	}
}

type storedSignupFixture struct {
	compactFixture
	guardProfile bool
}

func (s *storedSignupFixture) Credential(context.Context, string) (User, string, error) {
	return User{}, "", ErrNotFound
}

func (s *storedSignupFixture) CreateUser(_ context.Context, u User, _ string, initial *StoredSession) error {
	s.owner, s.row = u, *initial
	s.owner.Name = "Stored"
	if s.guardProfile {
		s.owner.AdminUserFields = &AdminUserFields{Role: "locked"}
	}
	return nil
}

func TestSessionVersionRechecksStoredSignup(t *testing.T) {
	cleanConfigEnv(t)
	for _, guarded := range []bool{false, true} {
		store := &storedSignupFixture{guardProfile: guarded}
		calls := 0
		a, err := New(Options{BaseURL: "https://auth.example.test", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true,
			SessionCookieCache: &SessionCookieCacheOptions{VersionFor: func(ctx context.Context, s Session, u User) (string, error) {
				calls++
				return u.ID, nil
			}}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://auth.example.test/api/auth/sign-up/email", strings.NewReader(`{"email":"user@example.test","name":"Submitted","password":"local-test-password"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 || calls != 1 || store.queries != 1 {
			t.Fatalf("registration, version lookups, stored reads: %d, %d, %d; %s", w.Code, calls, store.queries, w.Body)
		}
		read := httptest.NewRequest("GET", "https://auth.example.test/api/auth/get-session", nil)
		dataIssued := false
		for _, c := range w.Result().Cookies() {
			read.AddCookie(c)
			if c.Name == a.prefixedCookieName("session_data") && c.MaxAge >= 0 {
				dataIssued = true
			}
		}
		if guarded && dataIssued {
			t.Fatal("registration published a snapshot after the stored profile became protected")
		}
		if !guarded {
			if dataIssued {
				t.Fatal("applied a pre-commit version to a changed profile")
			}
			issued := httptest.NewRecorder()
			a.ServeHTTP(issued, read)
			if issued.Code != 200 || !strings.Contains(issued.Body.String(), "Stored") || calls != 2 {
				t.Fatal("live read did not recompute from the stored profile", issued.Code, calls)
			}
			for _, c := range issued.Result().Cookies() {
				read.AddCookie(c)
			}
			got, err := a.cachedSessionView(read, store.row.Token)
			if err != nil || got == nil || got.User.Name != "Stored" {
				t.Fatal("cache did not use the stored public profile", err)
			}
		}
	}
}
