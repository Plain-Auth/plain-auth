package plainauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type refreshFixture struct {
	Store
	row             StoredSession
	deleted         bool
	refreshes       int
	revokeOnRefresh bool
}

func (f *refreshFixture) Session(_ context.Context, token string) (StoredSession, User, error) {
	if f.deleted || token != f.row.Token {
		return StoredSession{}, User{}, ErrNotFound
	}
	return f.row, User{ID: f.row.UserID}, nil
}
func (f *refreshFixture) RefreshSession(_ context.Context, token string, previous, now, next time.Time) (bool, error) {
	if f.revokeOnRefresh {
		f.deleted = true
	}
	if f.deleted || token != f.row.Token || !f.row.ExpiresAt.Equal(previous) || !f.row.ExpiresAt.After(now) {
		return false, nil
	}
	f.refreshes++
	f.row.UpdatedAt = now
	f.row.ExpiresAt = next
	return true, nil
}
func (f *refreshFixture) DeleteExpiredSession(_ context.Context, token string, now time.Time) error {
	if token == f.row.Token && !f.row.ExpiresAt.After(now) {
		f.deleted = true
	}
	return nil
}

func TestSessionRefreshWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{"sliding", "deferred", "disabled", "dont-remember", "concurrent-revoke", "expiry"} {
		t.Run(name, func(t *testing.T) {
			now := start
			const ttl = 7 * 24 * time.Hour
			initialExpiry := start.Add(ttl)
			store := &refreshFixture{row: StoredSession{Session: Session{ID: "s", UserID: "u", Token: "test-token", CreatedAt: start, UpdatedAt: start, ExpiresAt: initialExpiry}}}
			auth, err := New(Options{Store: store, BaseURL: "http://auth.test", Secret: strings.Repeat("s", 32), DeferSessionRefresh: name == "deferred", DisableSessionRefresh: name == "disabled"})
			if err != nil {
				t.Fatal(err)
			}
			auth.now = func() time.Time { return now }
			sessionCookie := auth.SessionCookie(store.row.Token, true)
			request := func(method, query string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, "http://auth.test/api/auth/get-session"+query, nil)
				r.Header.Set("Origin", "http://auth.test")
				r.AddCookie(sessionCookie)
				if name == "dont-remember" {
					marker := auth.sessionCookie("true", false)
					marker.Name = "authn.dont_remember"
					r.AddCookie(marker)
				}
				w := httptest.NewRecorder()
				auth.ServeHTTP(w, r)
				return w
			}
			now = start.Add(24*time.Hour - time.Millisecond)
			r := request("GET", "")
			if r.Code != 200 || store.refreshes != 0 {
				t.Fatal("premature refresh")
			}
			now = start.Add(24 * time.Hour)
			h := http.Header{"Cookie": {sessionCookie.Name + "=" + sessionCookie.Value}}
			if _, err = auth.GetSession(t.Context(), h); err != nil || store.refreshes != 0 {
				t.Fatal("native read changed session")
			}
			switch name {
			case "deferred":
				r = request("GET", "")
				var deferred struct{ NeedsRefresh bool }
				if err := json.Unmarshal(r.Body.Bytes(), &deferred); err != nil || !deferred.NeedsRefresh || store.refreshes != 0 {
					t.Fatalf("GET failed to defer: %s", r.Body)
				}
				r = request("POST", "")
			case "disabled", "dont-remember":
				r = request("GET", "")
				if r.Code != 200 || store.refreshes != 0 || len(r.Result().Cookies()) != 0 {
					t.Fatal("disabled session was renewed")
				}
				return
			case "concurrent-revoke":
				store.revokeOnRefresh = true
				r = request("GET", "")
				if r.Code != 401 || !store.deleted || store.refreshes != 0 || r.Result().Cookies()[0].MaxAge != -1 {
					t.Fatal("revocation did not win the race")
				}
				return
			case "expiry":
				now = initialExpiry
				r = request("GET", "")
				if r.Code != 200 || strings.TrimSpace(r.Body.String()) != "null" || !store.deleted {
					t.Fatalf("expired session not cleaned: %s", r.Body)
				}
				return
			default:
				r = request("GET", "?disableRefresh=true")
				if r.Code != 200 || store.refreshes != 0 {
					t.Fatal("disableRefresh was ignored")
				}
				r = request("GET", "")
			}
			if r.Code != 200 || store.refreshes != 1 || !store.row.ExpiresAt.Equal(now.Add(ttl)) || len(r.Result().Cookies()) != 1 {
				t.Fatalf("sliding window update failed: %s, %+v", r.Body, store.row)
			}
			request("GET", "")
			if store.refreshes != 1 {
				t.Fatal("refreshed twice within update age")
			}
		})
	}
}
