package sqlstore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/apikey"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestAPIKeySessionRetiresDisabledBrowserCache(t *testing.T) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ddl, err := schema.Generate("sqlite", []string{"api-key"})
	must(err)
	db, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
	must(err)
	t.Cleanup(func() { db.Close() })

	const source = "X-Application-Key"
	service, err := apikey.New(apikey.Options{Store: db, EnableSession: true, ExtractKey: func(r *http.Request) (string, bool, error) {
		key := r.Header.Get(source)
		return key, key != "", nil
	}})
	must(err)
	plugin, err := apikey.NewPlugin(service)
	must(err)
	const origin = "https://cache.example.test"
	host, err := auth.New(auth.Options{Store: db, BaseURL: origin, Secret: strings.Repeat("s", 32), CookiePrefix: "example", DeferSessionRefresh: true, Plugins: []auth.Plugin{plugin}})
	must(err)

	owner, visitor := testUser("key-owner"), testUser("browser-owner")
	visit := testSession(visitor, "visitor-session")
	visit.ExpiresAt = time.Now().Add(time.Hour)
	must(db.CreateUser(ctx, owner, "fixture", nil))
	must(db.CreateUser(ctx, visitor, "fixture", &visit))
	browser := host.SessionCookie(visit.Token, true)
	data := strings.TrimSuffix(browser.Name, "session_token") + "session_data"
	budget := int64(4)
	key, err := service.Create(ctx, owner.ID, apikey.CreateInput{Policy: apikey.Policy{Remaining: &budget}})
	must(err)
	revoked, err := service.Create(ctx, owner.ID, apikey.CreateInput{})
	must(err)
	must(service.Delete(ctx, owner.ID, revoked.ID))

	for _, method := range []string{"GET", "POST"} {
		for _, tc := range []struct {
			name, credential string
			mixed            bool
		}{
			{"accepted", key.Secret, false}, {"revoked", revoked.Secret, false}, {"mixed", key.Secret, true},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(method, origin+"/api/auth/get-session", nil)
				req.Header.Set("Origin", origin)
				req.Header.Set(source, tc.credential)
				for _, name := range []string{data, data + ".0", "unrelated.session_data"} {
					req.AddCookie(&http.Cookie{Name: name, Value: "old"})
				}
				if tc.mixed {
					req.AddCookie(browser)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, req)
				cookies := w.Result().Cookies()
				if tc.name != "accepted" {
					if w.Code < 400 || w.Code >= 500 || tc.mixed && w.Code != 400 || len(cookies) != 0 || strings.Contains(w.Body.String(), owner.ID) || strings.Contains(w.Body.String(), visitor.ID) {
						t.Fatalf("rejected credentials changed browser state or returned a principal (status %d)", w.Code)
					}
					return
				}
				var result auth.SessionResult
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || result.User.ID != owner.ID || result.Session.CredentialType != "application" {
					t.Fatalf("incorrect key identity (status %d)", w.Code)
				}
				expected := map[string]bool{data: true, data + ".0": true}
				for _, c := range cookies {
					if !expected[c.Name] || c.MaxAge >= 0 || c.Value != "" {
						t.Fatalf("unexpected cookie operation for %s", c.Name)
					}
					delete(expected, c.Name)
				}
				if len(expected) != 0 {
					t.Fatal("obsolete browser cache retained", expected)
				}
			})
		}
	}
	stored, err := service.Get(ctx, owner.ID, key.ID)
	must(err)
	if stored.Remaining == nil || *stored.Remaining != 2 {
		t.Fatal("a conflicting credential consumed the application's usage budget")
	}
}
