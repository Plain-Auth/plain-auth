package sqlstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestInteractiveBrowserConsent(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			store, peer := open(), open()
			write := func(query string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(query), args...)
				must(err)
			}
			const base = "https://auth.example.test"
			const redirect = "https://reports.example.test/return"
			var failHash, collide bool
			config := op.Options{Scopes: []string{"read", "export"}, Authorization: op.BrowserAuthorizationOptions{
				ConsentPage: "/approve?theme=dark", ConsentReference: func(_ context.Context, a op.RegistrationAccess, _ []string) (string, error) {
					return a.Headers.Get("X-Test-Tenant"), nil
				},
			}, Tokens: op.TokenOptions{HashAuthorizationCode: func(_ context.Context, raw string) (string, error) {
				if failHash {
					return "", errors.New("local callback failure")
				}
				if collide {
					return "reserved-code-digest", nil
				}
				sum := sha256.Sum256([]byte(raw))
				return base64.RawURLEncoding.EncodeToString(sum[:]), nil
			}}}
			host := func(s *Store) *auth.Auth {
				p, err := op.New(config)
				must(err)
				off := false
				a, err := auth.New(auth.Options{Store: s, Plugins: []auth.Plugin{p}, BaseURL: base, Secret: strings.Repeat("s", 40), RateLimit: &off})
				must(err)
				return a
			}
			a, b := host(store), host(peer)
			now := time.Now().UTC().Truncate(time.Second)
			for _, owner := range []string{"owner", "other"} {
				write(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, owner, owner, owner+"@example.test", true, store.date(now), store.date(now))
				write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`, owner, owner, owner, store.date(now), store.date(now), store.date(now.Add(time.Hour)))
			}
			write(`INSERT INTO "oauthClient" ("id","clientId","redirectUris","applicationType","tokenEndpointAuthMethod","scopes") VALUES ('app','app',?,'web','none',?)`, `["https://reports.example.test/return"]`, `["read","export"]`)
			prompt := func(tenant string) string {
				t.Helper()
				q := url.Values{"response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {redirect}, "scope": {"read export"}, "code_challenge_method": {"S256"}, "code_challenge": {"challenge"}, "prompt": {"consent"}}
				r := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				r.AddCookie(a.SessionCookie("owner", true))
				r.Header.Set("X-Test-Tenant", tenant)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				u, err := url.Parse(w.Header().Get("Location"))
				must(err)
				if w.Code != 302 || u.Host != "auth.example.test" || u.Path != "/approve" || u.Query().Get("theme") != "dark" {
					t.Fatalf("unexpected consent page: HTTP %d path %q", w.Code, u.Path)
				}
				fields, err := a.VerifyOAuthPageQuery(u.RawQuery)
				must(err)
				if fields.Has("theme") || fields.Get("scope") != "read export" {
					t.Fatal("unverified page field entered signed form")
				}
				return fields.Encode()
			}
			post := func(h *auth.Auth, signed, owner, tenant string, accept bool, scope string) *httptest.ResponseRecorder {
				body := map[string]any{"accept": accept, "oauth_query": signed, "scope": scope}
				encoded, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", base+"/api/auth/oauth2/consent", bytes.NewReader(encoded))
				r.Header.Set("Origin", base)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Test-Tenant", tenant)
				if owner != "" {
					r.AddCookie(h.SessionCookie(owner, true))
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			count := func(query string) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(query)).Scan(&n))
				return n
			}
			sign := prompt("A")
			if w := post(b, sign, "", "A", true, "read"); w.Code != 401 {
				t.Fatalf("anonymous approval returned %d", w.Code)
			}
			for _, v := range []struct{ user, tenant string }{{"other", "A"}, {"owner", "B"}} {
				if w := post(b, sign, v.user, v.tenant, true, "read"); w.Code != 400 {
					t.Fatalf("mismatched prompt binding returned %d", w.Code)
				}
			}
			if w := post(b, sign, "owner", "A", false, "read"); w.Code != 200 || !strings.Contains(w.Body.String(), "access_denied") {
				t.Fatal("denial did not reach the application")
			}
			if w := post(a, sign, "owner", "A", true, "read"); w.Code != 400 || count(`SELECT COUNT(*) FROM "oauthConsent"`) != 0 {
				t.Fatal("denied request could be used to approve access")
			}
			expired := prompt("A")
			write(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`, store.date(now.Add(-time.Minute)), browserConsentKey)
			if w := post(b, expired, "owner", "A", true, "read"); w.Code != 400 {
				t.Fatal("expired consent was accepted")
			}
			sign = prompt("A")
			failHash = true
			if w := post(a, sign, "owner", "A", true, "read"); w.Code != 500 || count(`SELECT COUNT(*) FROM "oauthConsent"`) != 0 {
				t.Fatal("failed code callback committed approval")
			}
			failHash = false
			write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES ('reserved-code-row','reserved-code-digest','reserved',?,?,?)`, store.date(now), store.date(now), store.date(now.Add(time.Hour)))
			collide = true
			if w := post(b, sign, "owner", "A", true, "read"); w.Code != 500 || count(`SELECT COUNT(*) FROM "oauthConsent"`) != 0 {
				t.Fatal("code insertion conflict committed consent or consumed the request")
			}
			collide = false
			results := make(chan int, 2)
			for _, h := range []*auth.Auth{a, b} {
				go func() { results <- post(h, sign, "owner", "A", true, "read").Code }()
			}
			status := []int{<-results, <-results}
			slices.Sort(status)
			if !slices.Equal(status, []int{200, 400}) {
				t.Fatal("concurrent approval outcomes", status)
			}
			sign = prompt("A")
			if w := post(b, sign, "owner", "A", true, "export"); w.Code != 200 {
				t.Fatalf("updating scoped approval returned %d", w.Code)
			}
			var id string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "oauthConsent" WHERE "referenceId"='A'`)).Scan(&id))
			consent, err := store.OAuthConsent(ctx, "owner", id)
			must(err)
			if !slices.Equal(consent.Scopes, []string{"export"}) || count(`SELECT COUNT(*) FROM "oauthConsent"`) != 1 {
				t.Fatal("approval did not replace the existing scoped consent")
			}
			sign = prompt("B")
			if w := post(b, sign, "owner", "B", true, "read"); w.Code != 200 || count(`SELECT COUNT(*) FROM "oauthConsent"`) != 2 {
				t.Fatal("tenant approvals were not isolated")
			}
			jar, err := cookiejar.New(nil)
			must(err)
			origin, err := url.Parse(base)
			must(err)
			jar.SetCookies(origin, []*http.Cookie{a.SessionCookie("owner", true)})
			sdk, err := client.New(base, &http.Client{Jar: jar, Transport: guestTransport{b}})
			must(err)
			for _, selection := range [][]string{{}, nil} {
				dest, err := sdk.DecideOAuthConsent(ctx, prompt(""), true, selection)
				must(err)
				u, err := url.Parse(dest)
				must(err)
				if u.Query().Get("code") == "" {
					t.Fatal("SDK failed to deliver consent code")
				}
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "oauthConsent" WHERE "referenceId" IS NULL`)).Scan(&id))
				personal, err := store.OAuthConsent(ctx, "owner", id)
				must(err)
				want := selection
				if want == nil {
					want = []string{"read", "export"}
				}
				if !slices.Equal(personal.Scopes, want) {
					t.Fatal("SDK lost distinction between omitted and explicit empty scopes")
				}
			}
			sign = prompt("A")
			write(`UPDATE "oauthClient" SET "redirectUris"=? WHERE "id"='app'`, `["https://different.example.test/return"]`)
			w := post(b, sign, "owner", "A", false, "read")
			var answer struct{ URL string }
			must(json.Unmarshal(w.Body.Bytes(), &answer))
			u, err := url.Parse(answer.URL)
			must(err)
			if w.Code != http.StatusOK || u.Host != "auth.example.test" || u.Path != "/api/auth/error" || u.Query().Get("error") != "access_denied" {
				t.Fatal("denial used a removed callback")
			}
			write(`UPDATE "oauthClient" SET "redirectUris"=? WHERE "id"='app'`, `["https://reports.example.test/return"]`)
			if post(a, sign, "owner", "A", true, "read").Code != 400 {
				t.Fatal("restoring a callback revived an explicitly denied request")
			}
		})
	}
}
