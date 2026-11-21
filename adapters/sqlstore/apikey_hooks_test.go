package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	ak "github.com/Stonewrit/stonewrit-auth/plugins/apikey"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestAPIKeyGenerationAndExtraction(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			wantCode := func(e error, code string) {
				t.Helper()
				var api *stonewrit.APIError
				if !errors.As(e, &api) || api.Code != code {
					t.Fatalf("expected %s, got %v", code, e)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"api-key", "organization"})
			must(e)
			dsn := organizationTestDSN(t, dialect)
			db, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer db.Close()
			peer, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer peer.Close()
			const root = "https://keyhooks.example"
			const custom = "X-Client-Credential"
			boom := &stonewrit.APIError{Status: 418, Code: "PRIVATE_DETAIL", Message: "private hook text"}
			var sequence atomic.Int64
			var extractions atomic.Int64
			var called ak.Generation
			generator := func(_ context.Context, g ak.Generation) (string, error) {
				called = g
				return fmt.Sprintf("application-%048d", sequence.Add(1)), nil
			}
			getter := func(r *http.Request) (string, bool, error) {
				extractions.Add(1)
				if r.Method != "" && r.URL.Path == "" {
					t.Fatal("missing request path")
				}
				values := r.Header.Values(custom)
				if len(values) == 0 {
					return "", false, nil
				}
				if len(values) != 1 {
					return "", true, nil
				}
				if values[0] == "error" {
					return "", false, boom
				}
				return values[0], true, nil
			}
			options := ak.Options{Store: db, ConfigID: "default", KeyLength: 32, DefaultPrefix: "app_", GenerateKey: generator, ExtractKey: getter, EnableSession: true, DisableRateLimit: true}
			users, e := ak.New(options)
			must(e)
			orgOpts := options
			orgOpts.ConfigID = "teams"
			orgOpts.Organization = &ak.OrganizationOptions{}
			orgOpts.ExtractKey = nil
			orgOpts.Headers = []string{"X-Team-Key"}
			teams, e := ak.New(orgOpts)
			must(e)
			kp, e := ak.NewPlugin(users, teams)
			must(e)
			op, e := org.New(org.Options{Store: db})
			must(e)
			host, e := stonewrit.New(stonewrit.Options{Store: db, BaseURL: root, Secret: strings.Repeat("h", 40), EmailAndPassword: true, RateLimit: new(bool), Plugins: []stonewrit.Plugin{kp, op}})
			must(e)
			signup := func(email string) (*client.Client, *client.EmailResult) {
				c, e := client.New(root, &http.Client{Transport: guestTransport{host}})
				must(e)
				u, e := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: email, Password: "a secure test password"})
				must(e)
				return c, u
			}
			browser, user := signup("owner@example.test")
			foreign, other := signup("other@example.test")
			key, e := browser.CreateAPIKey(ctx, client.CreateAPIKeyRequest{})
			must(e)
			if called != (ak.Generation{UserID: user.User.ID, ConfigID: "default", Length: 32, Prefix: "app_"}) || !strings.HasPrefix(key.Secret, "application-") || *key.Start != key.Secret[:6] || *key.Prefix != "app_" {
				t.Fatal("incorrect personal generation inputs or display fields")
			}
			var group org.Organization
			must(browser.Do(ctx, "POST", "/organization/create", map[string]any{"name": "Creators", "slug": "creators"}, &group))
			before := sequence.Load()
			_, e = foreign.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID})
			if e == nil || sequence.Load() != before {
				t.Fatal("foreign member reached the organization generator")
			}
			orgKey, e := browser.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID, Prefix: "org_"})
			must(e)
			if called.UserID != user.User.ID || called.OrganizationID != group.ID || called.ConfigID != "teams" || called.Prefix != "org_" || orgKey.ReferenceID != group.ID {
				t.Fatal("incorrect organization generation context")
			}
			var digest string
			must(db.db.QueryRowContext(ctx, db.bind(`SELECT "key" FROM "apikey" WHERE "id"=?`), key.ID).Scan(&digest))
			if digest != ak.Digest(key.Secret) {
				t.Fatal("custom secret did not use the standard digest")
			}
			// Explicit native verification consumes the supplied value without invoking an extractor.
			before = extractions.Load()
			result, e := users.Verify(ctx, key.Secret, nil)
			must(e)
			if !result.Valid || extractions.Load() != before {
				t.Fatal("explicit verification invoked a request hook")
			}
			call := func(headers http.Header, withCookie bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", root+"/api/auth/get-session", nil)
				for name, values := range headers {
					r.Header[name] = values
				}
				if withCookie {
					r.AddCookie(host.SessionCookie(*user.Token, true))
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w
			}
			h := http.Header{}
			h.Set(custom, key.Secret)
			before = extractions.Load()
			if w := call(h, false); w.Code != 200 || !strings.Contains(w.Body.String(), user.User.ID) || extractions.Load() != before+1 {
				t.Fatal("HTTP credential was not resolved once", w.Code)
			}
			session, e := host.GetSession(ctx, h)
			must(e)
			if session == nil || session.User.ID != user.User.ID {
				t.Fatal("native header credential")
			}
			if w := call(h, true); w.Code != 400 {
				t.Fatal("browser credential was allowed alongside custom key", w.Code)
			}
			if w := call(http.Header{"X-Team-Key": {orgKey.Secret}, custom: {key.Secret}}, false); w.Code != 401 {
				t.Fatal("ambiguous extraction sources accepted", w.Code)
			}
			before = extractions.Load()
			if w := call(http.Header{"X-Api-Key": {key.Secret}}, false); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "null" || extractions.Load() != before+1 {
				t.Fatal("custom extraction fell back to configured headers or ran twice")
			}
			for _, present := range []string{"", "invalid", "error"} {
				h := http.Header{}
				h.Set(custom, present)
				w := call(h, true)
				if w.Code < 400 || strings.Contains(w.Body.String(), "private hook text") || strings.Contains(w.Body.String(), user.User.ID) {
					t.Fatal("rejected credential fell back or exposed hook errors", w.Code)
				}
			}
			r := httptest.NewRequest("GET", root+"/app", nil)
			r.Header.Set(custom, key.Secret)
			w := httptest.NewRecorder()
			users.Middleware(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				k, ok := ak.FromContext(r.Context())
				if !ok || k.ID != key.ID {
					t.Fatal("application key missing")
				}
				w.WriteHeader(204)
			})).ServeHTTP(w, r)
			if w.Code != 204 {
				t.Fatal("custom credential middleware", w.Code)
			}
			r.Header.Set(custom, "error")
			_, e = users.VerifyRequest(r, nil)
			if !errors.Is(e, boom) {
				t.Fatal("lost native extraction error")
			}
			orgCheck, e := teams.Verify(ctx, orgKey.Secret, nil)
			must(e)
			if !orgCheck.Valid {
				t.Fatal("organization credential did not verify")
			}
			_, e = host.GetSession(ctx, http.Header{"X-Team-Key": {orgKey.Secret}})
			wantCode(e, "INVALID_REFERENCE_ID_FROM_API_KEY")
			// Distinct store connections and owners compete for one generated digest.
			dup := strings.Repeat("D", 40)
			options.GenerateKey = func(context.Context, ak.Generation) (string, error) { return dup, nil }
			options.Store = db
			first, e := ak.New(options)
			must(e)
			options.Store = peer
			second, e := ak.New(options)
			must(e)
			type answer struct {
				id  string
				key *ak.Created
				err error
			}
			out := make(chan answer, 2)
			for service, id := range map[*ak.Service]string{first: user.User.ID, second: other.User.ID} {
				go func() { k, e := service.Create(ctx, id, ak.CreateInput{}); out <- answer{id, k, e} }()
			}
			a, b := <-out, <-out
			if a.err != nil {
				a, b = b, a
			}
			must(a.err)
			wantCode(b.err, "API_KEY_ALREADY_ISSUED")
			must(first.Delete(ctx, a.id, a.key.ID))
			_, e = second.Create(ctx, b.id, ak.CreateInput{})
			wantCode(e, "API_KEY_ALREADY_ISSUED")
			// Pre-upgrade keys have no reservation but must also block reissuance.
			_, e = db.db.ExecContext(ctx, db.bind(`DELETE FROM "stonewrit_api_key_digest" WHERE "digest"=?`), apiKeyFingerprint(ak.Digest(key.Secret)))
			must(e)
			options.GenerateKey = func(context.Context, ak.Generation) (string, error) { return key.Secret, nil }
			legacy, e := ak.New(options)
			must(e)
			_, e = legacy.Create(ctx, other.User.ID, ak.CreateInput{})
			wantCode(e, "API_KEY_ALREADY_ISSUED")
			for _, bad := range []string{"", strings.Repeat("x", 31), strings.Repeat("q", 4100), strings.Repeat("k", 32) + "\n"} {
				options.GenerateKey = func(context.Context, ak.Generation) (string, error) { return bad, nil }
				fail, e := ak.New(options)
				must(e)
				if got, e := fail.Create(ctx, user.User.ID, ak.CreateInput{}); e == nil || got != nil {
					t.Fatal("invalid generated credential persisted")
				}
			}
			options.GenerateKey = func(context.Context, ak.Generation) (string, error) { return "", boom }
			fail, e := ak.New(options)
			must(e)
			if _, e = fail.Create(ctx, user.User.ID, ak.CreateInput{}); !errors.Is(e, boom) || strings.Contains(e.Error(), boom.Message) {
				t.Fatal("generator errors must be identifiable without exposing their contents")
			}
			cancelCtx, cancel := context.WithCancel(ctx)
			options.GenerateKey = func(context.Context, ak.Generation) (string, error) { cancel(); return strings.Repeat("C", 40), nil }
			canceled, e := ak.New(options)
			must(e)
			if _, e = canceled.Create(cancelCtx, user.User.ID, ak.CreateInput{}); !errors.Is(e, context.Canceled) {
				t.Fatal("cancelled generator issued a key", e)
			}
			// Final persistence uses current membership, even when it changes inside
			// a slow generator after the preliminary authorization transaction.
			_, e = db.db.ExecContext(ctx, db.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), "issuer-member", group.ID, other.User.ID, "issuer", db.date(time.Now()))
			must(e)
			orgOpts.Organization = &ak.OrganizationOptions{Roles: ak.Permissions{"issuer": {ak.CreateAction}}}
			orgOpts.GenerateKey = func(hookCtx context.Context, g ak.Generation) (string, error) {
				_, err := peer.db.ExecContext(hookCtx, peer.bind(`UPDATE "member" SET "role"=? WHERE "id"=?`), "member", "issuer-member")
				return strings.Repeat("R", 40), err
			}
			rotating, e := ak.New(orgOpts)
			must(e)
			issued, e := rotating.Create(ctx, other.User.ID, ak.CreateInput{OrganizationID: group.ID})
			if e == nil || issued != nil {
				t.Fatal("revoked organization issuer persisted a generated key")
			}
			result, e = rotating.Verify(ctx, strings.Repeat("R", 40), nil)
			must(e)
			if result.Valid {
				t.Fatal("failed organization issuance left a usable secret")
			}
			extractCtx, stop := context.WithCancel(ctx)
			options.ExtractKey = func(r *http.Request) (string, bool, error) { stop(); return key.Secret, true, nil }
			interrupt, e := ak.New(options)
			must(e)
			if _, e = interrupt.VerifyRequest(httptest.NewRequestWithContext(extractCtx, "GET", root+"/app", nil), nil); !errors.Is(e, context.Canceled) {
				t.Fatal("lost extractor cancellation", e)
			}

		})
	}
}
