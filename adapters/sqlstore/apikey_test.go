package sqlstore

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestAPIKeyLifecycleAndPolicy(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			expect := func(err error, code string) {
				t.Helper()
				var e *plainauth.APIError
				if !errors.As(err, &e) || e.Code != code {
					t.Fatalf("expected %s got %v", code, err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key", "admin"})
			must(err)
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			peer, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer peer.Close()
			opts := ak.Options{Store: store, EnableMetadata: true, MinExpiration: time.Second, DefaultPermissions: ak.Permissions{"reports": {"read"}}}
			keys, err := ak.New(opts)
			must(err)
			opts.Store = peer
			other, err := ak.New(opts)
			must(err)
			const origin = "https://keys.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{keys.Plugin()}})
			must(err)
			browser := func() *client.Client {
				c, e := client.New(origin, &http.Client{Transport: guestTransport{host}})
				must(e)
				return c
			}
			member, outsider := browser(), browser()
			owner, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@example.test", Password: "example password"})
			must(err)
			foreign, err := outsider.SignUpEmail(ctx, client.SignUpRequest{Name: "Other", Email: "other@example.test", Password: "example password"})
			must(err)
			made, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "client", Prefix: "app_", Metadata: map[string]any{"env": "local"}})
			must(err)
			if made.ID == "" || len(made.Secret) != 68 || !strings.HasPrefix(made.Secret, "app_") || made.Start == nil || *made.Start != made.Secret[:6] || made.ReferenceID != owner.User.ID {
				t.Fatal("issued credential did not match the owner or display prefix")
			}
			var persisted string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "key" FROM "apikey" WHERE "id"=?`), made.ID).Scan(&persisted))
			if persisted != ak.Digest(made.Secret) || persisted == made.Secret {
				t.Fatal("stored value is not the secret digest")
			}
			verify := func(key string, required ak.Permissions, valid bool, code string) {
				t.Helper()
				r, e := keys.Verify(ctx, key, required)
				must(e)
				if r.Valid != valid || (valid && r.Key == nil) || (!valid && (r.Key != nil || r.Error == nil || r.Error.Code != code)) {
					t.Fatalf("wrong verification result: valid=%v err=%v", r.Valid, r.Error)
				}
			}
			verify(made.Secret, ak.Permissions{"reports": {"write"}}, false, "KEY_NOT_FOUND")
			verify(made.Secret, ak.Permissions{"reports": {"read"}}, true, "")
			got, err := member.GetAPIKey(ctx, made.ID, "")
			must(err)
			if got.RequestCount != 1 || got.Metadata["env"] != "local" {
				t.Fatal("denied permission consumed a use or lost metadata")
			}
			_, err = outsider.GetAPIKey(ctx, made.ID, "")
			expect(err, "KEY_NOT_FOUND")
			name := "renamed"
			_, err = outsider.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: made.ID, Name: &name})
			expect(err, "KEY_NOT_FOUND")
			expect(outsider.DeleteAPIKey(ctx, made.ID, ""), "KEY_NOT_FOUND")
			disabled := false
			changed, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: made.ID, Enabled: &disabled, Name: &name})
			must(err)
			if changed.Enabled || *changed.Name != "renamed" {
				t.Fatal("owner update was not saved")
			}
			verify(made.Secret, nil, false, "KEY_DISABLED")
			page, err := outsider.ListAPIKeys(ctx, "", ak.PageOptions{})
			must(err)
			if page.Total != 0 || len(page.Keys) != 0 {
				t.Fatal("list exposed a different owner's keys")
			}
			delegated := testSession(owner.User, "delegated-application-key")
			delegated.ImpersonatedBy = &foreign.User.ID
			must(store.CreateSession(ctx, delegated))
			borrowed := httptest.NewRequest("POST", origin+"/api/auth/api-key/create", strings.NewReader(`{"name":"delegated"}`))
			borrowed.Header.Set("Content-Type", "application/json")
			borrowed.Header.Set("Origin", origin)
			borrowed.AddCookie(host.SessionCookie(delegated.Token, true))
			rec := httptest.NewRecorder()
			host.ServeHTTP(rec, borrowed)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "OWNER_SESSION_REQUIRED") {
				t.Fatal("delegated session issued an application key")
			}
			revoked := testSession(owner.User, "revoked-application-key")
			must(store.CreateSession(ctx, revoked))
			must(store.DeleteSession(ctx, revoked.Token))
			denied := store.CreateAPIKey(ctx, ak.Owner{UserID: owner.User.ID, SessionToken: revoked.Token}, made.Key, ak.Digest("unused"))
			if !errors.Is(denied, ak.ErrSession) {
				t.Fatalf("revoked session reached key persistence: %v", denied)
			}
			_, err = keys.Update(ctx, owner.User.ID, made.ID, ak.UpdateInput{})
			expect(err, "NO_VALUES_TO_UPDATE")
			var raw map[string]any
			must(member.Do(ctx, "GET", "/api-key/get?id="+made.ID, nil, &raw))
			if _, ok := raw["key"]; ok {
				t.Fatal("management response contained the stored digest or secret")
			}
			expect(member.Do(ctx, "POST", "/api-key/create", map[string]any{"userId": foreign.User.ID}, nil), "UNAUTHORIZED_SESSION")
			expect(member.Do(ctx, "POST", "/api-key/create", map[string]any{"permissions": map[string][]string{"admin": {"all"}}}, nil), "SERVER_ONLY_PROPERTY")
			expect(member.Do(ctx, "POST", "/api-key/update", map[string]any{"keyId": made.ID, "remaining": 300}, nil), "SERVER_ONLY_PROPERTY")
			for _, endpoint := range []string{"/api-key/verify", "/api-key/delete-all-expired-api-keys"} {
				err := member.Do(ctx, "POST", endpoint, map[string]any{}, nil)
				var api *plainauth.APIError
				if !errors.As(err, &api) || api.Status != http.StatusNotFound {
					t.Fatalf("server-only API exposed over HTTP: %s %v", endpoint, err)
				}
			}
			must(member.DeleteAPIKey(ctx, made.ID, ""))
			verify(made.Secret, nil, false, "INVALID_API_KEY")
			// Independent Go services use separate database connections.
			usage := int64(3)
			max := int64(2)
			noRate := false
			race := func(in ak.CreateInput, want int, deny string) {
				t.Helper()
				k, e := keys.Create(ctx, owner.User.ID, in)
				must(e)
				var accepted atomic.Int32
				var wg sync.WaitGroup
				for i := range 12 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						svc := keys
						if i%2 == 1 {
							svc = other
						}
						r, e := svc.Verify(ctx, k.Secret, nil)
						if e != nil {
							t.Error(e)
							return
						}
						if r.Valid {
							accepted.Add(1)
						} else if r.Error == nil || r.Error.Code != deny && !(deny == "USAGE_EXCEEDED" && r.Error.Code == "INVALID_API_KEY") {
							t.Errorf("unexpected verification %v", r.Error)
						}
					}()
				}
				wg.Wait()
				if int(accepted.Load()) != want {
					t.Fatalf("concurrent key quota granted %d, want %d", accepted.Load(), want)
				}
			}
			race(ak.CreateInput{Policy: ak.Policy{Remaining: &usage, RateLimitEnabled: &noRate}}, 3, "USAGE_EXCEEDED")
			race(ak.CreateInput{Policy: ak.Policy{RateLimitMax: &max}}, 2, "RATE_LIMIT_EXCEEDED")
			lifetime := time.Minute
			expires, e := keys.Create(ctx, owner.User.ID, ak.CreateInput{ExpiresIn: lifetime})
			must(e)
			_, e = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Hour)), expires.ID)
			must(e)
			verify(expires.Secret, nil, false, "KEY_EXPIRED")
			verify(expires.Secret, nil, false, "INVALID_API_KEY")
			amount := int64(2)
			interval := time.Second
			refill, e := keys.Create(ctx, owner.User.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &amount, RefillInterval: &interval, RefillAmount: &amount}})
			must(e)
			verify(refill.Secret, nil, true, "")
			verify(refill.Secret, nil, true, "")
			verify(refill.Secret, nil, false, "USAGE_EXCEEDED")
			_, e = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "lastRefillAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Hour)), refill.ID)
			must(e)
			verify(refill.Secret, nil, true, "")
			policies, err := ak.New(ak.Options{Store: store, ConfigID: "automation", RequireName: true, Headers: []string{"X-Service-Key", "X-Alternate-Key"}, DefaultExpiration: time.Hour, MinExpiration: time.Second, MaxExpiration: time.Hour, RateMax: 1, DefaultPermissions: ak.Permissions{"build": {"run"}}})
			must(err)
			_, e = policies.Create(ctx, owner.User.ID, ak.CreateInput{})
			expect(e, "NAME_REQUIRED")
			_, e = policies.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Bad", ExpiresIn: 24 * time.Hour})
			expect(e, "EXPIRES_IN_IS_TOO_LARGE")
			_, e = policies.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Bad", Metadata: map[string]any{"env": 1}})
			expect(e, "METADATA_DISABLED")
			job, e := policies.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Builder"})
			must(e)
			if job.ExpiresAt == nil || job.ExpiresAt.Sub(job.CreatedAt) != time.Hour {
				t.Fatal("default expiration missing")
			}
			_, e = keys.Get(ctx, owner.User.ID, job.ID)
			expect(e, "KEY_NOT_FOUND")
			verify(job.Secret, nil, false, "INVALID_API_KEY")
			// Editing a returned key must not change defaults for later issuances.
			job.Permissions["build"][0] = "other"
			secondJob, e := policies.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Runner"})
			must(e)
			if secondJob.Permissions["build"][0] != "run" {
				t.Fatal("issued metadata mutated future permission defaults")
			}
			serviceRoute := policies.Middleware(ak.Permissions{"build": {"run"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				credential, ok := ak.FromContext(r.Context())
				if !ok || credential.ID != job.ID || credential.ReferenceID != owner.User.ID {
					t.Error("middleware did not attach the verified owner and key")
				}
				w.WriteHeader(204)
			}))
			request := func(headers http.Header) *httptest.ResponseRecorder {
				req := httptest.NewRequest("GET", "https://api.example/build", nil)
				req.Header = headers
				w := httptest.NewRecorder()
				serviceRoute.ServeHTTP(w, req)
				return w
			}
			if request(http.Header{"X-Service-Key": {job.Secret}, "X-Alternate-Key": {secondJob.Secret}}).Code != 401 {
				t.Fatal("ambiguous key headers accepted")
			}
			if request(http.Header{"X-Api-Key": {job.Secret}}).Code != 401 {
				t.Fatal("unconfigured credential header accepted")
			}
			if request(http.Header{"X-Service-Key": {job.Secret}}).Code != 204 {
				t.Fatal("configured key header failed")
			}
			throttled := request(http.Header{"X-Alternate-Key": {job.Secret}})
			if throttled.Code != 429 || throttled.Header().Get("Retry-After") == "" {
				t.Fatal("rate rejection omitted retry interval")
			}
			_, e = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "lastRequest"=? WHERE "id"=?`), store.date(time.Now().Add(-48*time.Hour)), job.ID)
			must(e)
			if request(http.Header{"X-Service-Key": {job.Secret}}).Code != 204 {
				t.Fatal("elapsed rate window did not reopen")
			}
			// Expired cleanup is scoped to the selected configuration and leaves live keys intact.
			_, e = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Hour)), job.ID)
			must(e)
			nExpired, e := keys.DeleteExpired(ctx)
			must(e)
			if nExpired != 0 {
				t.Fatal("expired cleanup crossed configuration boundary")
			}
			nExpired, e = policies.DeleteExpired(ctx)
			must(e)
			if nExpired != 1 {
				t.Fatal("expired cleanup did not remove exactly one key")
			}
			live, e := policies.Get(ctx, owner.User.ID, secondJob.ID)
			must(e)
			if live.ID != secondJob.ID {
				t.Fatal("live key lost during sweep")
			}
			_, e = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), true, owner.User.ID)
			must(e)
			verify(refill.Secret, nil, false, "USER_BANNED")
			_, e = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), false, owner.User.ID)
			must(e)
			must(store.DeleteAccount(ctx, owner.User.ID, *owner.Token, "", "", time.Now()))
			verify(refill.Secret, nil, false, "INVALID_API_KEY")
			var n int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT count(*) FROM "apikey" WHERE "referenceId"=?`), owner.User.ID).Scan(&n))
			if n != 0 {
				t.Fatal("user deletion retained application credentials")
			}
		})
	}
}
