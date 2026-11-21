package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	stonewrit "github.com/Stonewrit/stonewrit-auth"
	ak "github.com/Stonewrit/stonewrit-auth/plugins/apikey"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestApplicationKeyValidator(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			type requestSource struct{}
			ctx := context.WithValue(t.Context(), requestSource{}, "worker")
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			user := testUser("validator-owner")
			must(store.CreateUser(ctx, user, "", nil))

			var calls, unrelatedCalls int
			var presented string
			var callbackErr error
			allow := false
			keys, err := ak.New(ak.Options{
				Store: store, ConfigID: "workers", EnableSession: true,
				DefaultPermissions: ak.Permissions{"report": {"read"}},
				ValidateKey: func(ctx context.Context, secret string) (bool, error) {
					if ctx.Value(requestSource{}) != "worker" {
						t.Fatal("validator lost the requesting context")
					}
					presented = secret
					calls++
					return allow, callbackErr
				},
			})
			must(err)
			other, err := ak.New(ak.Options{Store: store, EnableSession: true,
				ValidateKey: func(context.Context, string) (bool, error) {
					unrelatedCalls++
					return true, nil
				},
			})
			must(err)
			plugin, err := ak.NewPlugin(other, keys)
			must(err)
			const origin = "https://service.example"
			host, err := stonewrit.New(stonewrit.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("s", 36), Plugins: []stonewrit.Plugin{plugin}})
			must(err)
			uses := int64(6)
			key, err := keys.Create(ctx, user.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &uses}})
			must(err)
			read := ak.Permissions{"report": {"read"}}
			denied, err := keys.Verify(ctx, key.Secret, read)
			must(err)
			if denied.Valid || denied.Key != nil || denied.Error == nil || denied.Error.Code != "KEY_NOT_FOUND" || presented != key.Secret || calls != 1 {
				t.Fatal("direct verification did not honor one rejection from its validator")
			}

			app := keys.Middleware(read, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if k, ok := ak.FromContext(r.Context()); !ok || k.ID != key.ID {
					t.Fatal("handler missing the verified key")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			request := func(h http.Handler, path string, status int, code string) {
				t.Helper()
				before := calls
				req := httptest.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
				req.Header.Set("X-API-Key", key.Secret)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != status || !strings.Contains(rec.Body.String(), code) || calls != before+1 || unrelatedCalls != 0 {
					t.Fatalf("verification result status=%d expected=%d callback delta=%d other=%d", rec.Code, status, calls-before, unrelatedCalls)
				}
				if strings.Contains(rec.Body.String(), "private-validator-detail") {
					t.Fatal("host callback error appeared in the HTTP response")
				}
			}
			request(app, "/reports", 401, "KEY_NOT_FOUND")
			request(host, "/api/auth/get-session", 403, "INVALID_API_KEY")
			callbackErr = &stonewrit.APIError{Status: 400, Code: "LOCAL", Message: "private-validator-detail"}
			_, err = keys.Verify(ctx, key.Secret, nil)
			if !errors.Is(err, callbackErr) {
				t.Fatal("trusted verification lost the application error")
			}
			request(host, "/api/auth/get-session", 500, "INTERNAL_SERVER_ERROR")
			request(app, "/reports", 500, "INTERNAL_SERVER_ERROR")
			callbackErr, allow = nil, true
			forbidden, err := keys.Verify(ctx, key.Secret, ak.Permissions{"report": {"write"}})
			must(err)
			if forbidden.Valid || forbidden.Error == nil || forbidden.Error.Code != "KEY_NOT_FOUND" {
				t.Fatal("callback acceptance overrode required permissions")
			}
			request(host, "/api/auth/get-session", 200, user.ID)
			request(app, "/reports", 204, "")
			got, err := keys.Get(ctx, user.ID, key.ID)
			must(err)
			if got.Remaining == nil || *got.Remaining != uses-2 || got.RequestCount != 2 {
				t.Fatalf("only successful requests should consume uses: %+v", got)
			}
			unknown, err := keys.Verify(ctx, strings.Repeat("z", 64), nil)
			must(err)
			if unknown.Valid || unknown.Error == nil || unknown.Error.Code != "INVALID_API_KEY" {
				t.Fatal("callback acceptance authenticated an unknown credential")
			}
		})
	}
}
