package sqlstore

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// The API key routes, Go calls, verification results and session reads
// answer each error with the status, code and message of the error table.
func TestAPIKeyErrorCodesAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			wantError := func(err error, status int, code, message string) {
				t.Helper()
				var api *plainauth.APIError
				if !errors.As(err, &api) || api.Status != status || api.Code != code || api.Message != message {
					t.Fatalf("expected %d %s %q, got %v", status, code, message, err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key", "organization", "admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			users, err := ak.New(ak.Options{Store: store, EnableMetadata: true, EnableSession: true})
			must(err)
			fixed, err := ak.New(ak.Options{Store: store, ConfigID: "fixed", RequireName: true, DisableCustomExpiration: true})
			must(err)
			teams, err := ak.New(ak.Options{Store: store, ConfigID: "teams", Organization: &ak.OrganizationOptions{Roles: map[string][]string{"auditor": {"read"}}}, EnableSession: true, Headers: []string{"X-Team-Key"}})
			must(err)
			plugin, err := ak.NewPlugin(users, fixed, teams)
			must(err)
			orgPlugin, err := org.New(org.Options{Store: store})
			must(err)
			const origin = "https://errors.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("e", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin, orgPlugin}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			owner, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@example.test", Password: "errors-password"})
			must(err)
			create := func(body map[string]any) error {
				return member.Do(ctx, http.MethodPost, "/api-key/create", body, nil)
			}
			wantError(create(map[string]any{"prefix": strings.Repeat("p", 33)}), 400, "INVALID_PREFIX_LENGTH", "The prefix length is either too large or too small.")
			wantError(create(map[string]any{"prefix": "bad prefix!"}), 400, "VALIDATION_ERROR", "[body.prefix] Invalid prefix format, must be alphanumeric and contain only underscores and hyphens.")
			wantError(create(map[string]any{"name": strings.Repeat("n", 33)}), 400, "INVALID_NAME_LENGTH", "The name length is either too large or too small.")
			wantError(create(map[string]any{"expiresIn": 3600}), 400, "EXPIRES_IN_IS_TOO_SMALL", "The expiresIn is smaller than the predefined minimum value.")
			wantError(create(map[string]any{"expiresIn": 366 * 86400}), 400, "EXPIRES_IN_IS_TOO_LARGE", "The expiresIn is larger than the predefined maximum value.")
			wantError(create(map[string]any{"metadata": "text"}), 400, "INVALID_METADATA_TYPE", "metadata must be an object or undefined")
			wantError(create(map[string]any{"configId": "fixed", "name": "Fixed", "expiresIn": 2 * 86400}), 400, "KEY_DISABLED_EXPIRATION", "Custom key expiration values are disabled.")
			wantError(create(map[string]any{"configId": "fixed", "name": "Fixed", "metadata": map[string]any{"env": "test"}}), 400, "METADATA_DISABLED", "Metadata is disabled.")
			wantError(create(map[string]any{"remaining": 5}), 400, "SERVER_ONLY_PROPERTY", "The property you're trying to set can only be set from the server auth instance only.")
			wantError(create(map[string]any{"configId": "teams", "name": "Team"}), 400, "ORGANIZATION_ID_REQUIRED", "Organization ID is required for organization-owned API keys.")
			_, err = fixed.Create(ctx, owner.User.ID, ak.CreateInput{})
			wantError(err, 400, "NAME_REQUIRED", "API Key name is required.")
			amount, interval, negative := int64(5), time.Hour, int64(-1)
			_, err = users.Create(ctx, owner.User.ID, ak.CreateInput{Policy: ak.Policy{RefillAmount: &amount}})
			wantError(err, 400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED", "refillAmount is required when refillInterval is provided")
			_, err = users.Create(ctx, owner.User.ID, ak.CreateInput{Policy: ak.Policy{RefillInterval: &interval}})
			wantError(err, 400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED", "refillInterval is required when refillAmount is provided")
			_, err = users.Create(ctx, owner.User.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &negative}})
			wantError(err, 400, "INVALID_REMAINING", "The remaining count is either too large or too small.")
			if unnamed, err := users.Create(ctx, owner.User.ID, ak.CreateInput{}); err != nil || unnamed.Name != nil {
				t.Fatal("an unnamed key was refused or named where names are optional", err)
			}

			key, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "Owner key"})
			must(err)
			wantError(member.Do(ctx, http.MethodPost, "/api-key/update", map[string]any{"keyId": key.ID}, nil), 400, "NO_VALUES_TO_UPDATE", "No values to update.")
			wantError(member.Do(ctx, http.MethodPost, "/api-key/update", map[string]any{"keyId": key.ID, "name": ""}, nil), 400, "INVALID_NAME_LENGTH", "The name length is either too large or too small.")
			_, err = member.GetAPIKey(ctx, "missing", "")
			wantError(err, 404, "KEY_NOT_FOUND", "API Key not found")
			_, err = member.GetAPIKey(ctx, key.ID, "bogus")
			wantError(err, 404, "KEY_NOT_FOUND", "API Key not found")

			var group org.Organization
			must(member.Do(ctx, http.MethodPost, "/organization/create", map[string]any{"name": "Errors", "slug": "errors"}, &group))
			teamKey, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID, Name: "Team"})
			must(err)
			visitor, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			_, err = visitor.SignUpEmail(ctx, client.SignUpRequest{Name: "Visitor", Email: "visitor@example.test", Password: "errors-password"})
			must(err)
			_, err = visitor.GetAPIKey(ctx, teamKey.ID, "teams")
			wantError(err, 403, "USER_NOT_MEMBER_OF_ORGANIZATION", "You are not a member of the organization that owns this API key.")
			plain, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			plainUser, err := plain.SignUpEmail(ctx, client.SignUpRequest{Name: "Plain", Email: "plain@example.test", Password: "errors-password"})
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), "plain-member", group.ID, plainUser.User.ID, "member", store.date(time.Now()))
			must(err)
			_, err = plain.GetAPIKey(ctx, teamKey.ID, "teams")
			wantError(err, 403, "INSUFFICIENT_API_KEY_PERMISSIONS", "You do not have permission to perform this action on organization API keys.")
			teamSecret, err := teams.Create(ctx, owner.User.ID, ak.CreateInput{OrganizationID: group.ID, Name: "Team session"})
			must(err)
			r := httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
			r.Header.Set("X-Team-Key", teamSecret.Secret)
			w := httptest.NewRecorder()
			host.ServeHTTP(w, r)
			if w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"INVALID_REFERENCE_ID_FROM_API_KEY","message":"The reference id from the API key is invalid."`) {
				t.Fatal("an organization key read a user session", w.Code, w.Body)
			}
			bare, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("e", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{teams.Plugin()}})
			must(err)
			bareMember, err := client.New(origin, &http.Client{Transport: guestTransport{bare}})
			must(err)
			_, err = bareMember.SignInEmail(ctx, client.SignInRequest{Email: "owner@example.test", Password: "errors-password"})
			must(err)
			_, err = bareMember.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID, Name: "No plugin"})
			wantError(err, 500, "ORGANIZATION_PLUGIN_REQUIRED", "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.")

			anonymous, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			_, err = anonymous.GetAPIKey(ctx, key.ID, "")
			wantError(err, 401, "UNAUTHORIZED", "Unauthorized")
			_, err = anonymous.ListAPIKeys(ctx, "", ak.PageOptions{})
			wantError(err, 401, "UNAUTHORIZED", "Unauthorized")
			wantError(anonymous.DeleteAPIKey(ctx, key.ID, ""), 401, "UNAUTHORIZED", "Unauthorized")
			_, err = anonymous.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "Signed out"})
			wantError(err, 401, "UNAUTHORIZED_SESSION", "Unauthorized or invalid session")
			renamed := "Signed out"
			_, err = anonymous.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, Name: &renamed})
			wantError(err, 401, "UNAUTHORIZED_SESSION", "Unauthorized or invalid session")

			solo, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("e", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{fixed.Plugin()}})
			must(err)
			soloMember, err := client.New(origin, &http.Client{Transport: guestTransport{solo}})
			must(err)
			_, err = soloMember.SignInEmail(ctx, client.SignInRequest{Email: "owner@example.test", Password: "errors-password"})
			must(err)
			_, err = soloMember.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "No default"})
			wantError(err, 400, "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND", "No default api-key configuration found.")
			soloKey, err := soloMember.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "fixed", Name: "Solo"})
			must(err)
			_, err = soloMember.GetAPIKey(ctx, soloKey.ID, "")
			wantError(err, 400, "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND", "No default api-key configuration found.")
			page, err := soloMember.ListAPIKeys(ctx, "", ak.PageOptions{})
			must(err)
			found := false
			for _, k := range page.Keys {
				found = found || k.ID == soloKey.ID
			}
			if !found {
				t.Fatal("a list without configId needed a default configuration")
			}

			verifyError := func(secret string, required ak.Permissions, code, message string) {
				t.Helper()
				v, err := users.Verify(ctx, secret, required)
				must(err)
				if v.Valid || v.Error == nil || v.Error.Code != code || v.Error.Message != message {
					t.Fatalf("verification answered %+v, want %s %q", v.Error, code, message)
				}
			}
			verifyError(strings.Repeat("z", 64), nil, "INVALID_API_KEY", "Invalid API key.")
			disabled, err := users.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Disabled"})
			must(err)
			no := false
			_, err = users.Update(ctx, owner.User.ID, disabled.ID, ak.UpdateInput{Policy: ak.Policy{Enabled: &no}})
			must(err)
			verifyError(disabled.Secret, nil, "KEY_DISABLED", "API Key is disabled")
			scoped, err := users.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Scoped", Policy: ak.Policy{Permissions: ak.Permissions{"reports": {"read"}}}})
			must(err)
			verifyError(scoped.Secret, ak.Permissions{"reports": {"write"}}, "KEY_NOT_FOUND", "API Key not found")
			zero := int64(0)
			spent, err := users.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Spent", Policy: ak.Policy{Remaining: &zero}})
			must(err)
			verifyError(spent.Secret, nil, "USAGE_EXCEEDED", "API Key has reached its usage limit")
			expired, err := users.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Expired"})
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Minute)), expired.ID)
			must(err)
			verifyError(expired.Secret, nil, "KEY_EXPIRED", "API Key has expired")

			sessionError := func(secret string, status int, code, message string) {
				t.Helper()
				r := httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
				r.Header.Set("X-Api-Key", secret)
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				var body struct{ Code, Message string }
				if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != code || body.Message != message {
					t.Fatalf("session read answered %d %s, want %d %s %q", w.Code, w.Body, status, code, message)
				}
			}
			sessionError("short", 403, "INVALID_API_KEY", "Invalid API key.")
			shared, err := ak.New(ak.Options{Store: store, ConfigID: "shared", EnableSession: true})
			must(err)
			sharing, err := ak.NewPlugin(users, shared)
			must(err)
			sharedHost, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("e", 32), RateLimit: &off, Plugins: []plainauth.Plugin{sharing}})
			must(err)
			r = httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
			r.Header.Set("X-Api-Key", "short")
			w = httptest.NewRecorder()
			sharedHost.ServeHTTP(w, r)
			if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"INVALID_API_KEY"`) {
				t.Fatal("a short key shared by two configurations was not refused with 403", w.Code, w.Body)
			}

			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), true, owner.User.ID)
			must(err)
			wantError(users.Delete(ctx, owner.User.ID, key.ID), 401, "USER_BANNED", "User is banned")
			v, err := users.Verify(ctx, scoped.Secret, nil)
			must(err)
			if v.Valid || v.Error == nil || v.Error.Code != "USER_BANNED" || v.Error.Message != "User is banned" {
				t.Fatal("a banned owner's key was not refused", v.Error)
			}
		})
	}
}

// keyTransport sends every request with an API key header.
type keyTransport struct {
	server *plainauth.Auth
	key    string
}

func (k keyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Api-Key", k.key)
	return guestTransport{k.server}.RoundTrip(r)
}

// A spent rate budget answers RATE_LIMITED with the milliseconds until the
// window reopens: under Details from Verify and the middleware, and under
// details in a session read's 429, which the Go client decodes.
func TestAPIKeyRateLimitDetails(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			keys, err := ak.New(ak.Options{Store: store, EnableSession: true, RateMax: 1})
			must(err)
			const origin = "https://limits.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("l", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{keys.Plugin()}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			owner, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "limits@example.test", Password: "limits-password"})
			must(err)
			delay := func(d *ak.RetryDetails) bool { return d != nil && d.TryAgainIn > 0 && d.TryAgainIn <= 86_400_000 }

			verified, err := keys.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Verify"})
			must(err)
			if v, err := keys.Verify(ctx, verified.Secret, nil); err != nil || !v.Valid {
				t.Fatal("a key within its budget was refused", err, v.Error)
			}
			v, err := keys.Verify(ctx, verified.Secret, nil)
			must(err)
			if v.Valid || v.Error.Code != "RATE_LIMITED" || v.Error.Message != "Rate limit exceeded." || !delay(v.Error.Details) {
				t.Fatal("rate denial lacked RATE_LIMITED details", v.Error)
			}

			session, err := keys.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Session"})
			must(err)
			viaKey, err := client.New(origin, &http.Client{Transport: keyTransport{host, session.Secret}})
			must(err)
			must(viaKey.Do(ctx, http.MethodGet, "/get-session", nil, nil))
			err = viaKey.Do(ctx, http.MethodGet, "/get-session", nil, nil)
			var detailed *plainauth.DetailedError
			if !errors.As(err, &detailed) || detailed.Status != 429 || detailed.Code != "RATE_LIMITED" || detailed.Message != "Rate limit exceeded." {
				t.Fatal("rate-limited session read lacked its details", err)
			}
			if ms, ok := detailed.Details["tryAgainIn"].(float64); !ok || ms <= 0 || ms > 86_400_000 {
				t.Fatal("the Go client lost the rate-limit details", detailed.Details)
			}

			guarded, err := keys.Create(ctx, owner.User.ID, ak.CreateInput{Name: "Middleware"})
			must(err)
			handler := keys.Middleware(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			serve := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "https://app.example/jobs", nil)
				r.Header.Set("X-Api-Key", guarded.Secret)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			if w := serve(); w.Code != http.StatusNoContent {
				t.Fatal("middleware refused a key within its budget", w.Code, w.Body)
			}
			w := serve()
			var failure ak.VerifyError
			if w.Code != 429 || w.Header().Get("Retry-After") == "" || json.Unmarshal(w.Body.Bytes(), &failure) != nil || failure.Code != "RATE_LIMITED" || !delay(failure.Details) {
				t.Fatal("middleware rate refusal lacked its retry delay", w.Code, w.Header(), w.Body)
			}
		})
	}
}
