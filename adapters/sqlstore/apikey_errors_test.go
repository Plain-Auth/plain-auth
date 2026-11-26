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
			ddl, err := schema.Generate(dialect, []string{"api-key", "admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			users, err := ak.New(ak.Options{Store: store, EnableMetadata: true, EnableSession: true})
			must(err)
			fixed, err := ak.New(ak.Options{Store: store, ConfigID: "fixed", RequireName: true, DisableCustomExpiration: true})
			must(err)
			plugin, err := ak.NewPlugin(users, fixed)
			must(err)
			const origin = "https://errors.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("e", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
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
			_, err = fixed.Create(ctx, owner.User.ID, ak.CreateInput{})
			wantError(err, 400, "NAME_REQUIRED", "API Key name is required.")
			amount, interval, negative := int64(5), time.Hour, int64(-1)
			_, err = users.Create(ctx, owner.User.ID, ak.CreateInput{Policy: ak.Policy{RefillAmount: &amount}})
			wantError(err, 400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED", "refillInterval is required when refillAmount is provided")
			_, err = users.Create(ctx, owner.User.ID, ak.CreateInput{Policy: ak.Policy{RefillInterval: &interval}})
			wantError(err, 400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED", "refillAmount is required when refillInterval is provided")
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
