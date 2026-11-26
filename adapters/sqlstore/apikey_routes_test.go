package sqlstore

import (
	"net/http"
	"strings"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

// POST /api-key/update changes or clears a key's lifetime, replaces its
// metadata and switches it off, and refuses values outside the policy
// without changing the key.
func TestAPIKeyUpdateFields(t *testing.T) {
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
			users, err := ak.New(ak.Options{Store: store, EnableMetadata: true})
			must(err)
			plain, err := ak.New(ak.Options{Store: store, ConfigID: "plain"})
			must(err)
			plugin, err := ak.NewPlugin(users, plain)
			must(err)
			const origin = "https://updates.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("u", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			_, err = member.SignUpEmail(ctx, client.SignUpRequest{Name: "Updater", Email: "updater@example.test", Password: "update-password"})
			must(err)
			seconds := func(d time.Duration) *int64 { n := int64(d / time.Second); return &n }
			key, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "first", ExpiresIn: seconds(48 * time.Hour)})
			must(err)
			get := func() *ak.Key {
				t.Helper()
				k, err := member.GetAPIKey(ctx, key.ID, "")
				must(err)
				return k
			}

			up, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, ExpiresIn: seconds(10 * 24 * time.Hour)})
			must(err)
			want := time.Now().Add(10 * 24 * time.Hour)
			if up.ExpiresAt == nil || up.ExpiresAt.Sub(want).Abs() > time.Minute || get().ExpiresAt.Sub(*up.ExpiresAt).Abs() > time.Second {
				t.Fatal("a new lifetime was not saved", up.ExpiresAt)
			}
			if up, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, ClearExpiration: true}); err != nil || up.ExpiresAt != nil || get().ExpiresAt != nil {
				t.Fatal("clearing the lifetime left an expiry", err)
			}
			if _, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, ExpiresIn: seconds(time.Hour)}); keyErrorCode(err) != "EXPIRES_IN_IS_TOO_SMALL" || get().ExpiresAt != nil {
				t.Fatal("a lifetime under a day was saved", err)
			}

			_, err = member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, Metadata: map[string]any{"tier": "gold"}})
			must(err)
			up, err = member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, Metadata: map[string]any{"region": "eu"}})
			must(err)
			if got := get().Metadata; len(got) != 1 || got["region"] != "eu" || up.Metadata["region"] != "eu" {
				t.Fatal("updated metadata was not saved", got)
			}
			if err := member.Do(ctx, http.MethodPost, "/api-key/update", map[string]any{"keyId": key.ID, "metadata": "text"}, nil); keyErrorCode(err) != "INVALID_METADATA_TYPE" {
				t.Fatal("metadata that is not an object was accepted", err)
			}
			for _, name := range []string{strings.Repeat("n", 33), ""} {
				if _, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, Name: &name}); keyErrorCode(err) != "INVALID_NAME_LENGTH" || *get().Name != "first" {
					t.Fatal("an out-of-range name was saved", err)
				}
			}
			other, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "plain"})
			must(err)
			if _, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: other.ID, ConfigID: "plain", Metadata: map[string]any{"tier": "gold"}}); keyErrorCode(err) != "METADATA_DISABLED" {
				t.Fatal("metadata was accepted while it is off", err)
			}

			outsider, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			_, err = outsider.SignUpEmail(ctx, client.SignUpRequest{Name: "Outsider", Email: "outsider@example.test", Password: "update-password"})
			must(err)
			taken := "taken"
			if _, err := outsider.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, Name: &taken}); keyErrorCode(err) != "KEY_NOT_FOUND" || *get().Name != "first" {
				t.Fatal("another user updated a key they do not own", err)
			}

			no := false
			if up, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: key.ID, Enabled: &no}); err != nil || up.Enabled || get().Enabled {
				t.Fatal("a key was not switched off", err)
			}
			if v, err := users.Verify(ctx, key.Secret, nil); err != nil || v.Valid || v.Error.Code != "KEY_DISABLED" {
				t.Fatal("a switched-off key still verified", err)
			}
		})
	}
}

// POST /api-key/delete removes only a key of the configuration it names,
// and a banned owner can delete nothing.
func TestAPIKeyDeleteScopeAndBan(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key", "admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			users, err := ak.New(ak.Options{Store: store})
			must(err)
			automation, err := ak.New(ak.Options{Store: store, ConfigID: "automation"})
			must(err)
			plugin, err := ak.NewPlugin(users, automation)
			must(err)
			const origin = "https://deletes.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("d", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			owner, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Deleter", Email: "deleter@example.test", Password: "delete-password"})
			must(err)
			key, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "Doomed"})
			must(err)
			for _, config := range []string{"automation", "bogus"} {
				if err := member.DeleteAPIKey(ctx, key.ID, config); keyErrorCode(err) != "KEY_NOT_FOUND" {
					t.Fatal("a delete under another configuration was not refused", config, err)
				}
			}
			if _, err := member.GetAPIKey(ctx, key.ID, ""); err != nil {
				t.Fatal("a delete under another configuration removed the key", err)
			}
			outsider, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			_, err = outsider.SignUpEmail(ctx, client.SignUpRequest{Name: "Outsider", Email: "outsider@example.test", Password: "delete-password"})
			must(err)
			if err := outsider.DeleteAPIKey(ctx, key.ID, ""); keyErrorCode(err) != "KEY_NOT_FOUND" {
				t.Fatal("another user's delete was not answered KEY_NOT_FOUND", err)
			}
			if _, err := member.GetAPIKey(ctx, key.ID, ""); err != nil {
				t.Fatal("another user's delete removed the key", err)
			}

			ban := func(banned bool) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), banned, owner.User.ID)
				must(err)
			}
			ban(true)
			if err := member.DeleteAPIKey(ctx, key.ID, ""); keyErrorCode(err) != "UNAUTHORIZED" {
				t.Fatal("a banned owner's delete over HTTP was not refused as signed out", err)
			}
			if err := users.Delete(ctx, owner.User.ID, key.ID); keyErrorCode(err) != "USER_BANNED" {
				t.Fatal("a banned owner's delete from Go was not refused", err)
			}
			ban(false)
			if _, err := users.Get(ctx, owner.User.ID, key.ID); err != nil {
				t.Fatal("a banned owner's delete removed the key", err)
			}
			_, err = member.SignInEmail(ctx, client.SignInRequest{Email: "deleter@example.test", Password: "delete-password"})
			must(err)
			must(member.DeleteAPIKey(ctx, key.ID, ""))
			if _, err := member.GetAPIKey(ctx, key.ID, ""); keyErrorCode(err) != "KEY_NOT_FOUND" {
				t.Fatal("a deleted key was still found", err)
			}
		})
	}
}
