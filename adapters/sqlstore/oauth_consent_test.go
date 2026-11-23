package sqlstore

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/apikey"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOAuthConsentManagement(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			wantError := func(err error, status int, code string) {
				t.Helper()
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Status != status || problem.Code != code {
					t.Fatalf("want HTTP %d %q, got %v", status, code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "admin", "api-key"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			store, peer := open(), open()
			providerScopes := []string{"reports", "email", ""}
			plugin := op.ConsentManagement(op.ConsentOptions{Scopes: providerScopes})
			providerScopes[0] = "unsaved"
			keys, err := apikey.New(apikey.Options{Store: store, EnableSession: true, DisableRateLimit: true})
			must(err)
			const origin = "https://consents.example.test"
			off := false
			host, err := auth.New(auth.Options{BaseURL: origin, Store: store, Secret: strings.Repeat("c", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{plugin, keys.Plugin()}})
			must(err)
			account := func(name string) (*client.Client, string) {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
				must(err)
				signed, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@consent.test", Password: "local consent password"})
				must(err)
				return c, signed.User.ID
			}
			owner, userID := account("owner")
			stranger, _ := account("stranger")
			empty, err := owner.OAuthConsents(ctx)
			must(err)
			if empty == nil || len(empty) != 0 {
				t.Fatal("expected empty list", empty)
			}
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
			const registeredClient = "report-client"
			const id = "grant + / & ?"
			before := time.Date(2025, 3, 12, 5, 10, 0, 0, time.UTC)
			exec(`INSERT INTO "oauthClient" ("id","clientId","redirectUris","userId") VALUES (?,?,?,?)`, "registered", registeredClient, "[]", userID)
			insert := func(id string) {
				exec(`INSERT INTO "oauthConsent" ("id","clientId","userId","referenceId","resources","requestedUserInfoClaims","scopes","createdAt","updatedAt") VALUES (?,?,?,?,?,?,?,?,?)`, id, registeredClient, userID, "project", `["urn:reports"]`, `["preferred_username"]`, `["email"]`, store.date(before), store.date(before))
			}
			insert(id)
			seen, err := owner.OAuthConsent(ctx, id)
			must(err)
			if seen.ID != id || seen.UserID == nil || *seen.UserID != userID || !seen.CreatedAt.Equal(before) || !slices.Equal(seen.Scopes, []string{"email"}) {
				t.Fatal("wrong grant", seen)
			}
			_, err = stranger.OAuthConsent(ctx, id)
			wantError(err, 401, "")
			_, err = stranger.UpdateOAuthConsent(ctx, id, []string{"reports"})
			wantError(err, 401, "")
			wantError(stranger.DeleteOAuthConsent(ctx, id), 401, "")
			_, err = owner.UpdateOAuthConsent(ctx, id, []string{"unsaved"})
			wantError(err, 400, "invalid_request")
			edited, err := owner.UpdateOAuthConsent(ctx, id, []string{"reports", "email", "reports"})
			must(err)
			if edited.UpdatedAt.Nanosecond() != 0 || !edited.UpdatedAt.After(before) || !slices.Equal(edited.Resources, seen.Resources) || !slices.Equal(edited.RequestedUserInfoClaims, seen.RequestedUserInfoClaims) {
				t.Fatal("unexpected consent update", edited)
			}
			persisted, err := peer.OAuthConsent(ctx, userID, id)
			must(err)
			if !slices.Equal(persisted.Scopes, edited.Scopes) || !persisted.UpdatedAt.Equal(edited.UpdatedAt) {
				t.Fatal("lost consent update", persisted)
			}
			exec(`UPDATE "oauthClient" SET "scopes"=? WHERE "clientId"=?`, `[]`, registeredClient)
			_, err = owner.UpdateOAuthConsent(ctx, id, []string{"reports"})
			wantError(err, 400, "invalid_request")
			cleared, err := owner.UpdateOAuthConsent(ctx, id, nil)
			must(err)
			if cleared.Scopes == nil || len(cleared.Scopes) != 0 {
				t.Fatal("failed to clear scopes")
			}
			exec(`UPDATE "oauthClient" SET "clientDiscoveryId"=? WHERE "clientId"=?`, "unconfigured", registeredClient)
			_, err = owner.UpdateOAuthConsent(ctx, id, nil)
			wantError(err, 404, "not_found")
			exec(`UPDATE "oauthClient" SET "clientDiscoveryId"=NULL WHERE "clientId"=?`, registeredClient)
			// Concurrent deletion must never allow a later update to recreate the grant.
			insert("concurrent")
			update := make(chan error, 1)
			go func() {
				_, err := peer.UpdateOAuthConsent(ctx, userID, "concurrent", []string{}, nil, time.Now().UTC().Truncate(time.Second))
				update <- err
			}()
			must(owner.DeleteOAuthConsent(ctx, "concurrent"))
			if err := <-update; err != nil && !errors.Is(err, auth.ErrNotFound) {
				t.Fatal(err)
			}
			_, err = peer.OAuthConsent(ctx, userID, "concurrent")
			if !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("deleted grant restored", err)
			}
			key, err := owner.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "Automation"})
			must(err)
			req := httptest.NewRequest(http.MethodGet, origin+"/api/auth/oauth2/get-consents", nil)
			req.Header.Set("X-API-Key", key.Secret)
			res := httptest.NewRecorder()
			host.ServeHTTP(res, req)
			if res.Code != 403 || !strings.Contains(res.Body.String(), "OWNER_SESSION_REQUIRED") {
				t.Fatalf("delegated key could manage consent: %d %s", res.Code, res.Body.String())
			}
			exec(`UPDATE "session" SET "impersonatedBy"=? WHERE "userId"=?`, "fixture-administrator", userID)
			_, err = owner.OAuthConsents(ctx)
			wantError(err, 403, "OWNER_SESSION_REQUIRED")
			wantError(owner.DeleteOAuthConsent(ctx, id), 403, "OWNER_SESSION_REQUIRED")
			exec(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "userId"=?`, userID)
			must(owner.DeleteOAuthConsent(ctx, id))
			wantError(owner.DeleteOAuthConsent(ctx, id), 404, "not_found")
		})
	}
}
