package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// An SSO resolver can require an active SCIM User; the store checks it
// again under the account's lock in the sign-in transaction.
func TestEnterpriseSignInGatedBySCIM(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"organization", "sso", "scim"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			idp := newSSOIssuer(t)
			now := time.Now().UTC()
			must(store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			pkce := true
			raw, err := json.Marshal(sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce})
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`), "record-acme", "acme", idp.URL, string(raw), "acme.example", "owner")
			must(err)
			var mu sync.Mutex
			var hook func()
			resolve := func(rc context.Context, in sso.UserResolutionInput) (sso.UserResolution, error) {
				ref := scim.UserExternalIDReference{ConnectionID: "workforce", ExternalID: in.AccountKey.AccountID}
				link, err := store.SCIMActiveUserLink(rc, ref)
				if errors.Is(err, scim.ErrNotFound) {
					return sso.UserResolution{Action: sso.ResolveReject, Code: "SCIM_USER_NOT_ACTIVE"}, nil
				}
				if err != nil {
					return sso.UserResolution{}, err
				}
				mu.Lock()
				h := hook
				mu.Unlock()
				if h != nil {
					h()
				}
				return sso.UserResolution{Action: sso.ResolveLink, UserID: link.UserID, Profile: "preserve", RequireActiveSCIMUser: &ref}, nil
			}
			h := newSSOHost(t, store, idp, sso.Options{ResolveUser: resolve})
			directory, err := scim.New(h.a, scim.Options{Store: store, Connections: []scim.Connection{{Directory: scim.Directory{ID: "workforce", ProvisioningDomainID: "workforce"}, Credentials: []scim.Credential{{ID: "writer", Token: "writer"}}}}})
			must(err)
			directoryCall := func(method, path string, body map[string]any) *httptest.ResponseRecorder {
				data, _ := json.Marshal(body)
				r := httptest.NewRequest(method, "https://service.test/identity/scim/v2/"+path, bytes.NewReader(data))
				r.Header.Set("Content-Type", scim.MediaType)
				r.Header.Set("Authorization", "Bearer writer")
				w := httptest.NewRecorder()
				directory.ServeHTTP(w, r)
				return w
			}
			active := func(id string, on bool) {
				t.Helper()
				if w := directoryCall(http.MethodPatch, "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "path": "active", "value": on}}}); w.Code != 200 {
					t.Fatal("PATCH failed", w.Code, w.Body.String())
				}
			}
			signIn := func() string {
				t.Helper()
				return h.signIn(map[string]any{"providerId": "acme"}, "employee@acme.example", "employee", "client_secret_basic", "").Header().Get("Location")
			}
			ref := scim.UserExternalIDReference{ConnectionID: "workforce", ExternalID: "employee"}

			if got := signIn(); !strings.Contains(got, "error=SCIM_USER_NOT_ACTIVE") {
				t.Fatal("an employee without a SCIM User signed in", got)
			}
			w := directoryCall(http.MethodPost, "Users", map[string]any{"schemas": []string{scim.UserSchema}, "externalId": "employee", "userName": "employee@acme.example"})
			var created map[string]any
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &created) != nil {
				t.Fatal("provisioning failed", w.Code, w.Body.String())
			}
			id := created["id"].(string)
			if got := signIn(); got != "https://service.test/home" {
				t.Fatal("an active SCIM User could not sign in through the paired provider", got)
			}
			var account, owner string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "userId" FROM "account" WHERE "providerId"=? AND "accountId"=?`), "acme", "employee").Scan(&account))
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "userId" FROM "scimUser" WHERE "id"=?`), id).Scan(&owner))
			if account != owner {
				t.Fatal("the gated sign-in did not link the provisioned account", account, owner)
			}
			if link, err := store.SCIMActiveUserLink(ctx, ref); err != nil || link.SCIMUserID != id || link.UserID != owner {
				t.Fatal("the active link did not name the SCIM User and its account", link, err)
			}
			if _, err := store.SCIMActiveUserLink(ctx, scim.UserExternalIDReference{ConnectionID: "workforce", ExternalID: "EMPLOYEE"}); !errors.Is(err, scim.ErrNotFound) {
				t.Fatal("an active link matched an externalId in another case", err)
			}
			if _, err := store.SCIMActiveUserLink(ctx, scim.UserExternalIDReference{ConnectionID: "Workforce", ExternalID: "employee"}); !errors.Is(err, scim.ErrNotFound) {
				t.Fatal("an active link crossed connections", err)
			}

			// A deactivation made while the resolver runs is caught by the
			// store's fence.
			_, err = store.db.ExecContext(ctx, store.bind(`DELETE FROM "session" WHERE "userId"=?`), owner)
			must(err)
			mu.Lock()
			hook = func() { active(id, false) }
			mu.Unlock()
			if got := signIn(); !strings.Contains(got, "error=SSO_USER_RESOLUTION_FAILED") {
				t.Fatal("a sign-in whose SCIM User was deactivated during resolution was not refused", got)
			}
			var sessions int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), owner).Scan(&sessions))
			if sessions != 0 {
				t.Fatal("a fenced sign-in issued a session", sessions)
			}
			mu.Lock()
			hook = nil
			mu.Unlock()
			if _, err := store.SCIMActiveUserLink(ctx, ref); !errors.Is(err, scim.ErrNotFound) {
				t.Fatal("an inactive SCIM User still had an active link", err)
			}
			if got := signIn(); !strings.Contains(got, "error=SCIM_USER_NOT_ACTIVE") {
				t.Fatal("an inactive SCIM User signed in", got)
			}
			active(id, true)
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
			// A retired connection, a tombstone for the externalId and an
			// orphaned User each lose the active link.
			exec(`UPDATE "scimConnectionBinding" SET "decommissionStatus"='reconciling' WHERE "connectionId"=?`, "workforce")
			if _, err := store.SCIMActiveUserLink(ctx, ref); !errors.Is(err, scim.ErrNotFound) {
				t.Fatal("a retired connection still had an active link", err)
			}
			if got := signIn(); !strings.Contains(got, "error=SCIM_USER_NOT_ACTIVE") {
				t.Fatal("a User of a retired connection signed in", got)
			}
			exec(`UPDATE "scimConnectionBinding" SET "decommissionStatus"='active' WHERE "connectionId"=?`, "workforce")
			mu.Lock()
			hook = func() {
				exec(`UPDATE "scimConnectionBinding" SET "decommissionStatus"='reconciling' WHERE "connectionId"=?`, "workforce")
			}
			mu.Unlock()
			if got := signIn(); !strings.Contains(got, "error=SSO_USER_RESOLUTION_FAILED") {
				t.Fatal("a sign-in whose connection was retired during resolution was not refused", got)
			}
			mu.Lock()
			hook = nil
			mu.Unlock()
			exec(`UPDATE "scimConnectionBinding" SET "decommissionStatus"='active' WHERE "connectionId"=?`, "workforce")
			if _, err := store.SCIMActiveUserLink(ctx, ref); err != nil {
				t.Fatal("a restored connection had no active link", err)
			}
			exec(`INSERT INTO "scimIdentityTombstone" ("id","connectionId","provisioningDomainId","externalId","externalIdKey","userId","profile","deletedAt") VALUES (?,?,?,?,?,?,?,?)`,
				"stale-tomb", "workforce", "workforce", "employee", scimKey("scim-user-external-id", "workforce", "employee"), owner, "preserve", now)
			if _, err := store.SCIMActiveUserLink(ctx, ref); !errors.Is(err, scim.ErrNotFound) {
				t.Fatal("a tombstoned externalId still had an active link", err)
			}
			exec(`DELETE FROM "scimIdentityTombstone" WHERE "id"=?`, "stale-tomb")
			exec(`DELETE FROM "scimSubject" WHERE "userId"=?`, owner)
			if _, err := store.SCIMActiveUserLink(ctx, ref); !errors.Is(err, scim.ErrNotFound) {
				t.Fatal("an orphaned SCIM User still had an active link", err)
			}
			exec(`INSERT INTO "scimSubject" ("id","userId","profileSourceId","revision","createdAt","updatedAt") VALUES (?,?,?,1,?,?)`, "restored", owner, id, store.date(now), store.date(now))
			if w := directoryCall(http.MethodDelete, "Users/"+id, nil); w.Code != 204 {
				t.Fatal("DELETE failed", w.Code, w.Body.String())
			}
			if _, err := store.SCIMActiveUserLink(ctx, ref); !errors.Is(err, scim.ErrNotFound) {
				t.Fatal("a deleted SCIM User still had an active link", err)
			}
		})
	}
}
