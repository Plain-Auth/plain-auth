package sqlstore

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// A client discovery creates a client with no owner or secret and its
// default resource links, replaces only the fields its document owns on a
// refresh, refuses clients of another source and refreshes of a deleted
// row, links a new default resource once, writes nothing for a bad default
// resource, and converges concurrent first saves on one row, on SQLite,
// PostgreSQL and MySQL.
func TestDiscoveredOAuthClients(t *testing.T) {
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
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(q), args...).Scan(&n))
				return n
			}
			write(`INSERT INTO "oauthResource" ("id","identifier","name") VALUES ('r1','urn:default','Default'),('r2','urn:new','New'),('r3','urn:off','Off')`)
			write(`UPDATE "oauthResource" SET "disabled"=? WHERE "identifier"='urn:off'`, true)
			refused := func(err error, code, description string) {
				t.Helper()
				var oauthErr *auth.OAuthError
				if !errors.As(err, &oauthErr) || oauthErr.Code != code || oauthErr.Description != description {
					t.Fatal("wanted a refusal", code, description, err)
				}
			}
			const id = "https://app.example.test/client.json"
			name, contacts := "App", []string{"ops@example.test"}
			t0 := time.Now().UTC().Truncate(time.Second)
			record := op.DiscoveredClientRecord{ID: "row-1", ClientID: id, DiscoveryID: "cimd", Scopes: []string{"openid"}, Now: t0,
				Metadata: op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, TokenEndpointAuthMethod: "none", GrantTypes: []string{"authorization_code"},
					ResponseTypes: []string{"code"}, Name: &name, Contacts: contacts, SubjectType: "pairwise", ApplicationType: "web", Resources: []string{"urn:default"}}}
			c, created, err := s.SaveDiscoveredClient(ctx, record)
			must(err)
			if !created || c.RowID != "row-1" || c.DiscoveryID != "cimd" || c.UserID != nil || c.ReferenceID != nil || c.SecretExpiresAt != nil ||
				c.ClientCredentialsScopes == nil || len(c.ClientCredentialsScopes) != 0 || *c.ApplicationType != "web" || *c.Scope != "openid" || *c.Name != "App" || *c.SubjectType != "pairwise" {
				t.Fatal("the created client was wrong", created, c)
			}
			if n := count(`SELECT COUNT(*) FROM "oauthClientResource" WHERE "clientId"=? AND "resourceId"='urn:default'`, id); n != 1 {
				t.Fatal("the default resource was not linked once", n)
			}
			got, err := s.LookupDiscoveredClient(ctx, id)
			must(err)
			if got.DiscoveryID != "cimd" || !got.CreatedAt.Equal(t0) || !got.UpdatedAt.Equal(t0) || got.ClientCredentialsScopes == nil {
				t.Fatal("the lookup lost provenance or timestamps", got.DiscoveryID, got.CreatedAt, got.UpdatedAt, got.ClientCredentialsScopes)
			}
			// A local client reads with no discovery and cannot be taken over.
			must(s.CreateRegisteredClient(ctx, op.ClientRegistrationRecord{ID: "local-row", ClientID: "local-app", CreatedAt: t0,
				Metadata: op.RegistrationMetadata{RedirectURIs: []string{"https://local.example.test/cb"}, TokenEndpointAuthMethod: "client_secret_basic"}}))
			if local, err := s.LookupDiscoveredClient(ctx, "local-app"); err != nil || local.DiscoveryID != "" || local.RowID != "local-row" {
				t.Fatal("a local client read wrongly", local, err)
			}
			taken := record
			taken.ClientID, taken.ID = "local-app", "row-x"
			_, _, err = s.SaveDiscoveredClient(ctx, taken)
			refused(err, "invalid_client", "client_id is already owned by a different registration source")
			other := record
			other.DiscoveryID = "other"
			_, _, err = s.SaveDiscoveredClient(ctx, other)
			refused(err, "invalid_client", "client_id is already owned by a different registration source")
			if _, err := s.LookupDiscoveredClient(ctx, "missing"); !errors.Is(err, op.ErrClientNotFound) {
				t.Fatal("a missing client was found", err)
			}
			// A refresh keeps server-owned fields and clears omitted document fields.
			write(`UPDATE "oauthClient" SET "disabled"=?,"skipConsent"=?,"enableEndSession"=?,"requirePKCE"=?,"clientCredentialsScopes"=? WHERE "clientId"=?`, true, true, true, true, `["machine"]`, id)
			t1 := t0.Add(time.Minute)
			refresh := op.DiscoveredClientRecord{ID: "ignored", ClientID: id, DiscoveryID: "cimd", Scopes: []string{"openid"}, Existing: &got, Now: t1,
				Metadata: op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, TokenEndpointAuthMethod: "none", GrantTypes: []string{"authorization_code"},
					Resources: []string{"urn:default", "urn:new"}}}
			c, created, err = s.SaveDiscoveredClient(ctx, refresh)
			must(err)
			if created || c.RowID != "row-1" || c.Name != nil || c.Contacts == nil || len(c.Contacts) != 0 || c.ResponseTypes == nil || len(c.ResponseTypes) != 0 || c.ApplicationType != nil || *c.SubjectType != "pairwise" {
				t.Fatal("the refresh did not replace the document fields", created, c)
			}
			if !*c.Disabled || !*c.SkipConsent || !*c.EnableEndSession || !*c.RequirePKCE || !slices.Equal(c.ClientCredentialsScopes, []string{"machine"}) || !c.CreatedAt.Equal(t0) || !c.UpdatedAt.Equal(t1) {
				t.Fatal("the refresh changed a server-owned field", c.Disabled, c.SkipConsent, c.EnableEndSession, c.RequirePKCE, c.ClientCredentialsScopes, c.CreatedAt, c.UpdatedAt)
			}
			for _, resource := range []string{"urn:default", "urn:new"} {
				if n := count(`SELECT COUNT(*) FROM "oauthClientResource" WHERE "clientId"=? AND "resourceId"=?`, id, resource); n != 1 {
					t.Fatal("a default resource was not linked exactly once", resource, n)
				}
			}
			// A stated subject type changes the stored one.
			refresh.Metadata.SubjectType = "public"
			c, _, err = s.SaveDiscoveredClient(ctx, refresh)
			must(err)
			if *c.SubjectType != "public" {
				t.Fatal("a stated subject type was not stored", *c.SubjectType)
			}
			// A missing or disabled default resource writes nothing.
			for _, resource := range []string{"urn:missing", "urn:off"} {
				bad := record
				bad.ClientID, bad.ID, bad.Metadata.Resources = "https://bad.example.test/client.json", "row-bad", []string{resource}
				_, _, err = s.SaveDiscoveredClient(ctx, bad)
				var oauthErr *auth.OAuthError
				if !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_target" {
					t.Fatal("a bad default resource was accepted", resource, err)
				}
				if n := count(`SELECT COUNT(*) FROM "oauthClient" WHERE "clientId"=?`, bad.ClientID); n != 0 {
					t.Fatal("a refused save wrote a client", n)
				}
			}
			// A refresh of a deleted row is refused.
			write(`DELETE FROM "oauthClient" WHERE "clientId"=?`, id)
			_, _, err = s.SaveDiscoveredClient(ctx, refresh)
			refused(err, "invalid_client", "client no longer exists")
			if _, _, err := s.SaveDiscoveredClient(ctx, op.DiscoveredClientRecord{ClientID: id}); err == nil {
				t.Fatal("a save without a discovery ID was accepted")
			}
			// Concurrent first saves through two pools converge on one row.
			peer, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { peer.Close() })
			const racer = "https://race.example.test/client.json"
			var wg sync.WaitGroup
			results := make([]bool, 4)
			errs := make([]error, 4)
			for i := range 4 {
				store := s
				if i%2 == 1 {
					store = peer
				}
				wg.Go(func() {
					first := record
					// No default resource, whose lock would serialize the saves.
					first.ClientID, first.ID, first.Metadata.Resources, first.Metadata.ApplicationType = racer, "race-"+string(rune('a'+i)), nil, ""
					_, results[i], errs[i] = store.SaveDiscoveredClient(ctx, first)
				})
			}
			wg.Wait()
			createdCount := 0
			for i := range 4 {
				must(errs[i])
				if results[i] {
					createdCount++
				}
			}
			if n := count(`SELECT COUNT(*) FROM "oauthClient" WHERE "clientId"=?`, racer); n != 1 || createdCount != 1 {
				t.Fatal("concurrent first saves did not converge", n, createdCount)
			}
			if raced, err := s.LookupDiscoveredClient(ctx, racer); err != nil || raced.ApplicationType != nil {
				t.Fatal("an empty application type was stored", raced.ApplicationType, err)
			}
		})
	}
}
