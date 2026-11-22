package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/scim"
	"github.com/Plain-Auth/plain-auth/schema"
)

// Pauses after managed bearer verification but before SQL provisioning starts.
type delayedDirectory struct {
	*Store
	entered, release chan struct{}
}

func (s *delayedDirectory) SCIMCreate(ctx context.Context, d scim.Directory, p scim.Profile) (scim.Record, error) {
	close(s.entered)
	<-s.release
	return s.Store.SCIMCreate(ctx, d, p)
}

func TestSCIMManagedCredentials(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			base, e := schema.Generate(dialect, []string{"scim"})
			must(e)
			before, e := OpenWithSchema(ctx, dialect, dsn, base)
			must(e)
			ex := auth.User{ID: "preserved", Email: "keep@example.test", Name: "existing", CreatedAt: time.Now(), UpdatedAt: time.Now()}
			must(before.CreateUser(ctx, ex, "fixture", nil))
			must(before.Close())
			ddl, e := schema.Generate(dialect, []string{"scim-managed"})
			must(e)
			a, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer a.Close()
			b, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer b.Close()
			_, e = a.FindAccountUser(ctx, ex.Email)
			must(e)
			build := func(s *Store, st scim.Store, secret string) *scim.Handler {
				h, e := auth.New(auth.Options{Store: s, Secret: strings.Repeat("x", 32), BaseURL: "https://catalog.test", BasePath: "/identity/custom"})
				must(e)
				d, e := scim.New(h, scim.Options{Store: st, Managed: &scim.ManagedOptions{CredentialHashSecret: secret, MaxActiveCredentials: 2}})
				must(e)
				return d
			}
			secret := strings.Repeat("managed-local-key-", 3)
			one, two := build(a, a, secret), build(b, b, secret)
			catalog, other := one.Catalog(), two.Catalog()
			policy := scim.CredentialPolicy{Scopes: []string{scim.UsersRead, scim.UsersWrite}, ExpiresAt: time.Now().Add(time.Hour)}
			for _, p := range []scim.CredentialPolicy{{Scopes: []string{scim.UsersRead}}, {Scopes: []string{scim.UsersRead}, ExpiresAt: time.Now().Add(-time.Minute)}, {Scopes: []string{}, ExpiresAt: policy.ExpiresAt}, {Scopes: []string{scim.UsersRead, scim.UsersRead}, ExpiresAt: policy.ExpiresAt}} {
				if _, e := catalog.Create(ctx, "Domain", "invalid-policy-0001", "actor", p); e == nil {
					t.Fatal("invalid issuance")
				}
			}
			call := func(h http.Handler, method, path, token string, body map[string]any, status int) {
				t.Helper()
				w := scimRequest(h, method, path, token, body)
				if w.Code != status {
					t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
				}
			}
			start := make(chan struct{})
			type result struct {
				issued scim.IssuedCredential
				err    error
			}
			res := make(chan result, 4)
			for _, c := range []*scim.Catalog{catalog, other} {
				go func() {
					<-start
					i, e := c.Create(ctx, "Domain", "create-correlation-001", "owner", policy)
					res <- result{i, e}
				}()
			}
			close(start)
			var i scim.IssuedCredential
			wins := 0
			for range 2 {
				r := <-res
				if r.err == nil {
					wins++
					i = r.issued
				} else if !errors.Is(r.err, scim.ErrCreationRequestConflict) || r.issued.Token != "" {
					t.Fatal("duplicate create", r.err)
				}
			}
			if wins != 1 {
				t.Fatal(wins)
			}
			d := scim.Directory{ID: i.Connection.ConnectionID, ProvisioningDomainID: "Domain"}
			foreign := d
			foreign.ProvisioningDomainID = "domain"
			ls, e := other.List(ctx, "Domain")
			must(e)
			if len(ls) != 1 || ls[0].ConnectionID != d.ID {
				t.Fatal(ls)
			}
			ls, e = other.List(ctx, "domain")
			must(e)
			if len(ls) != 0 {
				t.Fatal("directory leak")
			}
			if _, e = other.Get(ctx, foreign); !errors.Is(e, scim.ErrManagedNotFound) {
				t.Fatal(e)
			}
			if _, e = other.Rotate(ctx, foreign, "other", policy); !errors.Is(e, scim.ErrManagedNotFound) {
				t.Fatal(e)
			}
			if _, e = other.Revoke(ctx, foreign, i.Credential.CredentialID, "other"); !errors.Is(e, scim.ErrManagedNotFound) {
				t.Fatal(e)
			}
			if _, e = other.Events(ctx, foreign, scim.EventQuery{}); !errors.Is(e, scim.ErrManagedNotFound) {
				t.Fatal(e)
			}
			state, e := other.Get(ctx, d)
			must(e)
			if len(state.Credentials) != 1 || state.Credentials[0].LastUsedAt != nil {
				t.Fatalf("%+v", state)
			}
			var stored string
			must(a.db.QueryRowContext(ctx, a.bind(`SELECT "tokenDigest" FROM "scimManagedCredential" WHERE "credentialId"=?`), i.Credential.CredentialID).Scan(&stored))
			if stored == i.Token || strings.Contains(stored, i.Credential.CredentialID) || len(stored) != 43 {
				t.Fatal("unexpected persisted digest")
			}
			public, e := json.Marshal(state)
			must(e)
			if strings.Contains(string(public), stored) || strings.Contains(string(public), i.Token) {
				t.Fatal("secret in public state")
			}
			call(two, "GET", "Users", i.Token+"bad", nil, 401)
			call(build(b, b, strings.Repeat("k", 32)), "GET", "Users", i.Token, nil, 401)
			call(two, "GET", "Groups", i.Token, nil, 403)
			call(two, "GET", "Users", i.Token, nil, 200)
			state, e = other.Get(ctx, d)
			must(e)
			last := state.Credentials[0].LastUsedAt
			if last == nil {
				t.Fatal("no last-use timestamp")
			}
			call(one, "GET", "Users", i.Token, nil, 200)
			state, e = other.Get(ctx, d)
			must(e)
			if !state.Credentials[0].LastUsedAt.Equal(*last) {
				t.Fatal("did not throttle last-use update")
			}
			start = make(chan struct{})
			for j := range 4 {
				c := []*scim.Catalog{catalog, other}[j%2]
				go func() { <-start; i, e := c.Rotate(ctx, d, "operator", policy); res <- result{i, e} }()
			}
			close(start)
			wins = 0
			var rotated scim.IssuedCredential
			for range 4 {
				r := <-res
				if r.err == nil {
					wins++
					rotated = r.issued
				} else if !errors.Is(r.err, scim.ErrManagedConflict) {
					t.Fatal(r.err)
				}
			}
			if wins != 1 {
				t.Fatal("rotation cap", wins)
			}
			call(one, "GET", "Users", i.Token, nil, 200)
			call(two, "GET", "Users", rotated.Token, nil, 200)
			paused := &delayedDirectory{Store: b, entered: make(chan struct{}), release: make(chan struct{})}
			delayed := build(b, paused, secret)
			finished := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				finished <- scimRequest(delayed, "POST", "Users", i.Token, map[string]any{"schemas": []string{scim.UserSchema}, "userName": "should-not-exist@example.test"})
			}()
			<-paused.entered
			_, e = catalog.Revoke(ctx, d, i.Credential.CredentialID, "admin")
			must(e)
			close(paused.release)
			if w := <-finished; w.Code != 401 {
				t.Fatalf("revoked in-flight request: %d %s", w.Code, w.Body.String())
			}
			if _, e = a.FindAccountUser(ctx, "should-not-exist@example.test"); !errors.Is(e, auth.ErrNotFound) {
				t.Fatal(e)
			}
			_, e = other.Revoke(ctx, d, i.Credential.CredentialID, "another")
			must(e)
			call(two, "GET", "Users", i.Token, nil, 401)
			fast, e := catalog.Rotate(ctx, d, "operator", policy)
			must(e)
			_, e = a.db.ExecContext(ctx, a.bind(`UPDATE "scimManagedCredential" SET "expiresAt"=? WHERE "credentialId"=?`), a.date(time.Now().Add(-time.Second)), fast.Credential.CredentialID)
			must(e)
			call(two, "GET", "Users", fast.Token, nil, 401)
			next, e := other.Rotate(ctx, d, "operator", policy)
			must(e)
			call(one, "GET", "Users", next.Token, nil, 200)
			state, e = other.Get(ctx, d)
			must(e)
			statuses := map[string]string{}
			for _, cred := range state.Credentials {
				statuses[cred.CredentialID] = cred.Status
			}
			if statuses[i.Credential.CredentialID] != "revoked" || statuses[fast.Credential.CredentialID] != "expired" || statuses[next.Credential.CredentialID] != "active" {
				t.Fatal(statuses)
			}
			log, e := other.Events(ctx, d, scim.EventQuery{})
			must(e)
			types := []string{}
			for j, v := range log.Events {
				if v.Sequence != j+1 {
					t.Fatal("non-contiguous audit")
				}
				types = append(types, v.Type)
			}
			if !slices.Equal(types, []string{"connection.created", "credential.issued", "credential.rotated", "credential.revoked", "credential.rotated", "credential.rotated"}) {
				t.Fatal(types)
			}
			page, e := catalog.Events(ctx, d, scim.EventQuery{Limit: 2, Offset: 1})
			must(e)
			if page.Total != 6 || page.Events[0].Sequence != 4 || page.Events[1].Sequence != 5 {
				t.Fatal(page)
			}
			for _, dir := range []string{"asc", "desc"} {
				page, e = catalog.Events(ctx, d, scim.EventQuery{Limit: 2, SortDirection: dir})
				must(e)
				if dir == "asc" && page.Events[0].Sequence != 1 || dir == "desc" && page.Events[0].Sequence != 6 {
					t.Fatal(page)
				}
			}
			call(one, "POST", "createSCIMManagedConnection", next.Token, nil, 404)
		})
	}
}
