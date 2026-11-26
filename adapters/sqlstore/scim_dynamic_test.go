package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

type directoryObserver struct {
	*Store
	identity chan scim.Principal
}

func (o *directoryObserver) SCIMGet(ctx context.Context, d scim.Directory, id string) (scim.Record, error) {
	p, ok := scim.PrincipalFromContext(ctx)
	if !ok || p.Directory != d {
		return scim.Record{}, errors.New("missing directory principal")
	}
	o.identity <- p
	return o.Store.SCIMGet(ctx, d, id)
}
func TestSCIMDynamicBearer(t *testing.T) {
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
			ddl, e := schema.Generate(dialect, []string{"scim"})
			must(e)
			first, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer first.Close()
			second, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer second.Close()
			_, e = first.db.ExecContext(ctx, first.bind(`CREATE TABLE "appDirectoryCredentials" ("digest" varchar(64) PRIMARY KEY,"claims" text NOT NULL)`))
			must(e)
			digest := func(token string) string { x := sha256.Sum256([]byte(token)); return hex.EncodeToString(x[:]) }
			storeClaims := func(token string, v scim.BearerVerification) {
				payload, e := json.Marshal(v)
				must(e)
				_, e = first.db.ExecContext(ctx, first.bind(`INSERT INTO "appDirectoryCredentials" ("digest","claims") VALUES (?,?)`), digest(token), string(payload))
				must(e)
			}
			future := time.Now().UTC().Add(time.Hour)
			claims := func(id, domain string, scopes ...string) scim.BearerVerification {
				return scim.BearerVerification{Connection: &scim.Directory{ID: id, ProvisioningDomainID: domain}, CredentialID: "issuer-creds", Scopes: scopes, ExpiresAt: future}
			}
			good := claims("runtime", "tenant", scim.UsersRead, scim.UsersWrite)
			storeClaims("active", good)
			stale := claims("expired", "tenant", scim.UsersWrite)
			stale.ExpiresAt = time.Now().Add(-time.Minute)
			storeClaims("stale", stale)
			declared := scim.BearerVerification{ConnectionID: "declared", CredentialID: "external", Scopes: []string{scim.UsersRead}}
			storeClaims("declared", declared)
			storeClaims("case-other", claims("RUNTIME", "tenant", scim.UsersRead, scim.UsersWrite))
			storeClaims("read", claims("readonly", "tenant", scim.UsersRead))
			storeClaims("collision", claims("declared", "else", scim.UsersRead))
			storeClaims("reserved", claims("ba_scim_connection_a", "tenant", scim.UsersRead))
			storeClaims("bad-domain", claims("bad", "", scim.UsersRead))
			bad := good
			bad.ConnectionID = "declared"
			storeClaims("ambiguous", bad)
			bad = declared
			bad.ConnectionID = "undeclared"
			storeClaims("unknown-conn", bad)
			bad = good
			bad.CredentialID = " "
			storeClaims("bad-id", bad)
			bad = good
			bad.Scopes = []string{scim.UsersRead, scim.UsersRead}
			storeClaims("duplicate", bad)
			bad.Scopes = []string{"unknown"}
			storeClaims("bad-scope", bad)
			bad.Scopes = nil
			storeClaims("absent-scopes", bad)
			storeClaims("remap", claims("runtime", "moved", scim.UsersRead))
			storeClaims("ba_scim_credential_fixture.fallback", good)
			storeClaims("padded-conn", claims(" runtime", "tenant", scim.UsersRead))
			storeClaims("long-conn", claims(strings.Repeat("r", 256), "tenant", scim.UsersRead))
			var calls atomic.Int64
			var itemPath atomic.Bool
			principals := make(chan scim.Principal, 12)
			build := func(db *Store, connections []scim.Connection) *scim.Handler {
				host, e := auth.New(auth.Options{BaseURL: "https://directory.test", BasePath: "/identity/custom", Secret: strings.Repeat("s", 32), Store: db})
				must(e)
				h, e := scim.New(host, scim.Options{Store: &directoryObserver{db, principals}, Connections: connections, VerifyBearerToken: func(ctx context.Context, in scim.BearerInput) (*scim.BearerVerification, error) {
					calls.Add(1)
					if in.Method == "GET" && in.Path == "/scim/v2/Users/:userId" {
						itemPath.Store(true)
					}
					if in.Headers.Get("Authorization") != "Bearer "+in.Token {
						return nil, errors.New("missing header")
					}
					in.Headers.Del("Authorization")
					if in.Token == "outage" {
						return nil, &scim.Error{Status: 418, Detail: "private verifier diagnostic"}
					}
					var count int
					if e := db.db.QueryRowContext(ctx, db.bind(`SELECT count(*) FROM "appDirectoryCredentials" WHERE "digest"=?`), digest(in.Token)).Scan(&count); e != nil || count == 0 {
						return nil, e
					}
					var raw string
					if e := db.db.QueryRowContext(ctx, db.bind(`SELECT "claims" FROM "appDirectoryCredentials" WHERE "digest"=?`), digest(in.Token)).Scan(&raw); e != nil {
						return nil, e
					}
					var v scim.BearerVerification
					e := json.Unmarshal([]byte(raw), &v)
					return &v, e
				}})
				must(e)
				return h
			}
			connections := []scim.Connection{{Directory: scim.Directory{ID: "declared", ProvisioningDomainID: "assigned"}}, {Directory: scim.Directory{ID: "static"}, Credentials: []scim.Credential{{ID: "key", Token: "static"},
				{ID: "scoped", Token: "scoped-static", Scopes: []string{scim.UsersRead}, ExpiresAt: future}}}}
			a, b := build(first, connections), build(second, connections)
			only := build(second, nil)
			call := func(h http.Handler, method, path, token string, body map[string]any, status int) map[string]any {
				t.Helper()
				w := scimRequest(h, method, path, token, body)
				if w.Code != status || strings.Contains(w.Body.String(), "private verifier diagnostic") {
					t.Fatalf("%s %s %d: %s", method, path, w.Code, w.Body.String())
				}
				if status == 401 && w.Header().Get("WWW-Authenticate") != `Bearer realm="SCIM"` {
					t.Fatal("missing challenge")
				}
				var v map[string]any
				must(json.Unmarshal(w.Body.Bytes(), &v))
				return v
			}
			call(a, "GET", "Users", "static", nil, 200)
			call(a, "GET", "Users", "ba_scim_credential_fixture.fallback", nil, 401)
			if n := calls.Load(); n != 0 {
				t.Fatal("called verifier for static or reserved token", n)
			}
			for _, token := range []string{"stale", "collision", "reserved", "unknown-conn", "bad-domain", "ambiguous", "bad-id", "duplicate", "bad-scope", "absent-scopes", "unknown", "padded-conn", "long-conn"} {
				call(a, "GET", "Users", token, nil, 401)
			}
			call(a, "GET", "Users", "outage", nil, 500)
			if w := scimRequest(a, "GET", "Users", "outage", nil); w.Header().Get("WWW-Authenticate") != "" {
				t.Fatal("a failing verifier answered with a bearer challenge", w.Header())
			}
			// Without a verifier only code-defined tokens authenticate.
			staticHost, e := auth.New(auth.Options{BaseURL: "https://directory.test", BasePath: "/identity/custom", Secret: strings.Repeat("s", 32), Store: first})
			must(e)
			staticOnly, e := scim.New(staticHost, scim.Options{Store: first, Connections: connections[1:]})
			must(e)
			if w := scimRequest(staticOnly, "GET", "Users", "active", nil); w.Code != 401 {
				t.Fatal("a token without a verifier was accepted", w.Code)
			}
			call(a, "POST", "Users", "read", nil, 403)
			var n int
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "scimConnectionBinding"`)).Scan(&n))
			if n != 1 {
				t.Fatal("rejected credentials created bindings", n)
			}
			call(a, "GET", "Users/absent", "declared", nil, 404)
			p := <-principals
			if p.Kind != "oauth-bearer" || p.ID != "declared" || p.ProvisioningDomainID != "assigned" || p.CredentialID != "external" || !p.ExpiresAt.IsZero() {
				t.Fatal("the declared principal lacks its directory or carries an expiry it was not given", p)
			}
			call(a, "GET", "Users/absent", "static", nil, 404)
			p = <-principals
			if p.Kind != "static-bearer" || p.CredentialID != "key" || p.ID != "static" || p.ProvisioningDomainID != "static" || len(p.Scopes) != 4 || !p.ExpiresAt.IsZero() {
				t.Fatal("the static principal lacks its directory, domain, scopes or expiry", p)
			}
			call(a, "GET", "Users/absent", "scoped-static", nil, 404)
			if p = <-principals; p.CredentialID != "scoped" || !slices.Equal(p.Scopes, []string{scim.UsersRead}) || !p.ExpiresAt.Equal(future) {
				t.Fatal("a scoped, expiring static credential lost its scopes or expiry", p)
			}
			start := make(chan struct{})
			statuses := make(chan *httptest.ResponseRecorder, 2)
			for _, h := range []*scim.Handler{a, only} {
				go func() { <-start; statuses <- scimRequest(h, "GET", "Users", "active", nil) }()
			}
			close(start)
			for range 2 {
				if w := <-statuses; w.Code != 200 {
					t.Fatalf("parallel first use %d %s", w.Code, w.Body.String())
				}
			}
			makeUser := func(name string) map[string]any {
				return map[string]any{"schemas": []string{scim.UserSchema}, "userName": name + "@example.test", "externalId": "same-id"}
			}
			id := call(a, "POST", "Users", "active", makeUser("first"), 201)["id"].(string)
			call(b, "POST", "Users", "case-other", makeUser("other"), 201)
			call(b, "GET", "Users/"+id, "case-other", nil, 404)
			<-principals
			call(b, "GET", "Users/"+id, "active", nil, 200)
			p = <-principals
			if !itemPath.Load() || p.Kind != "oauth-bearer" || p.ProvisioningDomainID != "tenant" || p.CredentialID != good.CredentialID || p.ID != good.Connection.ID || !p.ExpiresAt.Equal(future) || !slices.Equal(p.Scopes, good.Scopes) {
				t.Fatal("scoped request identity", p)
			}
			call(a, "GET", "Users", "remap", nil, 409)
			_, e = first.db.ExecContext(ctx, first.bind(`DELETE FROM "appDirectoryCredentials" WHERE "digest"=?`), digest("active"))
			must(e)
			call(b, "GET", "Users", "active", nil, 401)
			call(a, "GET", "Users", "active", nil, 401)
			storeClaims("restored", good)
			_, e = first.db.ExecContext(ctx, first.bind(`UPDATE "scimConnectionBinding" SET "decommissionStatus"='complete' WHERE "connectionKey"=?`), scimKey("scim-connection", "runtime"))
			must(e)
			call(b, "GET", "Users", "restored", nil, 401)
		})
	}
}
