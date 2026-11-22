package sqlstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/schema"
)

func fixtureSessionFields() map[string]auth.SessionField {
	return map[string]auth.SessionField{
		"label":        {Type: auth.FieldString, Column: "display_label", Default: "en", Required: true},
		"attempts":     {Type: auth.FieldNumber, Default: 7},
		"flag":         {Type: auth.FieldBoolean},
		"deviceClass":  {Type: auth.FieldString, ServerOnly: true, Default: "standard"},
		"internalNote": {Type: auth.FieldString, Hidden: true},
		"internalRisk": {Type: auth.FieldNumber, Hidden: true, ServerOnly: true, Default: 2},
	}
}

func TestConfiguredSessionFieldsAcrossStores(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := fixtureSessionFields()
			var store, peer auth.Store
			if dialect == "memory" {
				store = memory.New()
				peer = store
			} else {
				dsn := organizationTestDSN(t, dialect)
				open := func() auth.Store {
					t.Helper()
					s, e := OpenWithSessionFields(ctx, dialect, dsn, nil, fields)
					if e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { s.Close() })
					return s
				}
				store, peer = open(), open()
			}
			opts := auth.Options{Store: store, Secret: strings.Repeat("s", 40), EmailAndPassword: true, SessionAdditionalFields: fields}
			server := httptest.NewUnstartedServer(nil)
			opts.BaseURL = "http://" + server.Listener.Addr().String()
			a, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = a
			server.Start()
			defer server.Close()
			opts.Store = peer
			b, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.New(opts.BaseURL, &http.Client{})
			if err != nil {
				t.Fatal(err)
			}
			before := func(data auth.Session, name string, want any) {
				t.Helper()
				v, ok := data.AdditionalField(name)
				if !ok || v != want {
					t.Fatalf("public field %s: %v %t, want %v", name, v, ok, want)
				}
			}
			absent := func(data auth.Session, name string) {
				t.Helper()
				if _, ok := data.AdditionalField(name); ok {
					t.Fatalf("returned hidden or physical field %s", name)
				}
			}
			result, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@fields.example.test", Password: "fixture scalar fields"})
			if err != nil {
				t.Fatal(err)
			}
			if result.Token == nil {
				t.Fatal("signup returned no session")
			}
			id := result.User.ID
			h := http.Header{"Cookie": {a.SessionCookie(*result.Token, true).String()}}
			one, err := c.GetSession(ctx)
			if err != nil || one == nil {
				t.Fatal(err)
			}
			before(one.Session, "label", "en")
			before(one.Session, "attempts", int64(7))
			before(one.Session, "flag", nil)
			before(one.Session, "deviceClass", "standard")
			absent(one.Session, "internalNote")
			absent(one.Session, "internalRisk")
			absent(one.Session, "display_label")
			updated, err := c.UpdateSession(ctx, map[string]any{"label": "fr", "attempts": 9, "flag": false, "internalNote": "host-readable", "userId": "another"})
			if err != nil {
				t.Fatal(err)
			}
			if updated.UserID != id || updated.Token != *result.Token {
				t.Fatal("additional fields changed the session authority")
			}
			before(*updated, "label", "fr")
			before(*updated, "flag", false)
			absent(*updated, "internalNote")
			stored, err := b.GetSession(ctx, h)
			if err != nil {
				t.Fatal(err)
			}
			before(stored.Session, "attempts", int64(9))
			for _, patch := range []map[string]any{{"deviceClass": "unowned"}, {"internalRisk": false}, {"label": "should never persist", "internalRisk": nil}, {"label": nil}, {"attempts": 1.5}, {"attempts": json.Number("1.00000000000000001")}, {"flag": "true"}, {"id": id}} {
				_, err := c.UpdateSession(ctx, patch)
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != 400 {
					t.Fatalf("invalid patch %v: %v", patch, err)
				}
			}
			unchanged, err := b.GetSession(ctx, h)
			if err != nil || unchanged == nil {
				t.Fatal(err)
			}
			before(unchanged.Session, "label", "fr")
			for _, change := range []func(*auth.Session){
				func(v *auth.Session) { v.ID += "x" },
				func(v *auth.Session) { v.UserID += "x" },
				func(v *auth.Session) { v.CredentialType = "application" },
				func(v *auth.Session) { v.ImpersonatedBy = &id },
			} {
				actor := unchanged.Session
				change(&actor)
				err := peer.(auth.SessionFieldStore).UpdateSessionFields(ctx, actor, fields, map[string]any{"label": "forged"}, time.Now())
				if !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("incorrect field update authority", err)
				}
			}
			// A host-controlled test fixture can set a declared server-only value.
			now := time.Now().UTC().Truncate(time.Millisecond)
			candidate := auth.StoredSession{Session: auth.Session{ID: "trusted-session", Token: "second-token", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			trusted, err := b.WithTrustedSessionFields(candidate, map[string]any{"deviceClass": "host-defined", "internalRisk": 12})
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.CreateSession(ctx, trusted); err != nil {
				t.Fatal(err)
			}
			h2 := http.Header{"Cookie": {a.SessionCookie(candidate.Token, true).String()}}
			other, err := a.GetSession(ctx, h2)
			if err != nil {
				t.Fatal(err)
			}
			before(other.Session, "deviceClass", "host-defined")
			absent(other.Session, "internalRisk")
			sessions, err := c.ListSessions(ctx)
			if err != nil || len(sessions) != 2 {
				t.Fatal("listed sessions", len(sessions), err)
			}
			for _, row := range sessions {
				if row.Token == candidate.Token {
					before(row, "deviceClass", "host-defined")
				} else {
					before(row, "label", "fr")
				}
				absent(row, "internalRisk")
			}

			if _, err := a.WithTrustedSessionFields(candidate, map[string]any{"activeOrganizationId": "foreign"}); err == nil {
				t.Fatal("trusted override set undeclared authority")
			}
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			for i, node := range []*auth.Auth{a, b} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					patch := []map[string]any{{"label": "parallel"}, {"attempts": 11}}[i]
					_, err := node.UpdateSession(ctx, h, patch)
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := b.GetSession(ctx, h)
			if err != nil {
				t.Fatal(err)
			}
			before(got.Session, "label", "parallel")
			before(got.Session, "attempts", int64(11))
			// An independently mounted node with no field configuration releases no custom values.
			opts.SessionAdditionalFields = nil
			bare, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			base, err := bare.GetSession(ctx, h)
			if err != nil {
				t.Fatal(err)
			}
			absent(base.Session, "label")
			withoutFields, err := bare.WithTrustedSessionFields(trusted, nil)
			if err != nil {
				t.Fatal(err)
			}
			gotFields, err := withoutFields.PhysicalSessionFields()
			if err != nil || len(gotFields) != 0 {
				t.Fatal("host trusted preparation retained another instance's private fields", err)
			}
			if err := peer.DeleteSession(ctx, *result.Token); err != nil {
				t.Fatal(err)
			}
			_, err = c.UpdateSession(ctx, map[string]any{"label": "stale"})
			var denied *auth.APIError
			if !errors.As(err, &denied) || denied.Status != 401 {
				t.Fatal("revoked session accepted an update", err)
			}
		})
	}
}

func TestConfiguredSessionFieldMigrations(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			s, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			node, err := auth.New(auth.Options{Store: s, BaseURL: "https://local.example", Secret: strings.Repeat("s", 40), EmailAndPassword: true})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := node.SignUpEmail(ctx, auth.SignUpInput{Name: "Legacy", Email: "legacy@fields.test", Password: "local migration pass"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			const original = "owner's team, café; west\\east"
			fields := map[string]auth.SessionField{"region": {Type: auth.FieldString, Default: original, Required: true}, "counter": {Type: auth.FieldNumber, Default: 5}, "active": {Type: auth.FieldBoolean, Default: false}, "optional": {Type: auth.FieldString}}
			if reject, err := OpenWithSessionFields(ctx, dialect, dsn, nil, map[string]auth.SessionField{"missing": {Type: auth.FieldString, Required: true}}); err == nil {
				reject.Close()
				t.Fatal("populated sessions accepted an undefined mandatory backfill")
			}
			for range 2 {
				opened, err := OpenWithSessionFields(ctx, dialect, dsn, nil, fields)
				if err != nil {
					t.Fatal(err)
				}
				opened.Close()
			}
			var region string
			var count int
			var flag bool
			var optional *string
			err = s.db.QueryRowContext(ctx, s.bind(`SELECT "region","counter","active","optional" FROM "session" WHERE "token"=?`), seed.Token).Scan(&region, &count, &flag, &optional)
			if err != nil || region != original || count != 5 || flag || optional != nil {
				t.Fatal("backfill", region, count, flag, optional, err)
			}
			if err := s.ValidateSessionFields(map[string]auth.SessionField{"region": {Type: auth.FieldNumber}}); err == nil {
				t.Fatal("incorrect physical type was accepted")
			}
			generated := `ALTER TABLE "session" ADD COLUMN "computedField" INTEGER GENERATED ALWAYS AS (1) VIRTUAL`
			if dialect == "postgres" {
				generated = `ALTER TABLE "session" ADD COLUMN "computedField" INTEGER GENERATED ALWAYS AS (1) STORED`
			}
			if _, err := s.db.ExecContext(ctx, s.bind(generated)); err != nil {
				t.Fatal(err)
			}
			badColumns := map[string]auth.SessionField{"addedFirst": {Type: auth.FieldString}, "computedField": {Type: auth.FieldNumber}}
			if opened, err := OpenWithSessionFields(ctx, dialect, dsn, nil, badColumns); err == nil {
				opened.Close()
				t.Fatal("application-owned field accepted a generated column")
			}
			if columns, err := s.sessionColumnCatalog(ctx, s.db); err != nil || columns["addedfirst"].name != "" {
				t.Fatal("failed preflight partially migrated the schema", err)
			}
			for _, bad := range []map[string]auth.SessionField{{"token": {Type: auth.FieldString}}, {"field": {Type: auth.FieldString, Column: "USERID"}}, {"x": {Type: auth.FieldNumber, Default: "bad"}}, {"x": {Type: auth.FieldBoolean}, "X": {Type: auth.FieldBoolean}}} {
				if _, err := schema.GenerateWithSessionFields(dialect, nil, bad); err == nil {
					t.Fatal("accepted conflicting fields", fmt.Sprint(bad))
				}
			}
		})
	}
}

func TestConfiguredSessionFieldAuthorizationAfterMigration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			fields := map[string]auth.SessionField{"label": {Type: auth.FieldString}}
			cold, err := OpenWithSessionFields(ctx, dialect, dsn, nil, fields)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Close()
			const origin = "https://store.example.test"
			opts := auth.Options{Store: cold, BaseURL: origin, Secret: strings.Repeat("s", 40), EmailAndPassword: true, SessionAdditionalFields: fields}
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := node.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: "owner@store.example.test", Password: "local test passphrase"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			h := http.Header{"Cookie": {node.SessionCookie(owner.Token, true).String()}}
			current, err := node.GetSession(ctx, h)
			if err != nil || current == nil {
				t.Fatal(err)
			}
			admin, err := OpenWithSessionFields(ctx, dialect, dsn, []string{"admin"}, fields)
			if err != nil {
				t.Fatal(err)
			}
			defer admin.Close()
			write := func(query string, args ...any) {
				t.Helper()
				if _, err := admin.db.ExecContext(ctx, admin.bind(query), args...); err != nil {
					t.Fatal(err)
				}
			}
			deny := func() {
				t.Helper()
				if _, err := node.UpdateSession(ctx, h, map[string]any{"label": "disallowed"}); err == nil {
					t.Fatal("restricted session mutated through a cold node")
				}
				err := cold.UpdateSessionFields(ctx, current.Session, fields, map[string]any{"label": "disallowed"}, time.Now())
				if err == nil {
					t.Fatal("restricted session mutated through direct SQL API")
				}
				var stored *string
				if err := admin.db.QueryRowContext(ctx, admin.bind(`SELECT "label" FROM "session" WHERE "id"=?`), current.Session.ID).Scan(&stored); err != nil || stored != nil {
					t.Fatal("restricted update persisted data", err)
				}
			}
			write(`UPDATE "session" SET "impersonatedBy"=? WHERE "id"=?`, "operator", current.Session.ID)
			deny()
			write(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "id"=?`, current.Session.ID)
			write(`UPDATE "user" SET "banned"=? WHERE "id"=?`, true, owner.User.ID)
			deny()
		})
	}
}

func TestConfiguredSessionFieldsRequireLiveProjection(t *testing.T) {
	for _, strategy := range []auth.SessionCookieCacheStrategy{auth.SessionCacheCompact, auth.SessionCacheJWT, auth.SessionCacheJWE} {
		t.Run(string(strategy), func(t *testing.T) {
			ctx := t.Context()
			fields := map[string]auth.SessionField{"label": {Type: auth.FieldString}}
			store, err := OpenWithSessionFields(ctx, "sqlite", organizationTestDSN(t, "sqlite"), nil, fields)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			const origin = "https://cache.example.test"
			opts := auth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("s", 40), EmailAndPassword: true, DeferSessionRefresh: true, SessionCookieCache: &auth.SessionCookieCacheOptions{Strategy: strategy}}
			plain, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			opts.SessionAdditionalFields = fields
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			call := func(server *auth.Auth, method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, origin+"/api/auth/"+path, strings.NewReader(body))
				if method == "POST" {
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Origin", origin)
				}
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				server.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("%s %s returned %d", method, path, w.Code)
				}
				return w
			}
			signup := call(plain, "POST", "sign-up/email", `{"name":"Before","email":"cache@fields.test","password":"local cache fixture"}`, nil)
			cookies := signup.Result().Cookies()
			hasCache := false
			for _, c := range cookies {
				hasCache = hasCache || strings.HasSuffix(c.Name, ".session_data") && c.Value != ""
			}
			if !hasCache {
				t.Fatal("expected a valid signed session snapshot")
			}
			var raw auth.AuthResult
			if err := json.Unmarshal(signup.Body.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			if _, err = store.db.ExecContext(ctx, `UPDATE "session" SET "label"='live' WHERE "token"=?`, raw.Token); err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{"GET", "POST"} {
				for _, query := range []string{"", "?disableCookieCache=true"} {
					w := call(node, method, "get-session"+query, "", cookies)
					var view auth.SessionResult
					if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
						t.Fatal(err)
					}
					if v, ok := view.Session.AdditionalField("label"); !ok || v != "live" {
						t.Fatal("configured view consumed a stale or partial snapshot", method, query)
					}
				}
			}
			if err := store.DeleteSession(ctx, raw.Token); err != nil {
				t.Fatal(err)
			}
			w := call(node, "GET", "get-session", "", cookies)
			if strings.TrimSpace(w.Body.String()) != "null" {
				t.Fatal("configured view returned a revoked cached login")
			}
		})
	}
}

func TestRequiredSessionFieldOnFirstLogin(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := map[string]auth.SessionField{"hostSubject": {Type: auth.FieldString, Required: true, ServerOnly: true}}
			var store auth.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				s, err := OpenWithSessionFields(ctx, dialect, organizationTestDSN(t, dialect), nil, fields)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				store = s
			}
			opts := auth.Options{Store: store, Secret: strings.Repeat("r", 40), BaseURL: "https://example.test", EmailAndPassword: true, SessionAdditionalFields: fields}
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			input := auth.SignUpInput{Name: "New", Email: "required@fields.test", Password: "local first login"}
			if _, err := node.SignUpEmail(ctx, input, auth.RequestMeta{}); err == nil {
				t.Fatal("missing required field created a login")
			}
			if _, _, err := store.Credential(ctx, input.Email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("failed first session left a credential behind", err)
			}
			opts.DisableAutoSignIn = true
			node, err = auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := node.SignUpEmail(ctx, input, auth.RequestMeta{})
			if err != nil || owner.Token != "" {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			prepared, err := node.WithTrustedSessionFields(auth.StoredSession{Session: auth.Session{ID: "seed", UserID: owner.User.ID, Token: "seed-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}, map[string]any{"hostSubject": "tenant-a"})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.CreateSession(ctx, prepared); err != nil {
				t.Fatal(err)
			}
			live, err := node.GetSession(ctx, http.Header{"Cookie": {node.SessionCookie(prepared.Token, true).String()}})
			if err != nil || live == nil {
				t.Fatal(err)
			}
			if v, ok := live.Session.AdditionalField("hostSubject"); !ok || v != "tenant-a" {
				t.Fatal("trusted session lost its required value")
			}
		})
	}
}

func TestPostgresImportedSessionFieldCaseCollision(t *testing.T) {
	ctx := t.Context()
	dsn := organizationTestDSN(t, "postgres")
	store, err := Open(ctx, "postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, name := range []string{"Region", "region"} {
		if _, err := store.db.ExecContext(ctx, `ALTER TABLE "session" ADD COLUMN "`+name+`" text`); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"Region", "region"} {
		fields := map[string]auth.SessionField{"residence": {Column: name, Type: auth.FieldString}}
		if err := store.ValidateSessionFields(fields); err == nil {
			t.Fatal("accepted an ambiguous case-folded imported column", name)
		}
		findings, err := CheckSchemaWithSessionFields(ctx, "postgres", dsn, nil, fields)
		if err != nil || len(findings) != 1 || findings[0] != (SchemaFinding{Kind: "incompatible-column", Table: "session", Column: name}) {
			t.Fatal("read-only check missed ambiguous imported columns", name, findings, err)
		}
		if migrated, err := OpenWithSessionFields(ctx, "postgres", dsn, nil, fields); err == nil {
			migrated.Close()
			t.Fatal("migration accepted ambiguous physical session columns", name)
		}
	}
}
