package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOAuthResourceManagement(t *testing.T) {
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
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != status || api.Code != code {
					t.Fatalf("want %d %s, got %v", status, code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			s, other := open(), open()
			host, err := auth.New(auth.Options{BaseURL: "https://issuer.example", Store: s, Secret: strings.Repeat("k", 32), EmailAndPassword: true})
			must(err)
			u, err := host.SignUpEmail(ctx, auth.SignUpInput{Name: "Operator", Email: "resource@example.test", Password: "a long fixture password"}, auth.RequestMeta{})
			must(err)
			h := http.Header{"Cookie": {host.SessionCookie(u.Token, true).String()}}
			const id = "https://api.example.test/tenant%2Fwest?region=a"
			const client = "Service.App"
			var calls []string
			var mu sync.Mutex
			opts := op.ResourceManagerOptions{Privileges: func(_ context.Context, a op.ResourceAccess) (bool, error) {
				if a.User.ID != u.User.ID || a.Session.UserID != u.User.ID || a.Session.ID == "" || a.Headers.Get("Cookie") == "" {
					t.Errorf("privilege callback lost the session or headers")
				}
				mu.Lock()
				calls = append(calls, a.Action+":"+a.Identifier)
				mu.Unlock()
				return a.Headers.Get("X-Deny") == "", nil
			}}
			m, err := op.NewResourceManager(host, s, opts)
			must(err)
			peer, err := op.NewResourceManager(host, other, op.ResourceManagerOptions{})
			must(err)
			all, err := m.List(ctx, h)
			must(err)
			if all == nil || len(all) != 0 {
				t.Fatal("empty resource list", all)
			}
			deny := h.Clone()
			deny.Set("X-Deny", "1")
			for _, headers := range []http.Header{nil, deny} {
				_, err = m.Create(ctx, headers, id, op.ResourcePatch{})
				wantError(err, 401, "unauthorized")
				_, err = m.Get(ctx, headers, id)
				wantError(err, 401, "unauthorized")
				_, err = m.List(ctx, headers)
				wantError(err, 401, "unauthorized")
				_, err = m.Update(ctx, headers, id, op.ResourcePatch{})
				wantError(err, 401, "unauthorized")
				wantError(m.Delete(ctx, headers, id), 401, "unauthorized")
				_, err = m.Link(ctx, headers, id, client)
				wantError(err, 401, "unauthorized")
				wantError(m.Unlink(ctx, headers, id, client), 401, "unauthorized")
			}

			var create op.ResourcePatch
			must(json.Unmarshal([]byte(`{"accessTokenTtl":300,"refreshTokenTtl":3600,"signingAlgorithm":"RS256","signingKeyId":"first","allowedScopes":["read"],"customClaims":{"quota":9007199254740993},"metadata":{"nested":["x",true]},"dpopBoundAccessTokensRequired":true,"disabled":true}`), &create))
			r, err := m.Create(ctx, h, id, create)
			must(err)
			if r.ID == "" || r.Name != id || r.PolicyVersion != 1 || r.CreatedAt.IsZero() || !r.CreatedAt.Equal(r.UpdatedAt) {
				t.Fatal("unexpected resource defaults", r)
			}
			r, err = peer.Get(ctx, h, id)
			must(err)
			if r.AccessTokenTTL == nil || *r.AccessTokenTTL != 300 || r.RefreshTokenTTL == nil || *r.RefreshTokenTTL != 3600 || r.SigningAlgorithm == nil || *r.SigningAlgorithm != "RS256" ||
				!r.Disabled || !r.DPoPBoundAccessTokensRequired || !slices.Equal(r.AllowedScopes, []string{"read"}) || string(r.CustomClaims["quota"]) != "9007199254740993" {
				t.Fatal("policy lost in storage", r)
			}
			_, err = m.Create(ctx, h, id, op.ResourcePatch{})
			wantError(err, 400, "invalid_request")
			var patch op.ResourcePatch
			must(json.Unmarshal([]byte(`{"signingKeyId":null,"refreshTokenTtl":null,"allowedScopes":[],"metadata":{},"disabled":false,"identifier":"replacement"}`), &patch))
			r, err = m.Update(ctx, h, id, patch)
			must(err)
			if r.Identifier != id || r.SigningKeyID != nil || r.RefreshTokenTTL != nil || r.AllowedScopes == nil || len(r.AllowedScopes) != 0 || r.Metadata == nil || len(r.Metadata) != 0 || r.Disabled || !r.DPoPBoundAccessTokensRequired || *r.AccessTokenTTL != 300 {
				t.Fatal("sparse patch did not preserve explicit and omitted values", r)
			}
			r, err = peer.Update(ctx, h, id, op.ResourcePatch{AllowedScopes: op.Clear[[]string](), CustomClaims: op.Clear[map[string]json.RawMessage]()})
			must(err)
			if r.AllowedScopes != nil || r.CustomClaims != nil {
				t.Fatal("cleared JSON fields", r)
			}
			var dbNulls int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthResource" WHERE "identifier"=? AND "customClaims" IS NULL AND "allowedScopes" IS NULL`), id).Scan(&dbNulls))
			if dbNulls != 1 {
				t.Fatal("cleared settings should be SQL NULL")
			}
			_, err = m.Update(ctx, h, id, op.ResourcePatch{Disabled: op.Set(true), AccessTokenTTL: op.Set(int64(0))})
			wantError(err, 400, "invalid_request")
			r, err = m.Get(ctx, h, id)
			must(err)
			if r.Disabled {
				t.Fatal("invalid patch partially applied")
			}
			_, err = m.Link(ctx, h, id, client)
			wantError(err, 404, "not_found")
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","redirectUris") VALUES ('registered',?,'[]')`), client)
			must(err)
			_, err = m.Link(ctx, h, "urn:missing", client)
			wantError(err, 404, "not_found")
			_, err = m.Link(ctx, h, id, strings.ToLower(client))
			wantError(err, 404, "not_found")

			// Two pools see one new grant, and disjoint updates both survive.
			type result struct {
				linked op.ResourceLink
				err    error
			}
			links := make(chan result, 8)
			for i := range 8 {
				manager := []*op.ResourceManager{m, peer}[i%2]
				go func() { v, e := manager.Link(ctx, h, id, client); links <- result{v, e} }()
			}
			newLinks := 0
			for range 8 {
				v := <-links
				must(v.err)
				if !v.linked.Linked {
					t.Fatal("missing link result")
				}
				if !v.linked.AlreadyLinked {
					newLinks++
				}
			}
			if newLinks != 1 {
				t.Fatalf("created %d links for one client and resource", newLinks)
			}
			updates := make(chan error, 2)
			go func() { _, e := m.Update(ctx, h, id, op.ResourcePatch{Name: op.Set("West")}); updates <- e }()
			go func() {
				_, e := peer.Update(ctx, h, id, op.ResourcePatch{AccessTokenTTL: op.Set(int64(120))})
				updates <- e
			}()
			must(<-updates)
			must(<-updates)
			all, err = peer.List(ctx, h)
			must(err)
			if len(all) != 1 || all[0].Name != "West" || *all[0].AccessTokenTTL != 120 {
				t.Fatal("lost concurrent update", all)
			}
			must(m.Unlink(ctx, h, id, client))
			must(peer.Unlink(ctx, h, id, client))
			link, err := m.Link(ctx, h, id, client)
			must(err)
			if link.AlreadyLinked {
				t.Fatal("unlink left a grant")
			}
			must(m.Delete(ctx, h, id))
			wantError(m.Delete(ctx, h, id), 404, "not_found")
			_, err = m.Get(ctx, h, id)
			wantError(err, 404, "not_found")
			_, err = m.Update(ctx, h, id, op.ResourcePatch{})
			wantError(err, 404, "not_found")
			var remaining int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthClientResource"`)).Scan(&remaining))
			if remaining != 0 {
				t.Fatal("resource deletion left a client grant")
			}
			must(m.Unlink(ctx, h, id, client))
			for _, expected := range []string{"create:", "list:", "read:" + id, "update:" + id, "delete:" + id, "link:" + id, "unlink:" + id} {
				if !slices.Contains(calls, expected) {
					t.Errorf("missing privilege check %q", expected)
				}
			}
			custom, err := op.NewResourceManager(host, s, op.ResourceManagerOptions{
				IdentifierValidator: func(_ context.Context, key string) (bool, error) { return key == "billing", nil },
			})
			must(err)
			_, err = m.Create(ctx, h, "billing", op.ResourcePatch{})
			wantError(err, 400, "invalid_target")
			_, err = custom.Create(ctx, h, "urn:example:billing", op.ResourcePatch{})
			wantError(err, 400, "invalid_target")
			customResource, err := custom.Create(ctx, h, "billing", op.ResourcePatch{})
			must(err)
			if customResource.Name != "billing" {
				t.Fatal("custom identifier was not preserved")
			}
			for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(method, "/api/auth/admin/oauth2/resources", nil)
				req.Header = h.Clone()
				host.ServeHTTP(rec, req)
				if rec.Code != 404 {
					t.Errorf("server-only operation published for %s: %d", method, rec.Code)
				}
			}
			must(host.SignOut(ctx, h))
			_, err = peer.List(ctx, h)
			wantError(err, 401, "unauthorized")
		})
	}
}
