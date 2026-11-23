package sqlstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

type resourceIssuanceKeys struct {
	*Store
	beforeSigning func()
}

func (s *resourceIssuanceKeys) ActiveJWTKey(ctx context.Context, alg string, now time.Time, generate func() (auth.StoredJWTKey, error)) (auth.StoredJWTKey, error) {
	if s.beforeSigning != nil {
		s.beforeSigning()
	}
	return s.Store.ActiveJWTKey(ctx, alg, now, generate)
}

func TestMachineResourceIssuance(t *testing.T) {
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
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "jwt"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			keys := &resourceIssuanceKeys{Store: s}
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			const id, resource, origin = "Machine", "urn:Reports", "https://issuer.example.test"
			const issuer = origin + "/custom"
			write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","redirectUris") VALUES ('one',?,'secret','client_secret_post',?,?,'[]')`, id, `["client_credentials"]`, `["read","write"]`)
			write(`INSERT INTO "oauthResource" ("id","identifier","name","allowedScopes") VALUES ('r',?,'Reports',?)`, resource, `["read"]`)
			jwt, err := auth.NewJWT(auth.JWTOptions{Issuer: issuer, AdditionalAlgorithms: []string{"ES256"}})
			must(err)
			var generationHook func()
			host := func(allowUnlinked, signing bool) *auth.Auth {
				t.Helper()
				opts := op.Options{Tokens: op.TokenOptions{AllowUnlinkedResources: allowUnlinked,
					GenerateOpaqueToken: func(context.Context) (string, error) {
						if generationHook != nil {
							generationHook()
						}
						return "generated", nil
					}}, Registration: op.RegistrationOptions{VerifySecret: func(_ context.Context, raw, stored string) (bool, error) { return raw == stored, nil }}}
				p, err := op.New(opts)
				must(err)
				plugins := []auth.Plugin{p}
				if signing {
					plugins = append(plugins, jwt)
				}
				off := false
				a, err := auth.New(auth.Options{BaseURL: origin, BasePath: "/auth", Store: keys, Secret: strings.Repeat("s", 40), Plugins: plugins, RateLimit: &off})
				must(err)
				return a
			}
			request := func(a *auth.Auth, resources []string, status int, code string) map[string]any {
				t.Helper()
				form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {"secret"}, "resource": resources}
				r := httptest.NewRequest(http.MethodPost, origin+"/auth/oauth2/token", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var body map[string]any
				must(json.Unmarshal(w.Body.Bytes(), &body))
				if w.Code != status || code != "" && body["error"] != code {
					t.Fatalf("wanted %d %q, got %d %s", status, code, w.Code, w.Body.String())
				}
				return body
			}
			linked, open, signed := host(false, false), host(true, false), host(false, true)
			res := []string{resource}
			request(linked, res, 400, "invalid_target")
			request(linked, make([]string, 65), 400, "invalid_target")
			request(open, []string{"urn:reports"}, 400, "invalid_target")
			request(open, []string{"urn:missing"}, 400, "invalid_target")
			write(`UPDATE "oauthResource" SET "disabled"=?`, true)
			request(open, res, 400, "invalid_target")
			write(`UPDATE "oauthResource" SET "disabled"=?`, false)
			generationHook = func() { write(`UPDATE "oauthResource" SET "accessTokenTtl"=11`) }
			if b := request(open, res, 200, ""); b["scope"] != "read" || b["expires_in"] != float64(11) {
				t.Fatal("did not apply current resource policy", b)
			}
			link := func() {
				write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES ('link',?,?)`, resource, id)
			}
			link()
			generationHook = func() { write(`DELETE FROM "oauthClientResource" WHERE "clientId"=?`, id) }
			request(linked, res, 400, "invalid_target")
			link()
			generationHook = func() { write(`UPDATE "oauthResource" SET "allowedScopes"=?`, `["other"]`) }
			request(linked, res, 400, "invalid_scope")
			write(`UPDATE "oauthResource" SET "allowedScopes"=?`, `["read"]`)
			generationHook = func() { write(`UPDATE "oauthResource" SET "dpopBoundAccessTokensRequired"=?`, true) }
			request(linked, res, 400, "invalid_dpop_proof")
			generationHook = nil
			write(`UPDATE "oauthResource" SET "dpopBoundAccessTokensRequired"=?, "signingAlgorithm"='ES256'`, false)
			keys.beforeSigning = func() { write(`UPDATE "oauthResource" SET "accessTokenTtl"=8`) }
			request(signed, res, 400, "invalid_request")
			keys.beforeSigning = nil
			response := request(signed, res, 200, "")
			claims, err := signed.VerifyJWT(ctx, response["access_token"].(string), auth.JWTVerifyOptions{Issuer: issuer, Audience: resource, Subject: id})
			must(err)
			if claims["scope"] != "read" || response["expires_in"] != float64(8) {
				t.Fatal("unexpected signed grant", claims)
			}
			write(`UPDATE "oauthResource" SET "signingKeyId"='missing'`)
			request(signed, res, 500, "")
			implicit := origin + "/auth/oauth2/userinfo"
			response = request(signed, []string{implicit}, 200, "")
			_, err = signed.VerifyJWT(ctx, response["access_token"].(string), auth.JWTVerifyOptions{Issuer: issuer, Audience: implicit, Subject: id})
			must(err)
			request(signed, []string{issuer + "/oauth2/userinfo"}, 400, "invalid_target")
			var count int
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "clientId"=?`), id).Scan(&count))
			if count != 1 {
				t.Fatalf("stored %d opaque tokens, expected only the allowed unlinked grant", count)
			}
		})
	}
}
