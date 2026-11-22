package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOAuthMachineIntrospection(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			const clientID = "Reports"
			const digest = "LookupKey"
			const insert = `INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","scopes","redirectUris") VALUES (?,?,?,?,?,?)`
			seed := func(key, id string) { write(insert, key, id, "saved-secret", "client_secret_basic", `[]`, `[]`) }
			seed("original", clientID)
			seed("peer", "Billing")
			now := time.Now().UTC().Truncate(time.Second)
			write(`INSERT INTO "oauthAccessToken" ("id","clientId","token","createdAt","expiresAt","scopes") VALUES (?,?,?,?,?,?)`,
				"issued", clientID, digest, s.date(now), s.date(now.Add(time.Hour)), `["read"]`)
			var beforeLookup func()
			p, err := op.New(op.Options{Registration: op.RegistrationOptions{
				SecretPrefix: "secret-", VerifySecret: func(_ context.Context, raw, stored string) (bool, error) {
					return raw == "value" && stored == "saved-secret", nil
				},
			}, Tokens: op.TokenOptions{OpaquePrefix: "token-", HashOpaqueToken: func(_ context.Context, raw string) (string, error) {
				if beforeLookup != nil {
					beforeLookup()
				}
				if raw == "fail" {
					return "", errors.New("private digest failure")
				}
				if raw == "value" {
					return digest, nil
				}
				return raw, nil
			}}})
			must(err)
			off := false
			const origin = "https://resource.example.test"
			host, err := auth.New(auth.Options{BaseURL: origin, BasePath: "/identity", Secret: strings.Repeat("s", 40), Store: s, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			call := func(client, token string, status int) map[string]any {
				t.Helper()
				body := url.Values{"token": {token}}.Encode()
				r := httptest.NewRequest(http.MethodPost, origin+"/identity/oauth2/introspect", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth(client, "secret-value")
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				if w.Code != status || strings.Contains(w.Body.String(), "private digest failure") {
					t.Fatalf("introspection status %d: %s", w.Code, w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" || (status == 401 && w.Header().Get("WWW-Authenticate") != "Basic") {
					t.Fatal("introspection cache policy or Basic challenge incorrect")
				}
				var result map[string]any
				must(json.Unmarshal(w.Body.Bytes(), &result))
				return result
			}
			active := call(clientID, "token-value", 200)
			want := map[string]any{"active": true, "client_id": clientID, "azp": clientID, "token_type": "Bearer", "scope": "read",
				"iss": origin + "/identity", "iat": float64(now.Unix()), "exp": float64(now.Add(time.Hour).Unix())}
			if !reflect.DeepEqual(active, want) {
				t.Fatalf("active response: %v", active)
			}
			inactive := func(id, token string) {
				t.Helper()
				if result := call(id, token, 200); !reflect.DeepEqual(result, map[string]any{"active": false}) {
					t.Fatalf("inactive response disclosed claims: %v", result)
				}
			}
			inactive("Billing", "token-value")
			inactive(clientID, "token-"+strings.ToLower(digest))
			inactive(clientID, "value")
			call(strings.ToLower(clientID), "token-value", 401)
			call(clientID, "token-fail", 500)
			for _, binding := range []struct{ column, value string }{
				{"authorizationCodeId", "code"}, {"referenceId", "tenant"}, {"resources", `["urn:reports"]`},
				{"requestedUserInfoClaims", `["email"]`}, {"confirmation", `{"jkt":"test"}`},
			} {
				write(`UPDATE "oauthAccessToken" SET "`+binding.column+`"=? WHERE "id"='issued'`, binding.value)
				inactive(clientID, "token-value")
				write(`UPDATE "oauthAccessToken" SET "` + binding.column + `"=NULL WHERE "id"='issued'`)
			}
			write(`UPDATE "oauthAccessToken" SET "expiresAt"=? WHERE "id"='issued'`, s.date(now))
			inactive(clientID, "token-value")
			write(`UPDATE "oauthAccessToken" SET "expiresAt"=? WHERE "id"='issued'`, s.date(now.Add(time.Hour)))
			beforeLookup = func() { write(`UPDATE "oauthAccessToken" SET "revoked"=? WHERE "id"='issued'`, s.date(now)) }
			inactive(clientID, "token-value")
			write(`UPDATE "oauthAccessToken" SET "revoked"=NULL WHERE "id"='issued'`)
			beforeLookup = func() { write(`UPDATE "oauthClient" SET "clientSecret"='rotated' WHERE "id"='original'`) }
			call(clientID, "token-value", 401)
			write(`UPDATE "oauthClient" SET "clientSecret"='saved-secret' WHERE "id"='original'`)
			beforeLookup = func() { write(`UPDATE "oauthClient" SET "disabled"=TRUE WHERE "id"='original'`) }
			call(clientID, "token-value", 401)
			write(`UPDATE "oauthClient" SET "disabled"=FALSE WHERE "id"='original'`)
			beforeLookup = func() {
				write(`DELETE FROM "oauthClient" WHERE "id"='original'`)
				seed("replacement", clientID)
			}
			call(clientID, "token-value", 401)
			beforeLookup = nil
			inactive(clientID, "token-value")
		})
	}
}

func TestOAuthIntrospectionRateLimit(t *testing.T) {
	testOAuthTokenRouteLimit(t, "introspect", 100)
}

func TestOAuthRevocationRateLimit(t *testing.T) {
	testOAuthTokenRouteLimit(t, "revoke", 30)
}

func TestOAuthClientKeyRotationRateLimit(t *testing.T) {
	testOAuthTokenRouteLimit(t, "client/rotate-keys", 5)
}

func testOAuthTokenRouteLimit(t *testing.T, route string, defaultMax int) {
	t.Helper()
	s, err := OpenWithOptions(t.Context(), "sqlite", organizationTestDSN(t, "sqlite"), []string{"oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, max := range []int{defaultMax, 2, 3} {
		t.Run(strconv.Itoa(max), func(t *testing.T) {
			var rule *auth.RateLimitRule
			if max == 2 {
				rule = &auth.RateLimitRule{Window: time.Minute, Max: max}
			} else if max == 3 {
				rule = &auth.RateLimitRule{}
			}
			opts := op.TokenOptions{IntrospectionRateLimit: rule, RevocationRateLimit: rule}
			p, err := op.New(op.Options{Tokens: opts, Assertions: op.AssertionOptions{KeyRotationRateLimit: rule}})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://limit.example.test"
			host, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("a", 40), Store: s, Plugins: []auth.Plugin{p},
				RateLimitDefault: &auth.RateLimitRule{Max: 3, Window: time.Minute}})
			if err != nil {
				t.Fatal(err)
			}
			body, media, normal := "token=x", "application/x-www-form-urlencoded", http.StatusUnauthorized
			if route == "client/rotate-keys" {
				body, media, normal = `{"client_assertion":"unused","client_assertion_type":"unused","jwks":{"keys":[{}]}}`, "application/json", http.StatusForbidden
			}
			for i := 0; i <= max; i++ {
				r := httptest.NewRequest(http.MethodPost, origin+"/api/auth/oauth2/"+route, strings.NewReader(body))
				r.Header.Set("Content-Type", media)
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				expected := normal
				if i == max {
					expected = http.StatusTooManyRequests
				}
				if w.Code != expected {
					t.Fatalf("%s request %d returned %d, want %d", route, i+1, w.Code, expected)
				}
			}
		})
	}
}
