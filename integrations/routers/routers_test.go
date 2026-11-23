// The integration module keeps framework dependencies out of the library.
package routers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v5"
)

type runner func(*http.Request) (*http.Response, error)

func httpRunner(handler http.Handler) runner {
	return func(req *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result(), nil
	}
}

func TestFrameworkMounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const issuerDiscovery = "/.well-known/oauth-authorization-server/api/auth"
	discovery, err := oauthprovider.NewResourceDiscovery(oauthprovider.ResourceMetadata{
		Resource: "https://api.example.test/reports", AuthorizationServers: []string{"https://issuer.example.test"},
	}, oauthprovider.DiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		mount func(http.Handler, http.HandlerFunc) runner
	}{
		{"ServeMux", func(h http.Handler, me http.HandlerFunc) runner {
			r := http.NewServeMux()
			r.Handle("/api/auth/", h)
			r.Handle(issuerDiscovery, h)
			r.Handle(discovery.Path(), discovery)
			r.HandleFunc("GET /me", me)
			return httpRunner(r)
		}},
		{"chi", func(h http.Handler, me http.HandlerFunc) runner {
			r := chi.NewRouter()
			r.Handle("/api/auth/*", h)
			r.Handle(issuerDiscovery, h)
			r.Handle(discovery.Path(), discovery)
			r.Get("/me", me)
			return httpRunner(r)
		}},
		{"Gorilla", func(h http.Handler, me http.HandlerFunc) runner {
			r := mux.NewRouter()
			r.PathPrefix("/api/auth/").Handler(h)
			r.Handle(issuerDiscovery, h)
			r.Handle(discovery.Path(), discovery)
			r.HandleFunc("/me", me).Methods("GET")
			return httpRunner(r)
		}},
		{"Gin", func(h http.Handler, me http.HandlerFunc) runner {
			r := gin.New()
			r.Any("/api/auth/*path", gin.WrapH(h))
			r.Any(issuerDiscovery, gin.WrapH(h))
			r.Any(discovery.Path(), gin.WrapH(discovery))
			r.GET("/me", gin.WrapH(me))
			return httpRunner(r)
		}},
		{"Echo", func(h http.Handler, me http.HandlerFunc) runner {
			r := echo.New()
			r.Any("/api/auth/*", echo.WrapHandler(h))
			r.Any(issuerDiscovery, echo.WrapHandler(h))
			r.Any(discovery.Path(), echo.WrapHandler(discovery))
			r.GET("/me", echo.WrapHandler(me))
			return httpRunner(r)
		}},
		{"Fiber", func(h http.Handler, me http.HandlerFunc) runner {
			r := fiber.New()
			r.All("/api/auth/*", adaptor.HTTPHandler(h))
			r.All(issuerDiscovery, adaptor.HTTPHandler(h))
			r.All(discovery.Path(), adaptor.HTTPHandler(discovery))
			r.Get("/me", adaptor.HTTPHandler(me))
			return func(req *http.Request) (*http.Response, error) {
				// Real password hashing under -race can exceed Fiber's one-second test default.
				return r.Test(req, fiber.TestConfig{Timeout: 15 * time.Second, FailOnTimeout: true})
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"oauth-provider", "jwt", "organization-teams"}, schema.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			const origin = "http://localhost"
			provider, err := oauthprovider.New(oauthprovider.Options{Scopes: []string{"openid", "reports"}})
			if err != nil {
				t.Fatal(err)
			}
			signer, err := authn.NewJWT(authn.JWTOptions{DisableHeader: true})
			if err != nil {
				t.Fatal(err)
			}
			groups, err := organization.New(organization.Options{Store: s, Teams: &organization.TeamOptions{}})
			if err != nil {
				t.Fatal(err)
			}
			auth, err := authn.New(authn.Options{BaseURL: origin, Secret: strings.Repeat("r", 32), Store: s, EmailAndPassword: true, Plugins: []authn.Plugin{provider, signer, groups}})
			if err != nil {
				t.Fatal(err)
			}
			run := tc.mount(auth, func(w http.ResponseWriter, r *http.Request) {
				session, err := auth.GetSession(r.Context(), r.Header)
				if err != nil {
					http.Error(w, "session lookup failed", http.StatusInternalServerError)
					return
				}
				if session == nil {
					http.Error(w, "sign in first", http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, session.User.Email)
			})
			send := func(method, path, body string, cookies []*http.Cookie, expect int) (*http.Response, string) {
				t.Helper()
				req, err := http.NewRequest(method, origin+path, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				if method == http.MethodPost {
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Origin", origin)
				}
				for _, c := range cookies {
					req.AddCookie(c)
				}
				res, err := run(req)
				if err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
				defer res.Body.Close()
				b, err := io.ReadAll(res.Body)
				if err != nil {
					t.Fatal(err)
				}
				if res.StatusCode != expect {
					t.Fatalf("%s %s: got %d: %s", method, path, res.StatusCode, b)
				}
				return res, strings.TrimSpace(string(b))
			}
			send("GET", "/app-owned", "", nil, 404)
			for _, path := range []string{issuerDiscovery, "/api/auth/.well-known/oauth-authorization-server", "/api/auth/.well-known/openid-configuration"} {
				_, raw := send("GET", path, "", nil, 200)
				var issuer oauthprovider.OpenIDProviderMetadata
				if err := json.Unmarshal([]byte(raw), &issuer); err != nil || issuer.TokenEndpoint != origin+"/api/auth/oauth2/token" {
					t.Fatal("unexpected authorization-server discovery document", raw, err)
				}
				if issuer.UserInfoEndpoint != origin+"/api/auth/oauth2/userinfo" || len(issuer.IDTokenSigningAlgorithms) != 1 || issuer.IDTokenSigningAlgorithms[0] != "EdDSA" {
					t.Fatal("router lost OpenID provider metadata", raw)
				}
				res, body := send("HEAD", path, "", nil, 200)
				if body != "" || res.Header.Get("Cache-Control") == "" {
					t.Fatal("unexpected discovery HEAD response", res.Header, body)
				}
			}
			_, metadata := send("GET", discovery.Path(), "", nil, http.StatusOK)
			var doc oauthprovider.ResourceMetadata
			if err := json.Unmarshal([]byte(metadata), &doc); err != nil || doc.Resource != "https://api.example.test/reports" {
				t.Fatal("unexpected resource discovery document", metadata, err)
			}
			send("GET", "/me", "", nil, http.StatusUnauthorized)
			res, _ := send("POST", "/api/auth/sign-up/email", `{"name":"Ada","email":"ada@example.com","password":"example-password"}`, nil, 200)
			cookies := res.Cookies()
			if len(cookies) == 0 {
				t.Fatal("registration returned no session cookie")
			}
			if _, email := send("GET", "/me", "", cookies, http.StatusOK); email != "ada@example.com" {
				t.Fatalf("application route received incorrect account %q", email)
			}
			_, session := send("GET", "/api/auth/get-session", "", cookies, 200)
			var result authn.SessionResult
			if json.Unmarshal([]byte(session), &result) != nil || result.User.Email != "ada@example.com" {
				t.Fatalf("unexpected session: %s", session)
			}
			checkSelection := func(method, path, body string, out any) {
				t.Helper()
				resp, raw := send(method, "/api/auth/organization/"+path, body, cookies, 200)
				if resp.Header.Get("Location") != "" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
					t.Fatal("ordinary selection did not return JSON to the calling application", tc.name)
				}
				if err := json.Unmarshal([]byte(raw), out); err != nil {
					t.Fatal(err)
				}
			}
			var studio, shop, selected organization.Organization
			checkSelection("POST", "create", `{"name":"Studio","slug":"studio"}`, &studio)
			checkSelection("POST", "create", `{"name":"Shop","slug":"shop"}`, &shop)
			checkSelection("POST", "set-active", `{"organizationSlug":"studio"}`, &selected)
			var view organization.FullOrganization
			checkSelection("GET", "get-full-organization?membersLimit=1", "", &view)
			if selected.ID != studio.ID || view.ID != studio.ID || len(view.Teams) != 1 || len(view.Members) != 1 || view.Members[0].User.Email != result.User.Email {
				t.Fatal("router lost the selected organization's members or teams", tc.name)
			}
			teamRequest, err := json.Marshal(map[string]string{"teamId": view.Teams[0].ID})
			if err != nil {
				t.Fatal(err)
			}
			var team organization.Team
			checkSelection("POST", "set-active-team", string(teamRequest), &team)
			if team.ID != view.Teams[0].ID || team.OrganizationID != studio.ID {
				t.Fatal("router returned an unrelated team", tc.name)
			}
			checkSelection("POST", "set-active", `{"organizationSlug":"shop"}`, &selected)
			_, session = send("GET", "/api/auth/get-session", "", cookies, 200)
			var switched authn.SessionResult
			if err := json.Unmarshal([]byte(session), &switched); err != nil {
				t.Fatal(err)
			}
			if selected.ID != shop.ID || switched.Session.ActiveOrganizationID == nil || *switched.Session.ActiveOrganizationID != shop.ID || switched.Session.ActiveTeamID != nil {
				t.Fatal("organization switch did not clear the previous team", tc.name)
			}
			res, _ = send("POST", "/api/auth/sign-out", "{}", cookies, 200)
			if len(res.Cookies()) < 2 {
				t.Fatal("adapter lost multiple Set-Cookie headers")
			}
			_, session = send("GET", "/api/auth/get-session", "", cookies, 200)
			if session != "null" {
				t.Fatal("revoked session accepted")
			}
			send("GET", "/me", "", cookies, http.StatusUnauthorized)
		})
	}
}
