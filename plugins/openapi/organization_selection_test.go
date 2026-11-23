package openapi_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/plugins/openapi"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOrganizationSelectionSchema(t *testing.T) {
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", filepath.Join(t.TempDir(), "selection.db"), []string{"organization-teams", "oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, tc := range []struct {
		name                    string
		teams, login, postLogin bool
	}{
		{name: "organizations"},
		{name: "teams", teams: true},
		{name: "issuer login only", teams: true, login: true},
		{name: "post-login selection", teams: true, login: true, postLogin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := organization.Options{Store: store}
			if tc.teams {
				options.Teams = &organization.TeamOptions{}
			}
			org, err := organization.New(options)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := openapi.New(openapi.Options{})
			if err != nil {
				t.Fatal(err)
			}
			plugins := []auth.Plugin{org, spec}
			if tc.login {
				pages := oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login"}
				if tc.postLogin {
					pages.PostLogin = &oauthprovider.PostLoginOptions{Page: "/choose", ShouldRedirect: func(context.Context, oauthprovider.PostLoginContext) (bool, error) { return true, nil }}
				}
				issuer, err := oauthprovider.New(oauthprovider.Options{Authorization: pages})
				if err != nil {
					t.Fatal(err)
				}
				plugins = append(plugins, issuer)
			}
			host, err := auth.New(auth.Options{BaseURL: "https://app.example", BasePath: "/identity", Secret: strings.Repeat("s", 40), Store: store, Plugins: plugins})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			host.ServeHTTP(w, httptest.NewRequest("GET", "/identity/open-api/generate-schema", nil))
			var doc obj
			if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || w.Code != 200 {
				t.Fatal("schema request failed", w.Code, err)
			}
			paths := node(doc, "paths")
			activeMember := node(paths, "/organization/get-active-member", "get")
			memberFields, _ := node(activeMember, "responses", "200", "content", "application/json", "schema")["allOf"].([]any)
			if len(memberFields) != 2 || memberFields[0].(obj)["$ref"] != "#/components/schemas/Member" {
				t.Fatal("expected active member response to include the membership")
			}
			user := node(memberFields[1].(obj), "properties", "user", "properties")
			if len(user) != 4 || user["id"] == nil || user["name"] == nil || user["email"] == nil || user["image"] == nil {
				t.Fatal("unexpected public member user fields", user)
			}
			lookup := node(paths, "/organization/get-active-member-role", "get")
			params, _ := lookup["parameters"].([]any)
			role := node(lookup, "responses", "200", "content", "application/json", "schema", "properties", "role")
			if len(params) != 3 || role["type"] != "string" {
				t.Fatal("missing organization role query parameters or response")
			}
			for path, model := range map[string]string{"/organization/set-active": "Organization", "/organization/set-active-team": "Team"} {
				if model == "Team" && !tc.teams {
					if paths[path] != nil {
						t.Fatal("team selector advertised without teams")
					}
					continue
				}
				op := node(paths, path, "post")
				body := node(op, "requestBody")
				fields := node(body, "content", "application/json", "schema", "properties")
				idTypes, _ := node(fields, strings.ToLower(model)+"Id")["type"].([]any)
				if body["required"] == true || !slices.Contains(idTypes, "null") || !slices.Contains(idTypes, "string") {
					t.Fatal("expected an optional, nullable selection", path)
				}
				if model == "Organization" && node(fields, "organizationSlug")["type"] != "string" {
					t.Fatal("missing organization slug selector")
				}
				responses := node(op, "responses")
				shapes, _ := node(responses, "200", "content", "application/json", "schema")["anyOf"].([]any)
				if len(shapes) < 2 || shapes[0].(obj)["$ref"] != "#/components/schemas/"+model || shapes[1].(obj)["type"] != "null" {
					t.Fatal("selection must return its public model or null", path)
				}
				if tc.postLogin {
					if node(fields, "oauth_query")["type"] != "string" || node(responses, "302", "headers", "Location", "schema")["type"] != "string" ||
						len(shapes) != 3 || node(shapes[2].(obj), "properties", "redirect")["const"] != true || node(shapes[2].(obj), "properties", "url")["type"] != "string" {
						t.Fatal("missing signed selection destination", path)
					}
				} else if fields["oauth_query"] != nil || responses["302"] != nil || len(shapes) != 2 {
					t.Fatal("ordinary selection advertised navigation", path)
				}
			}
		})
	}
}
