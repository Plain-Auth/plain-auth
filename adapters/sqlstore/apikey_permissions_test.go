package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// DefaultPermissionsFor works out each new key's permissions from its owner,
// for user and organization keys, after the creator is authorized; server
// permissions win and a failure stores nothing.
func TestAPIKeyDefaultPermissionsCallback(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key", "organization"})
			must(err)
			db, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer db.Close()
			var calls []string
			failing := ""
			boom := errors.New("private permission detail")
			f := func(_ context.Context, ref string) (ak.Permissions, error) {
				calls = append(calls, ref)
				if ref == failing {
					return nil, boom
				}
				return ak.Permissions{"projects": {"read:" + ref}}, nil
			}
			if _, err := ak.New(ak.Options{Store: db, DefaultPermissions: ak.Permissions{"x": {"y"}}, DefaultPermissionsFor: f}); err == nil {
				t.Fatal("accepted both default permission settings")
			}
			personal, err := ak.New(ak.Options{Store: db, DefaultPermissionsFor: f})
			must(err)
			teams, err := ak.New(ak.Options{Store: db, ConfigID: "teams", Organization: &ak.OrganizationOptions{}, DefaultPermissionsFor: f})
			must(err)
			plugin, err := ak.NewPlugin(personal, teams)
			must(err)
			orgs, err := org.New(org.Options{Store: db})
			must(err)
			const origin = "https://permissions.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: db, BaseURL: origin, Secret: strings.Repeat("p", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin, orgs}})
			must(err)
			signUp := func(email string) (*client.Client, *client.EmailResult) {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
				must(err)
				res, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Member", Email: email, Password: "permissions-password"})
				must(err)
				return c, res
			}
			owner, ou := signUp("owner@example.test")
			foreign, _ := signUp("foreign@example.test")
			made, err := owner.CreateAPIKey(ctx, client.CreateAPIKeyRequest{})
			must(err)
			if len(calls) != 1 || calls[0] != ou.User.ID || len(made.Permissions["projects"]) != 1 || made.Permissions["projects"][0] != "read:"+ou.User.ID {
				t.Fatal("default permissions callback did not set the user key's permissions", calls, made.Permissions)
			}
			if v, err := personal.Verify(ctx, made.Secret, ak.Permissions{"projects": {"read:" + ou.User.ID}}); err != nil || !v.Valid {
				t.Fatal("a key did not verify with its worked-out permissions", err)
			}
			explicit, err := personal.Create(ctx, ou.User.ID, ak.CreateInput{Policy: ak.Policy{Permissions: ak.Permissions{"admin": {"all"}}}})
			must(err)
			if len(calls) != 2 || len(explicit.Permissions) != 1 || explicit.Permissions["admin"][0] != "all" {
				t.Fatal("explicit permissions did not win over the callback", explicit.Permissions)
			}
			var group struct{ ID string }
			must(owner.Do(ctx, "POST", "/organization/create", map[string]any{"name": "Builders", "slug": "builders"}, &group))
			team, err := owner.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID})
			must(err)
			if calls[len(calls)-1] != group.ID || team.Permissions["projects"][0] != "read:"+group.ID {
				t.Fatal("organization key permissions did not come from the organization ID", calls)
			}
			before := len(calls)
			_, err = foreign.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID})
			var api *plainauth.APIError
			if !errors.As(err, &api) || api.Code != "USER_NOT_MEMBER_OF_ORGANIZATION" || len(calls) != before {
				t.Fatal("the callback ran before the creator was authorized", err)
			}
			failing = ou.User.ID
			listed, err := owner.ListAPIKeys(ctx, "", ak.PageOptions{})
			must(err)
			_, err = owner.CreateAPIKey(ctx, client.CreateAPIKeyRequest{})
			_, direct := personal.Create(ctx, ou.User.ID, ak.CreateInput{})
			after, lerr := owner.ListAPIKeys(ctx, "", ak.PageOptions{})
			if !errors.As(err, &api) || api.Status != 500 || strings.Contains(api.Message, boom.Error()) || !errors.Is(direct, boom) || lerr != nil || after.Total != listed.Total {
				t.Fatal("a failing permissions callback stored a key or leaked its error", err, direct)
			}
		})
	}
}
