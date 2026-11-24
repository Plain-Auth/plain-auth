package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

// A provisioned SCIM user goes through ValidateUserInfo with method scim; a
// refusal answers a SCIM 403 with the refusal's message and stores nothing.
func TestSCIMUserValidation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"scim"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var checks []auth.UserInfoValidation
			host, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity/custom", Secret: strings.Repeat("a", 32), Store: store,
				ValidateUserInfo: func(_ context.Context, v auth.UserInfoValidation) error {
					checks = append(checks, v)
					if !strings.HasSuffix(v.User.Email, "@company.example") {
						return &auth.APIError{Code: "scim_blocked", Message: "Only company users are provisioned"}
					}
					return nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			h, err := scim.New(host, scim.Options{Store: store, Connections: []scim.Connection{{Directory: scim.Directory{ID: "ACME", ProvisioningDomainID: "Org"}, Credentials: []scim.Credential{{ID: "owned", Token: "writer"}}}}})
			if err != nil {
				t.Fatal(err)
			}
			create := func(email string) (int, map[string]any) {
				w := scimRequest(h, "POST", "Users", "writer", map[string]any{"schemas": []string{scim.UserSchema}, "userName": email, "externalId": email, "displayName": "Directory User"})
				var out map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			if status, body := create("eve@else.example"); status != 403 || body["detail"] != "Only company users are provisioned" || body["status"] != "403" {
				t.Fatal("a refused SCIM user was provisioned", status, body)
			}
			check := checks[len(checks)-1]
			if check.Action != auth.UserInfoCreateUser || check.Method != "scim" || check.User.Email != "eve@else.example" || check.User.Name != "Directory User" || check.Request == nil {
				t.Fatalf("the SCIM check was %+v", check)
			}
			if _, err := store.FindAccountUser(ctx, "eve@else.example"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("a refused SCIM user was stored", err)
			}
			if status, body := create("ada@company.example"); status != 201 {
				t.Fatal("an admitted SCIM user failed", status, body)
			}
		})
	}
}
