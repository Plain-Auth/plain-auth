package openapi_test

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/openapi"
	"github.com/Stonewrit/stonewrit-auth/plugins/organization"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	"github.com/Stonewrit/stonewrit-auth/providers"
	"github.com/Stonewrit/stonewrit-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

func TestConfiguredOrganizationAndBillingSchema(t *testing.T) {
	ddl, err := schema.Generate("sqlite", []string{"organization-teams", "stripe-subscriptions"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(t.Context(), "sqlite", filepath.Join(t.TempDir(), "spec.db"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	org, err := organization.New(organization.Options{Store: store, Teams: &organization.TeamOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	api, err := openapi.New(openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	stripe := billing.New(billing.Options{WebhookSecret: "whsec_offline_schema", Subscriptions: &billing.SubscriptionOptions{Client: &sdk.Client{}, Plans: []billing.Plan{{Name: "pro", PriceID: "price_pro"}}}})
	a, err := auth.New(auth.Options{BaseURL: "https://auth.example.test/login", Store: store, Secret: strings.Repeat("s", 48), Plugins: []auth.Plugin{org, stripe, api},
		SocialProviders: map[string]auth.OAuthProvider{"github": providers.GitHub("public-fixture", "private-fixture-credential")}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://untrusted.example/login/open-api/generate-schema", nil)
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "private-fixture-credential") {
		t.Fatal("schema included provider configuration")
	}
	var doc obj
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if got := doc["servers"].([]any)[0].(obj)["url"]; got != "https://auth.example.test/login" {
		t.Fatal("hostname came from request", got)
	}

	paths := node(doc, "paths")
	schemas := node(doc, "components", "schemas")
	for _, name := range []string{"Organization", "Member", "Invitation", "Team", "TeamMember", "Subscription"} {
		if schemas[name] == nil {
			t.Fatal("missing installed model", name)
		}
	}
	if paths["/subscription/billing-portal"] != nil || paths["/sign-up/email"] != nil || node(paths, "/get-session", "post") != nil {
		t.Fatal("listed disabled configuration")
	}
	if node(paths, "/organization/list-teams", "get", "responses", "200", "content", "application/json", "schema", "items")["$ref"] != "#/components/schemas/Team" {
		t.Fatal("list team response schema")
	}
	role := node(paths, "/organization/update-member-role", "post")
	if node(role, "responses", "200", "content", "application/json", "schema")["$ref"] != "#/components/schemas/Member" {
		t.Fatal("role update must return the public member directly")
	}
	if len(node(role, "requestBody", "content", "application/json", "schema", "properties", "role")["anyOf"].([]any)) != 2 {
		t.Fatal("role update must accept both a string and an array")
	}
	start := node(paths, "/sign-in/social", "post", "requestBody", "content", "application/json", "schema", "properties")
	if got := node(start, "provider")["enum"].([]any); len(got) != 1 || got[0] != "github" {
		t.Fatal("disabled providers advertised", got)
	}
	callback := node(paths, "/callback/{id}", "post", "requestBody", "content")
	if callback["application/json"] != nil || callback["application/x-www-form-urlencoded"] == nil {
		t.Fatal("incorrect OAuth form callback", callback)
	}
	if node(paths, "/get-access-token", "post", "requestBody", "content", "application/json", "schema", "properties", "accountId")["type"] != "string" {
		t.Fatal("account token selector missing")
	}
	fields := node(paths, "/subscription/upgrade", "post", "requestBody", "content", "application/json", "schema", "properties")
	if fields["plan"] == nil || fields["returnUrl"] == nil || fields["metadata"] != nil || fields["scheduleAtPeriodEnd"] != nil {
		t.Fatal("unsupported checkout options", fields)
	}
	protected := node(paths, "/subscription/list", "get")["security"].([]any)
	if len(protected) != 1 || protected[0].(obj)["apiKeyCookie"] == nil {
		t.Fatal("invented bearer scheme", protected)
	}
	if node(doc, "components", "securitySchemes", "stripeSignature")["name"] != "Stripe-Signature" {
		t.Fatal("missing webhook signature header")
	}
	if node(paths, "/stripe/webhook", "post")["security"].([]any)[0].(obj)["stripeSignature"] == nil {
		t.Fatal("wrong webhook authentication")
	}
	ids := map[string]bool{}
	for _, path := range paths {
		for _, val := range path.(obj) {
			id := val.(obj)["operationId"].(string)
			if ids[id] {
				t.Fatal("duplicate operation ID", id)
			}
			ids[id] = true
		}
	}
	var verifyRefs func(any)
	verifyRefs = func(value any) {
		switch v := value.(type) {
		case obj:
			for k, x := range v {
				if k == "$ref" {
					ref := x.(string)
					var target = obj(doc)
					for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
						target = node(target, part)
					}
					if target == nil {
						t.Fatal("unresolved schema reference", ref)
					}
				} else {
					verifyRefs(x)
				}
			}
		case []any:
			for _, x := range v {
				verifyRefs(x)
			}
		}
	}
	verifyRefs(doc)
}
