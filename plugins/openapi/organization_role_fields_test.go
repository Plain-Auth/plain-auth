package openapi_test

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/openapi"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOrganizationRoleFieldDescription(t *testing.T) {
	for _, mandatory := range []bool{false, true} {
		fields := map[string]organization.RoleField{
			"color":        {Type: auth.FieldString, Required: true, Default: "blue", Column: "display_color"},
			"audit":        {Type: auth.FieldString, ServerOnly: true},
			"note":         {Type: auth.FieldString, Hidden: true},
			"metadata":     {Type: organization.RoleJSON},
			"tags":         {Type: organization.RoleStringArray},
			"weights":      {Type: organization.RoleNumberArray, Required: true, Default: []float64{}},
			"issuerSecret": {Type: auth.FieldString, Hidden: true, ServerOnly: true},
		}
		if mandatory {
			fields["rank"] = organization.RoleField{Type: auth.FieldNumber, Required: true}
		}
		store, err := sqlstore.OpenWithAdditionalFields(t.Context(), "sqlite", filepath.Join(t.TempDir(), "roles.db"), []string{"organization-roles"}, schema.AdditionalFields{OrganizationRole: fields})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		org, err := organization.New(organization.Options{Store: store, DynamicAccessControl: true, RoleAdditionalFields: fields})
		if err != nil {
			t.Fatal(err)
		}
		spec, err := openapi.New(openapi.Options{})
		if err != nil {
			t.Fatal(err)
		}
		host, err := auth.New(auth.Options{Store: store, BaseURL: "https://roles.example", Secret: strings.Repeat("d", 40), Plugins: []auth.Plugin{org, spec}})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		host.ServeHTTP(w, httptest.NewRequest("GET", "/api/auth/open-api/generate-schema", nil))
		var doc obj
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || w.Code != 200 {
			t.Fatal(w.Code, err)
		}
		model := node(doc, "components", "schemas", "OrganizationRole", "properties")
		if node(model, "color")["type"] != "string" || node(model, "audit")["readOnly"] != true || model["note"] != nil || model["issuerSecret"] != nil || model["display_color"] != nil {
			t.Fatal("wrong role output projection", model)
		}
		body := func(path string) obj {
			return node(doc, "paths", "/organization/"+path, "post", "requestBody", "content", "application/json", "schema")
		}
		create := body("create-role")
		envelope := node(create, "properties", "additionalFields")
		input := node(envelope, "properties")
		patch := node(body("update-role"), "properties", "data")
		for _, props := range []obj{input, node(patch, "properties")} {
			if props["color"] == nil || props["note"] == nil || props["audit"] != nil || props["issuerSecret"] != nil || props["display_color"] != nil {
				t.Fatal("incorrect role field input description", props)
			}
		}
		for _, properties := range []obj{model, input, node(patch, "properties")} {
			if node(properties, "tags", "items")["type"] != "string" || node(properties, "weights", "items")["type"] != "number" || properties["metadata"] == nil {
				t.Fatal("missing JSON and typed array schemas", properties)
			}
		}
		if slices.Contains(create["required"].([]any), any("additionalFields")) != mandatory || !slices.Contains(envelope["required"].([]any), any("color")) || patch["required"] != nil {
			t.Fatal("wrong required fields for create or partial update", mandatory)
		}
	}
}
