package openapi_test

import (
	"slices"
	"testing"

	"github.com/Plain-Auth/plain-auth/plugins/bearer"
	"github.com/Plain-Auth/plain-auth/plugins/openapi"
	"github.com/Plain-Auth/plain-auth/plugins/phonenumber"
)

func TestPhoneSchemaMatchesInstalledAccountOperations(t *testing.T) {
	_, baseline := fixture(t, openapi.Options{})
	plain := schemaDoc(t, baseline)
	if node(plain, "components", "schemas", "User", "properties")["phoneNumber"] != nil || node(plain, "paths")["/phone-number/verify"] != nil {
		t.Fatal("phone fields or routes published on a server without the plugin")
	}
	phone, err := phonenumber.New(phonenumber.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, srv := fixture(t, openapi.Options{}, phone, bearer.New(bearer.Options{}))
	doc := schemaDoc(t, srv)
	paths := node(doc, "paths")
	if paths["/phone-number/consume-otp"] != nil {
		t.Fatal("native-only proof published as an HTTP operation")
	}
	if node(doc, "components", "schemas", "User", "properties")["phoneNumberVerified"] == nil {
		t.Fatal("installed phone fields missing")
	}
	op := node(paths, "/phone-number/verify", "post")
	options := op["security"].([]any)
	hasCredential := func(name string) bool {
		return slices.ContainsFunc(options, func(x any) bool { _, ok := x.(obj)[name]; return ok })
	}
	if !slices.ContainsFunc(options, func(x any) bool { return len(x.(obj)) == 0 }) || !hasCredential("apiKeyCookie") || !hasCredential("bearerAuth") {
		t.Fatal("verification must also support signed-out callers")
	}
	phoneBody := node(op, "requestBody", "content", "application/json", "schema")
	if len(phoneBody["required"].([]any)) != 2 || node(phoneBody, "properties", "code")["writeOnly"] != true || node(phoneBody, "properties", "updatePhoneNumber")["description"] == nil {
		t.Fatal("verification input contract")
	}
	result := node(op, "responses", "200", "content", "application/json", "schema")
	if node(result, "properties", "user")["$ref"] != "#/components/schemas/User" || node(result, "properties", "status")["const"] != true {
		t.Fatal("verified user result contract")
	}
	if got := node(paths, "/update-user", "post", "requestBody", "content", "application/json", "schema", "properties", "phoneNumber")["type"]; got != "null" {
		t.Fatal("update-user must advertise clearing only")
	}
	login := node(paths, "/sign-in/phone-number", "post")
	if len(login["security"].([]any)) != 0 || node(login, "responses", "200", "content", "application/json", "schema", "properties")["redirect"] != nil {
		t.Fatal("password sign-in contract publishes unsupported fields or credentials")
	}
	password := node(paths, "/phone-number/reset-password", "post", "requestBody", "content", "application/json", "schema", "properties", "newPassword")
	if password["minLength"] != float64(10) || password["maxLength"] != float64(99) {
		t.Fatal("password limits from instance were omitted")
	}
}
