package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

type failureStore struct{ Store }

func (failureStore) SCIMGet(context.Context, Directory, string) (Record, error) {
	return Record{}, errors.New("private driver diagnostic")
}
func TestSCIMProtocolAndCredentialConfiguration(t *testing.T) {
	host, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity", Secret: strings.Repeat("a", 32), Store: memory.New()})
	if err != nil {
		t.Fatal(err)
	}
	conn := func(id, token string) Connection {
		return Connection{Directory: Directory{ID: id}, Credentials: []Credential{{ID: "one", Token: token}}}
	}
	for _, cs := range [][]Connection{{conn("ba_scim_connection_managed", "a")}, {conn("a", "one"), conn("b", "one")}, {conn("a", "one"), conn("a", "two")}, {conn("a", "")}, {conn("a", "two words")}, {{Directory: Directory{ID: "a"}, Credentials: []Credential{{ID: "key", Token: "one", Scopes: []string{"bad"}}}}}} {
		if _, err := New(host, Options{Store: failureStore{}, Connections: cs}); err == nil {
			t.Fatal("accepted invalid connection")
		}
	}
	options := Options{Store: failureStore{}, Connections: []Connection{conn("a", "one")}}
	// SCIM provisioning does not run database hooks yet, so it refuses a host with hooks.
	hooked, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity", Secret: strings.Repeat("a", 32), Store: memory.New(),
		DatabaseHooks: auth.DatabaseHooks{User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
			After: func(context.Context, auth.UserRecord, *auth.HookContext) error { return nil },
		}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(hooked, options); err == nil || !strings.Contains(err.Error(), "database hooks") {
		t.Fatal("SCIM accepted a host whose database hooks it would bypass", err)
	}
	h, err := New(host, options)
	if err != nil {
		t.Fatal(err)
	}
	options.Connections[0].Credentials[0].Token = "mutated-after-install"
	for _, tc := range []struct {
		method, path, token, media, body string
		status                           int
	}{
		{"GET", "/identity/ok", "", "", "", 200},
		{"GET", "/identity/scim/v2/Users/id", "one", "", "", 500},
		{"GET", "/identity/scim/v2/Users/id", "mutated-after-install", "", "", 401},
		{"GET", "/identity/scim/v2/ResourceTypes/Group", "", "", "", 404},
		{"GET", "/identity/scim/v2/Schemas/" + UserSchema, "", "", "", 200},
		{"GET", "/identity/scim/v2/Users/a%2fb", "one", "", "", 404},
		{"GET", "/identity/scim/v2/Users/id", "", "", "", 401},
		{"PATCH", "/identity/scim/v2/Users/id", "one", "text/plain", "{}", 415},
		{"PATCH", "/identity/scim/v2/Users/id", "one", "application/json", "{} {}", 400},
		{"POST", "/identity/scim/v2/Users", "one", "application/json", "`", 400},
		{"OPTIONS", "/identity/scim/v2/Users", "", "", "", 405},
	} {
		t.Run(tc.method+" "+tc.path+tc.token+tc.media, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Cookie", "session=fixture")
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.media != "" {
				r.Header.Set("Content-Type", tc.media)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private driver diagnostic") {
				t.Fatal("private driver detail exposed")
			}
			if strings.Contains(tc.path, "/scim/") && w.Header().Get("Content-Type") != MediaType {
				t.Fatal("wrong response media")
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "/identity/scim/v2/Users/id", nil)
	r.Header.Add("Authorization", "Bearer one")
	r.Header.Add("Authorization", "Bearer two")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("multiple Authorization headers accepted")
	}
}
func TestSCIMNormalizedProfileAndPatch(t *testing.T) {
	p, err := normalize(map[string]any{"SCHEMAS": []any{UserSchema}, "USERNAME": "Person@Example.test", "Name": map[string]any{"givenname": " A "}, "ACTiVe": "TRUE"})
	if err != nil || p.PrimaryEmail != "person@example.test" || p.DisplayName != "A" || !p.Active {
		t.Fatalf("%+v %v", p, err)
	}
	r := Record{Profile: p}
	for _, ops := range [][]any{
		{map[string]any{"op": "add", "path": "name", "value": map[string]any{"familyName": "Two"}}},
		{map[string]any{"path": UserSchema + ":name.givenName", "value": "Shift"}},
		{map[string]any{"op": "remove", "path": "name.givenName"}},
		{map[string]any{"op": "replace", "value": map[string]any{"title": []any{"Director"}, "timeZone": "UTC"}}},
		{map[string]any{"op": "add", "path": "emails", "value": []any{map[string]any{"type": "work", "value": "second@example.test"}}}},
	} {
		if _, e := patchProfile(r, ops); e != nil {
			t.Fatal(ops, e)
		}
	}
	// Another runtime reads an emails add as an array of values.
	if _, e := patchProfile(r, []any{map[string]any{"op": "add", "path": "emails", "value": map[string]any{"type": "work", "value": "second@example.test"}}}); e == nil {
		t.Fatal("an emails add with a bare object was accepted")
	}
	for _, bad := range []map[string]any{
		{"userName": "no-address"},
		{"userName": "foo@example.test", "emails": []any{map[string]any{"type": "work", "value": "aaa@example.test"}, map[string]any{"type": "WORK", "value": "bbb@example.test"}}},
		{"userName": "foo@example.test", "emails": []any{map[string]any{"primary": true, "value": "one@example.test"}, map[string]any{"primary": "true", "value": "two@example.test"}}},
		{"userName": "foo@example.test", "active": "yes"},
		{"userName": "foo@example.test", "phoneNumbers": []any{map[string]any{"type": "work"}}},
	} {
		bad["schemas"] = []any{UserSchema}
		if _, e := normalize(bad); e == nil {
			t.Fatal("accepted invalid data", bad)
		}
	}
}

func TestSCIMRespectsDisabledHTTPPaths(t *testing.T) {
	host, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity", Secret: strings.Repeat("s", 32), Store: memory.New(), DisabledPaths: []string{"/scim/v2/Users"}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(host, Options{Store: failureStore{}, Connections: []Connection{{Directory: Directory{ID: "hr"}, Credentials: []Credential{{ID: "sync", Token: "key"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		method, route string
		status        int
	}{{"GET", "Users", 404}, {"POST", "Users", 404}, {"GET", "Users/one", 401}, {"GET", "ServiceProviderConfig", 200}} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(item.method, "https://directory.example.test/identity/scim/v2/"+item.route, nil))
		if rec.Code != item.status {
			t.Fatal(item, rec.Code, rec.Body.String())
		}
	}
}

func TestSCIMIdentityNeedsIdentityStore(t *testing.T) {
	host, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", Secret: strings.Repeat("a", 32), Store: memory.New()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(host, Options{Store: failureStore{}, Connections: []Connection{{Directory: Directory{ID: "a"}, Credentials: []Credential{{ID: "one", Token: "token"}}}},
		Identity: &Identity{ResolveUser: func(context.Context, IdentityResolutionInput) (IdentityResolution, error) {
			return IdentityResolution{}, nil
		}}})
	if err == nil || !strings.Contains(err.Error(), "IdentityStore") {
		t.Fatal("scim.New accepted identity resolution on a store that cannot apply it", err)
	}
}

// The discovery documents advertise bearer authentication only, and Bulk,
// /Me, POST search and Basic credentials are refused.
func TestSCIMDiscoveryDocumentsAndRefusedRoutes(t *testing.T) {
	host, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity", Secret: strings.Repeat("a", 32), Store: memory.New()})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(host, Options{Store: failureStore{}, Connections: []Connection{{Directory: Directory{ID: "a"}, Credentials: []Credential{{ID: "one", Token: "one"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, authorization string) (*httptest.ResponseRecorder, map[string]any) {
		r := httptest.NewRequest(method, "https://directory.example.test/identity/scim/v2/"+path, strings.NewReader("{}"))
		r.Header.Set("Content-Type", MediaType)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}
	w, cfg := call("GET", "ServiceProviderConfig", "")
	if w.Code != 200 {
		t.Fatal("service provider config was not served", w.Code)
	}
	if !reflect.DeepEqual(cfg["authenticationSchemes"], []any{map[string]any{"name": "OAuth Bearer Token", "description": "Authentication using a bearer token in the Authorization header.", "specUri": "https://www.rfc-editor.org/info/rfc6750", "type": "oauthbearertoken", "primary": true}}) {
		t.Fatal("service provider config lost its bearer authentication scheme", cfg["authenticationSchemes"])
	}
	if !reflect.DeepEqual(cfg["bulk"], map[string]any{"supported": false, "maxOperations": 0.0, "maxPayloadSize": 0.0}) {
		t.Fatal("service provider config advertised bulk operations", cfg["bulk"])
	}
	if !reflect.DeepEqual(cfg["sort"], map[string]any{"supported": false}) {
		t.Fatal("service provider config advertised sorting", cfg["sort"])
	}
	if !reflect.DeepEqual(cfg["etag"], map[string]any{"supported": false}) {
		t.Fatal("service provider config advertised ETags", cfg["etag"])
	}
	if !reflect.DeepEqual(cfg["changePassword"], map[string]any{"supported": false}) {
		t.Fatal("service provider config advertised password changes", cfg["changePassword"])
	}
	if !reflect.DeepEqual(cfg["patch"], map[string]any{"supported": true}) {
		t.Fatal("service provider config did not advertise PATCH", cfg["patch"])
	}
	if !reflect.DeepEqual(cfg["filter"], map[string]any{"supported": true, "maxResults": 100.0}) {
		t.Fatal("service provider config did not advertise filters with 100 results", cfg["filter"])
	}
	if !reflect.DeepEqual(cfg["schemas"], []any{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}) {
		t.Fatal("service provider config did not declare its schema", cfg["schemas"])
	}
	if !reflect.DeepEqual(cfg["meta"], map[string]any{"resourceType": "ServiceProviderConfig", "location": "https://directory.example.test/identity/scim/v2/ServiceProviderConfig"}) {
		t.Fatal("service provider config meta is not the public directory location", cfg["meta"])
	}
	refusedWith := func(w *httptest.ResponseRecorder, body map[string]any, status int) bool {
		schemas, _ := body["schemas"].([]any)
		return w.Code == status && len(schemas) == 1 && schemas[0] == errorSchema && body["status"] == strconv.Itoa(status)
	}
	if w, body := call("GET", "Schemas/urn:example:unknown:2.0:Thing", ""); !refusedWith(w, body, 404) {
		t.Fatal("an unknown schema ID did not return a SCIM 404", w.Code, w.Body.String())
	}
	if w, body := call("GET", "ResourceTypes/Unknown", ""); !refusedWith(w, body, 404) {
		t.Fatal("an unknown resource type did not return a SCIM 404", w.Code, w.Body.String())
	}
	if w, body := call("GET", "Bulk", "Bearer one"); !refusedWith(w, body, 404) {
		t.Fatal("a Bulk read was not refused with 404", w.Code, w.Body.String())
	}
	if w, body := call("POST", "Bulk", "Bearer one"); !refusedWith(w, body, 404) {
		t.Fatal("a Bulk request was not refused with 404", w.Code, w.Body.String())
	}
	if w, body := call("GET", "Me", "Bearer one"); !refusedWith(w, body, 404) {
		t.Fatal("a Me request was not refused with 404", w.Code, w.Body.String())
	}
	if w, _ := call("POST", "Users/.search", "Bearer one"); w.Code != 405 || w.Header().Get("Allow") != "GET, PUT, PATCH, DELETE" {
		t.Fatal("POST-based User search was not refused with 405", w.Code, w.Header().Get("Allow"))
	}
	if w, _ := call("POST", ".search", "Bearer one"); w.Code != 404 {
		t.Fatal("a root search request was not refused with 404", w.Code)
	}
	if w, body := call("GET", "Users", "Basic b25lOm9uZQ=="); w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Bearer realm="SCIM"` || body["status"] != "401" {
		t.Fatal("Basic authentication was not refused with a bearer challenge", w.Code, w.Header().Get("WWW-Authenticate"), w.Body.String())
	}
}

// Two spellings of one attribute are a syntax error, whether either value
// is null, in a User, a role, a pathless PATCH value or a Group.
func TestSCIMCaseDuplicateAttributesAreInvalidSyntax(t *testing.T) {
	syntax := func(err error) bool {
		var e *Error
		return errors.As(err, &e) && e.Type == "invalidSyntax"
	}
	user := map[string]any{"schemas": []any{UserSchema}, "userName": "a@example.test", "UserName": "b@example.test"}
	if _, err := normalize(user); !syntax(err) {
		t.Fatal("a case-duplicate User attribute was not invalidSyntax", err)
	}
	if _, err := normalize(map[string]any{"schemas": []any{UserSchema}, "userName": "a@example.test", "active": true, "Active": nil}); !syntax(err) {
		t.Fatal("a case-duplicate null attribute was not invalidSyntax", err)
	}
	if _, err := roleObject(map[string]any{"value": "a", "Value": "b"}); !syntax(err) {
		t.Fatal("a case-duplicate role attribute was not invalidSyntax", err)
	}
	current := Record{Profile: Profile{UserName: "a@example.test", PrimaryEmail: "a@example.test", Active: true, Attributes: map[string]any{"schemas": []any{UserSchema}, "name": map[string]any{}, "emails": []any{map[string]any{"value": "a@example.test", "primary": true}}}}}
	ops := []any{map[string]any{"op": "replace", "value": map[string]any{"displayName": "One", "DisplayName": "Two"}}}
	if _, err := patchProfile(current, ops); !syntax(err) {
		t.Fatal("a case-duplicate pathless PATCH value was not invalidSyntax", err)
	}
	if _, err := applyGroupPatch(Group{ID: "g"}, []any{map[string]any{"op": "replace", "value": map[string]any{"displayName": "A", "DisplayName": "B"}}}); !syntax(err) {
		t.Fatal("a Group PATCH value naming displayName twice was not invalidSyntax", err)
	}
	if _, err := parseGroup(map[string]any{"schemas": []any{GroupSchema}, "displayName": "One", "DISPLAYNAME": "Two"}, false); !syntax(err) {
		t.Fatal("a case-duplicate Group attribute was not invalidSyntax", err)
	}
}

// A pathless value applies its keys in sorted order, so "name" lands before
// "name.givenName" every time.
func TestSCIMPathlessPatchKeyOrder(t *testing.T) {
	current := Record{Profile: Profile{UserName: "a@example.test", DisplayName: "Ada", PrimaryEmail: "a@example.test", Active: true, Attributes: map[string]any{"schemas": []any{UserSchema}, "name": map[string]any{}, "emails": []any{map[string]any{"value": "a@example.test", "primary": true}}}}}
	ops := []any{map[string]any{"op": "replace", "value": map[string]any{"name": map[string]any{"givenName": "A"}, "name.givenName": "B"}}}
	for range 50 {
		p, err := patchProfile(current, ops)
		if err != nil {
			t.Fatal(err)
		}
		if p.Attributes["name"].(map[string]any)["givenName"] != "B" {
			t.Fatal("a pathless PATCH applied its keys in a varying order", p.Attributes["name"])
		}
	}
}

// Null values expand into removals that run after the operation's other
// keys; a missing value stays an error.
func TestSCIMUserPatchNullExpansion(t *testing.T) {
	ops, err := expandNulls([]patchOp{
		{op: "replace", path: "title", hasValue: true},
		{op: "add", path: "name", value: []any{map[string]any{"givenName": "A", "familyName": nil}}, hasValue: true},
		{op: "replace", value: map[string]any{"locale": nil, "name": map[string]any{"middleName": nil}}, hasValue: true},
		{op: "replace", path: "emails", value: []any{map[string]any{"value": "a@example.test", "type": nil, "display": map[string]any{"x": nil}}}, hasValue: true},
	})
	want := []patchOp{
		{op: "remove", path: "title"},
		{op: "add", path: "name", value: []any{map[string]any{"givenName": "A"}}, hasValue: true},
		{op: "remove", path: "name.familyName"},
		{op: "remove", path: "locale"},
		{op: "remove", path: "name.middleName"},
		{op: "replace", path: "emails", value: []any{map[string]any{"value": "a@example.test"}}, hasValue: true},
	}
	if err != nil || !reflect.DeepEqual(ops, want) {
		t.Fatal("null PATCH values did not expand into ordered removals", ops, err)
	}
	if _, err := expandNulls([]patchOp{{op: "replace", value: map[string]any{"name": map[string]any{"givenName": "A"}, "Active": nil}, hasValue: true}}); err == nil {
		t.Fatal("a pathless null active expanded")
	}
	r := Record{Profile: Profile{UserName: "a@example.test", Active: true, Attributes: map[string]any{"emails": []any{map[string]any{"value": "a@example.test", "primary": true}}}}}
	if _, err := patchProfile(r, []any{map[string]any{"op": "replace", "path": "title"}}); err == nil {
		t.Fatal("an add or replace without a value was accepted")
	}
}
