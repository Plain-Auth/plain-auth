package openapi_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/openapi"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestProfileFieldContracts(t *testing.T) {
	fields := map[string]auth.UserField{
		"locale":       {Type: auth.FieldString, Required: true, Column: "preferred_locale"},
		"count":        {Type: auth.FieldNumber, Required: true, Default: 4},
		"flag":         {Type: auth.FieldBoolean},
		"code":         {Type: auth.FieldNumber},
		"otp":          {Type: auth.FieldBoolean},
		"accountClass": {Type: auth.FieldString, ServerOnly: true, Default: "private-default"},
		"privateNote":  {Type: auth.FieldString, Hidden: true},
		"internalRisk": {Type: auth.FieldNumber, Hidden: true, ServerOnly: true},
	}
	store, err := sqlstore.OpenWithAdditionalFields(t.Context(), "sqlite", filepath.Join(t.TempDir(), "profile.sqlite"), []string{"admin", "phone-number"}, schema.AdditionalFields{User: fields})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	api, err := openapi.New(openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := auth.NewAdmin(auth.AdminOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		enableRegistration bool
	}{{"registration", true}, {"established accounts", false}} {
		t.Run(tc.name, func(t *testing.T) {
			enabled := tc.enableRegistration
			otp, err := auth.NewEmailOTP(auth.EmailOTPOptions{DisableSignUp: !enabled, Send: func(context.Context, auth.EmailOTPMessage) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			var signup *auth.PhoneSignUpOptions
			if enabled {
				signup = &auth.PhoneSignUpOptions{GetTempEmail: func(n string) string { return n + "@example.test" }}
			}
			phone, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{SignUpOnVerification: signup})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://profiles.example.test"
			host, err := auth.New(auth.Options{BaseURL: origin, BasePath: "/identity", Store: store, Secret: strings.Repeat("x", 40), EmailAndPassword: true, UserAdditionalFields: fields, Plugins: []auth.Plugin{api, admin, otp, phone}})
			if err != nil {
				t.Fatal(err)
			}
			w := ssoWire{t, host, origin}
			doc := w.decode(w.call("GET", "/open-api/generate-schema", nil, nil, 200))
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{"internalRisk", "preferred_locale", "private-default"} {
				if strings.Contains(string(raw), private) {
					t.Fatal("leaked private configuration", private)
				}
			}
			user := node(doc, "components", "schemas", "User")
			out := node(user, "properties")
			if out["accountClass"] == nil || out["privateNote"] != nil || !slices.Contains(user["required"].([]any), any("count")) {
				t.Fatal("public user output", user)
			}
			body := func(path string) obj {
				return node(doc, "paths", path, "post", "requestBody", "content", "application/json", "schema")
			}
			for _, p := range []string{"/sign-up/email", "/update-user", "/admin/create-user"} {
				s := body(p)
				if p == "/admin/create-user" {
					if !slices.Contains(s["required"].([]any), any("data")) {
						t.Fatal("admin create must require data")
					}
					s = node(s, "properties", "data")
				}
				req, _ := s["required"].([]any)
				if slices.Contains(req, any("locale")) != (p != "/update-user") || slices.Contains(req, any("count")) {
					t.Fatal("incorrect required inputs", p, req)
				}
				props := node(s, "properties")
				if props["accountClass"] != nil || node(props, "privateNote")["writeOnly"] != true || node(props, "count")["minimum"] != float64(math.MinInt32) || node(props, "count")["maximum"] != float64(math.MaxInt32) {
					t.Fatal("wrong custom request fields", p, props)
				}
			}
			for _, p := range []string{"/phone-number/verify", "/sign-in/email-otp"} {
				s := body(p)
				if slices.Contains(s["required"].([]any), any("locale")) || (node(s, "properties", "locale") != nil) != enabled {
					t.Fatal("wrong conditional registration input", p)
				}
				if enabled && node(s, "properties", "locale")["description"] != "Required when creating a user." {
					t.Fatal("missing first registration requirement", p)
				}
			}
			if node(body("/phone-number/verify"), "properties", "code")["type"] != "string" || node(body("/sign-in/email-otp"), "properties", "otp")["type"] != "string" {
				t.Fatal("profile setting shadowed a credential")
			}
			form := node(doc, "paths", "/sign-up/email", "post", "requestBody", "content", "application/x-www-form-urlencoded", "schema", "properties")
			if form["count"] != false || node(form, "locale")["type"] != "string" {
				t.Fatal("form schema accepted non-text inputs", form)
			}
			if !enabled {
				return
			}
			formBody := url.Values{"name": {"Form User"}, "email": {"form@profiles.test"}, "password": {"local fixture password"}, "locale": {"fr"}}
			formStatus := func(want int) {
				t.Helper()
				req := httptest.NewRequest("POST", origin+"/identity/sign-up/email", strings.NewReader(formBody.Encode()))
				req.RemoteAddr = "192.0.2.9:10000"
				req.Header.Set("Origin", origin)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()
				host.ServeHTTP(rec, req)
				if rec.Code != want {
					t.Fatalf("form signup status %d, want %d", rec.Code, want)
				}
			}
			formBody.Set("count", "5")
			formStatus(400)
			formBody.Del("count")
			formStatus(200)
			payload := obj{"name": "Profile", "email": "owner@profiles.test", "password": "local fixture password"}
			w.call("POST", "/sign-up/email", payload, nil, 400)
			payload["locale"], payload["privateNote"] = "fr", "private fixture note"
			created := w.decode(w.call("POST", "/sign-up/email", payload, nil, 200))
			profile := node(created, "user")
			if profile["locale"] != "fr" || profile["count"] != float64(4) || profile["accountClass"] != "private-default" || profile["privateNote"] != nil {
				t.Fatal("response violates public user schema")
			}
			h := http.Header{"Cookie": {host.SessionCookie(created["token"].(string), true).String()}}
			w.call("POST", "/update-user", obj{"flag": true}, h, 200)
			if node(w.decode(w.call("GET", "/get-session", nil, h, 200)), "user")["flag"] != true {
				t.Fatal("optional patch was not published")
			}
		})
	}
}

func TestSignupWithRequiredNonTextFieldUsesJSON(t *testing.T) {
	fields := map[string]auth.UserField{"accepted": {Type: auth.FieldBoolean, Required: true}}
	store, err := sqlstore.OpenWithAdditionalFields(t.Context(), "sqlite", filepath.Join(t.TempDir(), "form.sqlite"), nil, schema.AdditionalFields{User: fields})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host, err := auth.New(auth.Options{BaseURL: "https://docs.test", Secret: strings.Repeat("z", 40), Store: store, EmailAndPassword: true, UserAdditionalFields: fields})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi.Generate(host)
	if err != nil {
		t.Fatal(err)
	}
	content := node(doc, "paths", "/sign-up/email", "post", "requestBody", "content")
	if content["application/json"] == nil || content["application/x-www-form-urlencoded"] != nil {
		t.Fatal("form signup cannot supply the required boolean", content)
	}
}

func TestConfiguredDateSchemasAndSignupForm(t *testing.T) {
	fields := map[string]auth.UserField{"reviewedAt": {Type: auth.FieldDate, Required: true}}
	sessions := map[string]auth.SessionField{"remindAt": {Type: auth.FieldDate}}
	store, err := sqlstore.OpenWithAdditionalFields(t.Context(), "sqlite", filepath.Join(t.TempDir(), "dates.db"), nil, schema.AdditionalFields{User: fields, Session: sessions})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p, err := openapi.New(openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://dates.example.test"
	a, err := auth.New(auth.Options{Store: store, BaseURL: origin, BasePath: "/identity", Secret: strings.Repeat("k", 40), EmailAndPassword: true, UserAdditionalFields: fields, SessionAdditionalFields: sessions, Plugins: []auth.Plugin{p}})
	if err != nil {
		t.Fatal(err)
	}
	w := ssoWire{t, a, origin}
	doc := w.decode(w.call("GET", "/open-api/generate-schema", nil, nil, 200))
	for _, media := range []string{"application/json", "application/x-www-form-urlencoded"} {
		body := node(doc, "paths", "/sign-up/email", "post", "requestBody", "content", media, "schema")
		property := node(body, "properties", "reviewedAt")
		if property["type"] != "string" || property["format"] != "date-time" || !slices.Contains(body["required"].([]any), any("reviewedAt")) {
			t.Fatalf("%s date input %v", media, property)
		}
	}
	for model, name := range map[string]string{"Session": "remindAt", "User": "reviewedAt"} {
		if node(doc, "components", "schemas", model, "properties", name)["format"] != "date-time" {
			t.Fatalf("missing format for %s.%s", model, name)
		}
	}
	body := url.Values{"name": {"Reader"}, "email": {"reader@example.test"}, "password": {"local fixture password"}, "reviewedAt": {"2025-03-23T15:04:05-04:00"}}
	req := httptest.NewRequest("POST", origin+"/identity/sign-up/email", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	out := httptest.NewRecorder()
	a.ServeHTTP(out, req)
	if out.Code != 200 || node(w.decode(out), "user")["reviewedAt"] != "2025-03-23T19:04:05.000Z" {
		t.Fatalf("form sign-up returned %d", out.Code)
	}
}
