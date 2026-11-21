package openapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/openapi"
)

func TestDeclaredSuccessStatusAndResponseOverrides(t *testing.T) {
	job := stonewrit.Endpoint{
		Method: http.MethodGet, Path: "/job", SuccessStatus: http.StatusAccepted,
		Handler: func(stonewrit.EndpointContext) (any, error) { return true, nil },
	}
	overridden := job
	overridden.Path = "/custom-job"
	overridden.Handler = func(stonewrit.EndpointContext) (any, error) { return stonewrit.HTMLPage("<p>Queued</p>"), nil }
	overridden.OpenAPI = json.RawMessage(`{"responses":{"202":{"description":"Queued for processing","content":{"text/html":{"schema":{"type":"string"}}}},"503":{"description":"Queue unavailable"}}}`)
	silent := overridden
	silent.Path, silent.SuccessStatus, silent.OpenAPI = "/empty-job", http.StatusNoContent, nil
	a, server := fixture(t, openapi.Options{}, stonewrit.Plugin{ID: "jobs", Endpoints: []stonewrit.Endpoint{job, overridden, silent}})
	paths := node(schemaDoc(t, server), "paths")

	for _, route := range a.DescribeHTTP().Routes {
		if route.Path == job.Path && route.SuccessStatus != http.StatusAccepted {
			t.Fatalf("published HTTP status for %s = %d", route.Path, route.SuccessStatus)
		}
	}
	res, body := get(t, server, "/identity/job")
	if res.StatusCode != http.StatusAccepted || !json.Valid(body) {
		t.Fatalf("job handler returned %d %s", res.StatusCode, body)
	}
	result := node(paths, "/job", "get", "responses")
	if result["200"] != nil || node(result, "202", "content", "application/json", "schema") == nil || result["default"] == nil {
		t.Fatalf("declared success response = %v", result)
	}
	html, data := get(t, server, "/identity/custom-job")
	if html.StatusCode != http.StatusAccepted || string(data) != "<p>Queued</p>" {
		t.Fatalf("declared HTML status = %d, body = %q", html.StatusCode, data)
	}
	empty, data := get(t, server, "/identity/empty-job")
	if empty.StatusCode != http.StatusNoContent || len(data) != 0 || node(paths, "/empty-job", "get", "responses", "204")["content"] != nil {
		t.Fatalf("empty operation = %d, body = %q", empty.StatusCode, data)
	}
	custom := node(paths, "/custom-job", "get", "responses")
	if len(custom) != 2 || node(custom, "202")["description"] != "Queued for processing" || custom["503"] == nil {
		t.Fatalf("explicit response map = %v", custom)
	}
	redirect := node(paths, "/reset-password/{token}", "get", "responses")
	if redirect["200"] != nil || node(redirect, "302", "headers", "Location") == nil {
		t.Fatalf("redirect-only endpoint = %v", redirect)
	}
	verify := node(paths, "/verify-email", "get", "responses")
	if verify["200"] == nil || verify["302"] == nil {
		t.Fatalf("conditional redirect = %v", verify)
	}
}
