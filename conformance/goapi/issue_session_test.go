package goapi_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// When a session create hook skips the session, IssueSessionOr answers the
// endpoint's own error, or 401 FAILED_TO_CREATE_SESSION when it names none,
// and commits nothing.
func TestIssueSessionOrSkipped(t *testing.T) {
	store := memory.New()
	committed := 0
	named := &authn.APIError{Status: 500, Code: "UNABLE_TO_CREATE_SESSION", Message: "Unable to create session"}
	issuer := authn.Plugin{ID: "issuer", Endpoints: []authn.Endpoint{{Method: "POST", Path: "/issue-or", Handler: func(c authn.EndpointContext) (any, error) {
		var skipped error
		if c.Body["named"] == true {
			skipped = named
		}
		return c.IssueSessionOr(skipped, "owner", func(context.Context, authn.StoredSession) (authn.User, error) {
			committed++
			return authn.User{ID: "owner"}, nil
		})
	}}}}
	off := false
	a, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), RateLimit: &off, Plugins: []authn.Plugin{issuer},
		DatabaseHooks: authn.DatabaseHooks{Session: authn.ModelHooks[authn.SessionRecord]{Create: authn.OperationHooks[authn.SessionRecord]{
			Before: func(context.Context, *authn.SessionRecord, *authn.HookContext) error { return authn.ErrSkipWrite },
		}}}})
	if err != nil {
		t.Fatal(err)
	}
	for body, want := range map[string]string{`{}`: `"code":"FAILED_TO_CREATE_SESSION"`, `{"named":true}`: `"code":"UNABLE_TO_CREATE_SESSION"`} {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/issue-or", strings.NewReader(body))
		r.Header.Set("Origin", "https://auth.example")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		status := 401
		if body != `{}` {
			status = 500
		}
		if w.Code != status || !strings.Contains(w.Body.String(), want) || w.Header().Get("Set-Cookie") != "" || committed != 0 {
			t.Fatal("a skipped session was not refused with the endpoint's answer", body, w.Code, w.Body, committed)
		}
	}
}
