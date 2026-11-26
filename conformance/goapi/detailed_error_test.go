package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
)

// A DetailedError answers with its details object beside code and message,
// keeps the details when the message is translated, and reaches the Go
// client as a DetailedError that still unwraps to its APIError.
func TestDetailedErrorResponse(t *testing.T) {
	limited := &authn.APIError{Status: 429, Code: "RATE_LIMITED", Message: "Rate limit exceeded."}
	plugin := authn.Plugin{ID: "limited", Endpoints: []authn.Endpoint{{Method: "GET", Path: "/limited", Handler: func(authn.EndpointContext) (any, error) {
		return nil, &authn.DetailedError{APIError: limited, Details: map[string]any{"tryAgainIn": 1500}}
	}}}}
	translator := authn.Plugin{ID: "translator", TranslateError: func(_ authn.ErrorContext, e authn.APIError) string {
		if e.Code == "RATE_LIMITED" {
			return "Zu viele Anfragen."
		}
		return ""
	}}
	off := false
	for _, translated := range []bool{false, true} {
		plugins := []authn.Plugin{plugin}
		if translated {
			plugins = append(plugins, translator)
		}
		a, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), RateLimit: &off, Plugins: plugins})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example/api/auth/limited", nil))
		var body struct {
			Code, Message, OriginalMessage string
			Details                        map[string]float64
		}
		if w.Code != 429 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != "RATE_LIMITED" || body.Details["tryAgainIn"] != 1500 {
			t.Fatal("a detailed error was answered without its details", w.Code, w.Body)
		}
		if translated && (body.Message != "Zu viele Anfragen." || body.OriginalMessage != "Rate limit exceeded.") {
			t.Fatal("a translated detailed error lost its message pair", w.Body)
		}

		server := httptest.NewServer(a)
		c, err := client.New(server.URL, &http.Client{})
		if err != nil {
			t.Fatal(err)
		}
		err = c.Do(context.Background(), "GET", "/limited", nil, nil)
		server.Close()
		var detailed *authn.DetailedError
		var api *authn.APIError
		if !errors.As(err, &detailed) || detailed.Details["tryAgainIn"] != float64(1500) || !errors.As(err, &api) || api.Status != 429 || api.Code != "RATE_LIMITED" {
			t.Fatalf("the client did not decode the details: %#v", err)
		}
	}
}
