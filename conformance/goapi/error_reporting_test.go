package goapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

func TestHTTPErrorReporterPreservesEndpointResponse(t *testing.T) {
	private := errors.New("private database error")
	for _, outcome := range []string{"reported", "failed", "panicked"} {
		t.Run(outcome, func(t *testing.T) {
			var logs bytes.Buffer
			report := make(chan error, 1)
			release := make(chan struct{})
			opts := auth.Options{BaseURL: "https://auth.example", Logger: slog.New(slog.NewTextHandler(&logs, nil)),
				Plugins: []auth.Plugin{{ID: "reports", Endpoints: []auth.Endpoint{{Method: "GET", Path: "/fault", Handler: func(auth.EndpointContext) (any, error) { return nil, private }}}}},
				OnAPIError: func(c auth.ErrorContext, e error) error {
					if c.Request.URL.Path != "/api/auth/fault" || c.User != nil {
						t.Error("unexpected report context")
					}
					report <- e
					<-release
					switch outcome {
					case "failed":
						return errors.New("private reporter credentials")
					case "panicked":
						panic("private reporter credentials")
					}
					return nil
				},
			}
			host := newHTTPAuth(t, opts)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				host.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://auth.example/api/auth/fault", nil))
			}()
			select {
			case e := <-report:
				if !errors.Is(e, private) {
					t.Error("reporter lost original error", e)
				}
			case <-done:
				t.Fatal("handler returned without reporting the endpoint error")
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("no error callback received")
			}
			select {
			case <-done:
				t.Error("handler completed before the reporting callback")
			default:
			}
			close(release)
			<-done
			if rec.Code != 500 || !strings.Contains(rec.Body.String(), "INTERNAL_SERVER_ERROR") || strings.Contains(rec.Body.String(), "private") {
				t.Fatal("reporter replaced the endpoint response", rec.Code, rec.Body)
			}
			want := ""
			if outcome == "failed" {
				want = "Authentication error reporter failed"
			}
			if outcome == "panicked" {
				want = "Authentication error reporter panicked"
			}
			if (want == "" && logs.Len() != 0) || !strings.Contains(logs.String(), want) || strings.Contains(logs.String(), "private") {
				t.Fatal("unexpected reporter log", logs.String())
			}
			host.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://auth.example/api/auth/ok", nil))
			host.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://auth.example/not-mounted", nil))
			if len(report) != 0 {
				t.Fatal("success or unmatched route produced an error report")
			}
		})
	}
}

func TestHTTPErrorReporterSeesResolvedIdentityBeforeTranslation(t *testing.T) {
	const route = "/business-rule"
	var report error
	var identity string
	opts := auth.Options{BaseURL: "https://auth.example",
		OnAPIError: func(c auth.ErrorContext, e error) error {
			report = e
			if c.User != nil {
				identity = c.User.ID
			}
			return nil
		},
		Plugins: []auth.Plugin{{ID: "business", TranslateError: func(_ auth.ErrorContext, e auth.APIError) string {
			if e.Code == "RULE" {
				return "Translated message"
			}
			return ""
		},
			Endpoints: []auth.Endpoint{{Method: "GET", Path: route, Handler: func(c auth.EndpointContext) (any, error) {
				s, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
				if err != nil {
					return nil, err
				}
				if s == nil {
					return nil, errors.New("missing fixture session")
				}
				return nil, &auth.APIError{Status: 409, Code: "RULE", Message: "Original message"}
			}}},
		}},
	}
	host := newHTTPAuth(t, opts)
	registered := serve(t, host, "POST", "/api/auth/sign-up/email", `{"email":"u@example.test","name":"User","password":"test-password"}`, http.Header{"Content-Type": {"application/json"}, "Origin": {"https://auth.example"}}, 200)
	var created auth.AuthResult
	if err := json.NewDecoder(registered.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://auth.example/api/auth"+route, nil)
	for _, c := range registered.Cookies() {
		req.AddCookie(c)
	}
	res := httptest.NewRecorder()
	host.ServeHTTP(res, req)
	var apiErr *auth.APIError
	if !errors.As(report, &apiErr) || apiErr.Message != "Original message" || identity != created.User.ID || res.Code != 409 || !strings.Contains(res.Body.String(), "Translated message") {
		t.Fatal("reported error, identity or translation changed", report, identity, res.Code, res.Body)
	}
}
