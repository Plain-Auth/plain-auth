package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/lastlogin"
)

type failingLoginPreference struct{}

func (failingLoginPreference) SaveSessionLoginMethod(context.Context, string, string, time.Time) error {
	return errors.New("private preference failure")
}
func (failingLoginPreference) UserLoginMethod(context.Context, string) (string, error) {
	return "", nil
}

func TestPerInstanceLogger(t *testing.T) {
	var captured bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&captured, &slog.HandlerOptions{Level: slog.LevelError})).With("service", "customer")
	send := true
	opts := auth.Options{
		BaseURL: "https://auth.example", Logger: logger, SendVerificationOnSignUp: &send,
		SendVerificationEmail: func(context.Context, auth.MailLink) error { return errors.New("private mail credentials") },
		Plugins:               []auth.Plugin{lastlogin.New(lastlogin.Options{Database: failingLoginPreference{}})},
	}
	first := newHTTPAuth(t, opts)
	opts.Logger = slog.New(slog.DiscardHandler)
	muted := newHTTPAuth(t, opts)
	email := "private-address@example.test"
	payload := `{"email":"` + email + `","name":"Private Customer","password":"secret-password"}`
	headers := http.Header{"Content-Type": {"application/json"}, "Origin": {"https://auth.example"}}
	serve(t, muted, http.MethodPost, "/api/auth/sign-up/email", payload, headers, 200)
	if captured.Len() != 0 {
		t.Fatal("silenced instance leaked its records into another instance")
	}
	first.Logger().WarnContext(t.Context(), "below the configured level")
	serve(t, first, http.MethodPost, "/api/auth/sign-up/email", payload, headers, 200)
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(captured.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil || event["level"] != "ERROR" || event["service"] != "customer" {
			t.Fatalf("unexpected auth record %v: %v", event, err)
		}
		events = append(events, event)
	}
	if len(events) != 2 || events[0]["msg"] != "Could not deliver sign-up verification email" || events[1]["msg"] != "Could not save last login method" {
		t.Fatal("expected the mail and plugin errors from the selected instance", events)
	}
	for _, s := range []string{email, "secret-password", "private mail credentials", "private preference failure", "Private Customer"} {
		if strings.Contains(captured.String(), s) {
			t.Fatal("sensitive account or callback data in diagnostics")
		}
	}
	opts.Logger = nil
	if newHTTPAuth(t, opts).Logger() != slog.Default() {
		t.Fatal("default logger did not follow the host")
	}
}

// The host logger's level decides which records are kept: Plain Auth logs
// warnings and errors itself, and a plugin's debug and info records go
// through the same logger.
func TestLoggerLevels(t *testing.T) {
	for _, tc := range []struct {
		level slog.Level
		want  []string
	}{
		{slog.LevelDebug, []string{"DEBUG", "INFO", "WARN", "ERROR"}},
		{slog.LevelInfo, []string{"INFO", "WARN", "ERROR"}},
		{slog.LevelWarn, []string{"WARN", "ERROR"}},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			var captured bytes.Buffer
			send, on := true, true
			a := newHTTPAuth(t, auth.Options{BaseURL: "https://auth.example", RateLimit: &on, SendVerificationOnSignUp: &send,
				Logger:                slog.New(slog.NewJSONHandler(&captured, &slog.HandlerOptions{Level: tc.level})),
				SendVerificationEmail: func(context.Context, auth.MailLink) error { return errors.New("mail is down") }})
			a.Logger().DebugContext(t.Context(), "plugin debug")
			a.Logger().InfoContext(t.Context(), "plugin info")
			// A request whose client address is unknown logs a warning, and a
			// failed sign-up mail logs an error.
			r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"email":"ada@example.test","name":"Ada","password":"a password for logging"}`))
			r.Header = http.Header{"Content-Type": {"application/json"}, "Origin": {"https://auth.example"}}
			r.RemoteAddr = ""
			a.ServeHTTP(httptest.NewRecorder(), r)
			var levels []string
			for _, line := range strings.Split(strings.TrimSpace(captured.String()), "\n") {
				var event map[string]any
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatal(err)
				}
				if level, _ := event["level"].(string); !slices.Contains(levels, level) {
					levels = append(levels, level)
				}
			}
			if !slices.Equal(levels, tc.want) {
				t.Fatalf("a %s logger kept %v, want %v: %s", tc.level, levels, tc.want, captured.String())
			}
		})
	}
}
