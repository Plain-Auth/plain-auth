package plainauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/lastlogin"
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
