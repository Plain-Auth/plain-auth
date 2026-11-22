package stonewrit_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
)

func TestPasswordCallbackFailuresAndCancellation(t *testing.T) {
	private := errors.New("private password service diagnostics")
	gate := make(chan struct{})
	entered := make(chan struct{}, 8)
	var calls atomic.Int32
	off := false
	service := newHTTPAuth(t, auth.Options{BaseURL: "http://auth.example", RateLimit: &off, PasswordHash: func(ctx context.Context, raw string) (string, error) {
		calls.Add(1)
		switch raw {
		case "private failure":
			return "", private
		case "empty credential":
			return "", nil
		}
		entered <- struct{}{}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-gate:
			return "", private
		}
	}})
	for _, password := range []string{"private failure", "empty credential"} {
		body := `{"email":"signup@example.test","name":"Test","password":"` + password + `"}`
		r := serve(t, service, "POST", "/api/auth/sign-up/email", body, http.Header{"Content-Type": {"application/json"}, "Origin": {"http://auth.example"}}, 500)
		data, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || strings.Contains(string(data), "private") || strings.Contains(string(data), "empty credential") {
			t.Fatalf("internal error disclosed %q", data)
		}
	}
	// Hold one callback per available slot while an extra caller cancels.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	results := make(chan error, 8)
	for range 6 {
		go func() {
			_, err := service.SignInEmail(ctx, auth.SignInInput{Email: "absent@example.test", Password: "blocked worker"}, auth.RequestMeta{})
			results <- err
		}()
	}
	<-entered
	cancel()
	for range 6 {
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	close(gate)
	before := calls.Load()
	_, err := service.SignInEmail(ctx, auth.SignInInput{Email: "missing@example.test", Password: "already canceled"}, auth.RequestMeta{})
	if !errors.Is(err, context.Canceled) || before != calls.Load() {
		t.Fatal("canceled request entered a callback", err)
	}
}
