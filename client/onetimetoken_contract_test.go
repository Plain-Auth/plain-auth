package client_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/onetimetoken"
)

func TestTransferCallbackFailures(t *testing.T) {
	for _, stage := range []string{"generate", "hash", "identifier"} {
		for _, failure := range []string{"error", "panic", "cancel"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				const origin = "https://callbacks.example.test"
				const private = "private-callback-error-material"
				sentinel := errors.New(private)
				var cancel context.CancelFunc
				fail := true
				raw := strings.Repeat("a", 400)
				callback := func(value string) (string, error) {
					if fail {
						switch failure {
						case "error":
							return "", sentinel
						case "panic":
							panic(private)
						case "cancel":
							if cancel != nil {
								cancel()
								return value, nil
							}
							return "", context.Canceled
						}
					}
					return value, nil
				}
				opts := onetimetoken.Options{
					SetHeaderOnNewSession: true,
					GenerateToken: func(context.Context, auth.SessionResult) (string, error) {
						if stage == "generate" {
							return callback(raw)
						}
						return raw, nil
					},
					HashToken: func(context.Context, string) (string, error) {
						if stage == "hash" {
							return callback("stored-key")
						}
						return "stored-key", nil
					},
				}
				p, err := onetimetoken.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				var logs bytes.Buffer
				server, err := auth.New(auth.Options{
					Store: memory.New(), BaseURL: origin, Secret: strings.Repeat("r", 40),
					EmailAndPassword: true, Plugins: []auth.Plugin{p},
					Logger: slog.New(slog.NewTextHandler(&logs, nil)),
					StoreVerificationIdentifier: auth.VerificationIdentifierStorage{Hash: func(_ context.Context, identifier string) (string, error) {
						if stage == "identifier" {
							return callback("id-" + identifier)
						}
						return "id-" + identifier, nil
					}},
				})
				if err != nil {
					t.Fatal(err)
				}
				var response http.Header
				c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
					w := httptest.NewRecorder()
					server.ServeHTTP(w, r)
					response = w.Header()
					if strings.Contains(w.Body.String(), private) {
						t.Fatal("callback detail reached HTTP response")
					}
					return w.Result(), nil
				})})
				if err != nil {
					t.Fatal(err)
				}
				owner, err := c.SignUpEmail(t.Context(), client.SignUpRequest{Name: "Owner", Email: "owner@example.test", Password: "fixture-password"})
				if err != nil || owner.Token == nil || *owner.Token == "" || response.Get("Set-Ott") != "" || strings.Contains(response.Get("Access-Control-Expose-Headers"), "set-ott") {
					t.Fatal("optional token failure disrupted login or published a credential", err)
				}
				if strings.Contains(logs.String(), private) {
					t.Fatal("optional header log leaked callback detail")
				}
				if _, err := c.GenerateOneTimeToken(t.Context()); err == nil {
					t.Fatal("explicit issuance ignored callback failure")
				}
				cookie := server.SessionCookie(*owner.Token, true)
				header := http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
				ctx, stop := context.WithCancel(t.Context())
				cancel = stop
				_, err = server.GenerateOneTimeToken(ctx, header)
				stop()
				if err == nil || failure == "error" && !errors.Is(err, sentinel) || failure == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("explicit native generation lost callback failure", err)
				}
				fail = false
				proof, err := server.GenerateOneTimeToken(t.Context(), header)
				if err != nil || proof != raw {
					t.Fatal("hashed long token generation failed", err)
				}
				if stage != "generate" {
					fail = true
					ctx, stop = context.WithCancel(t.Context())
					cancel = stop
					_, err = server.VerifyOneTimeToken(ctx, proof)
					stop()
					if err == nil {
						t.Fatal("redemption ignored hash failure")
					}
					fail = false
				}
				got, err := server.VerifyOneTimeToken(t.Context(), proof)
				if err != nil || got.Session.Token != *owner.Token {
					t.Fatal("retry lost unconsumed proof", err)
				}
				if _, err := server.VerifyOneTimeToken(t.Context(), proof); err == nil {
					t.Fatal("callback recovery allowed replay")
				}
			})
		}
	}
}

func TestTransferLifetimeConfiguration(t *testing.T) {
	for _, options := range []onetimetoken.Options{
		{ExpiresIn: -time.Second},
		{ExpiresIn: time.Minute, ExpireImmediately: true},
		{HashTokens: true, HashToken: func(context.Context, string) (string, error) { return "", nil }},
	} {
		if _, err := onetimetoken.New(options); err == nil {
			t.Fatal("ambiguous or invalid transfer configuration accepted")
		}
	}
}
