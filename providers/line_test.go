package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestLINEChannelTokenVerification(t *testing.T) {
	const channel, nonce = "01234", "browser-state-nonce"
	now := time.Now().Unix()
	for _, tc := range []struct {
		name, field string
		value       any
		allowed     bool
	}{
		{"active channel", "", nil, true},
		{"other channel", "aud", "another", false},
		{"different browser", "nonce", "another", false},
		{"unrecognized issuer", "iss", "https://other.example", false},
		{"expired ID token", "exp", now - 1, false},
		{"unissued ID token", "iat", now + 300, false},
		{"missing email permission", "email", "", false},
		{"empty user ID", "sub", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := LINE(channel, "fixture-secret")
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" || r.URL.String() != "https://api.line.me/oauth2/v2.1/verify" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" {
					t.Fatal("unexpected verification request")
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.PostForm.Get("client_id") != channel || r.PostForm.Get("nonce") != nonce || r.PostForm.Get("id_token") != "id-token" || len(r.PostForm) != 3 {
					t.Fatal("wrong verification grant")
				}
				claims := map[string]any{"iss": lineIssuer, "aud": channel, "nonce": nonce, "iat": now, "exp": now + 900, "sub": "line-user", "email": "jo@example.org", "email_verified": true, "name": "Jo"}
				if tc.field != "" {
					claims[tc.field] = tc.value
				}
				data, err := json.Marshal(claims)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, client)
			token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": "id-token"})
			profile, err := p.Resolve(ctx, token, nonce)
			if tc.allowed {
				if err != nil || profile.Subject != "line-user" || profile.EmailVerified || profile.Name != "Jo" {
					t.Fatal(profile, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid channel identity")
			}
		})
	}
	t.Run("verification refused", func(t *testing.T) {
		p := LINE(channel, "fixture-secret")
		calls := 0
		ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})})
		token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": "rejected"})
		if _, err := p.Resolve(ctx, token, nonce); err == nil || calls != 1 {
			t.Fatal("failed channel verification must stop sign-in", err, calls)
		}
	})
}
