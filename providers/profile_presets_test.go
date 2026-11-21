package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

func TestProfilePresetBrowserSignIn(t *testing.T) {
	var samples map[string]struct {
		Authorize, Token, UserInfo string
		Scopes                     []string
		Input                      json.RawMessage
		Expected                   map[string]any
	}
	data, err := os.ReadFile("testdata/profile_presets.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &samples); err != nil {
		t.Fatal(err)
	}
	for name, sample := range samples {
		t.Run(name, func(t *testing.T) {
			presetName := name
			if name == "slack" {
				presetName = "slack-oidc"
			}
			if !slices.Contains(Names(), presetName) {
				t.Fatalf("%s missing from provider names", name)
			}
			provider, err := New(presetName, "fixture", "secret")
			if err != nil {
				t.Fatal(err)
			}
			const base = "https://app.example/identity"
			callback := base + "/callback/" + name
			var challenge string
			provider.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body []byte
				switch r.URL.String() {
				case sample.Token:
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.Method != "POST" || r.PostForm.Get("client_id") != "fixture" || r.PostForm.Get("client_secret") != "secret" || r.PostForm.Get("code") != "sample" || r.PostForm.Get("redirect_uri") != callback || challenge == "" || oauth2.S256ChallengeFromVerifier(r.PostForm.Get("code_verifier")) != challenge {
						t.Fatal("token request did not match the browser authorization")
					}
					body = []byte(`{"access_token":"access","token_type":"Bearer"}`)
				case sample.UserInfo:
					scheme, method := "Bearer", "GET"
					if name == "yandex" {
						scheme = "OAuth"
					}
					if name == "slack" {
						method = "POST"
					}
					if name == "hubspot" {
						if err := r.ParseForm(); err != nil {
							t.Fatal(err)
						}
						if r.Method != "POST" || r.Header.Get("Authorization") != "" || r.PostForm.Get("client_id") != "fixture" || r.PostForm.Get("client_secret") != "secret" || r.PostForm.Get("token_type_hint") != "access_token" || r.PostForm.Get("token") != "access" {
							t.Fatal("invalid token introspection")
						}
					} else if r.Method != method || r.Header.Get("Authorization") != scheme+" access" {
						t.Fatal("invalid authenticated profile request")
					}
					body = sample.Input
				default:
					t.Fatalf("unexpected request %s", r.URL)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			api, err := auth.New(auth.Options{Store: store, BaseURL: "https://app.example", BasePath: "/identity", Secret: strings.Repeat("x", 32), SocialProviders: map[string]auth.OAuthProvider{name: provider}})
			if err != nil {
				t.Fatal(err)
			}
			start := httptest.NewRequest("POST", base+"/sign-in/social", strings.NewReader(`{"provider":"`+name+`"}`))
			start.Header.Set("Content-Type", "application/json")
			start.Header.Set("Origin", "https://app.example")
			w := httptest.NewRecorder()
			api.ServeHTTP(w, start)
			target, err := url.Parse(w.Header().Get("Location"))
			if err != nil || w.Code != 200 {
				t.Fatal("start", w.Code, err)
			}
			query := target.Query()
			target.RawQuery = ""
			challenge = query.Get("code_challenge")
			if target.String() != sample.Authorize || query.Get("scope") != strings.Join(sample.Scopes, " ") || query.Get("redirect_uri") != callback || query.Get("code_challenge_method") != "S256" {
				t.Fatal("unexpected authorization URL")
			}
			back := httptest.NewRequest("GET", callback+"?code=sample&state="+url.QueryEscape(query.Get("state")), nil)
			for _, c := range w.Result().Cookies() {
				back.AddCookie(c)
			}
			w = httptest.NewRecorder()
			api.ServeHTTP(w, back)
			read := httptest.NewRequest("GET", base+"/get-session", nil)
			for _, c := range w.Result().Cookies() {
				read.AddCookie(c)
			}
			session, err := api.GetSession(t.Context(), read.Header)
			if w.Code != 302 || err != nil || session == nil || session.User.Email != sample.Expected["email"] || session.User.EmailVerified != sample.Expected["emailVerified"] {
				t.Fatal("unexpected sign-in", w.Code, err)
			}
			accounts, err := store.ListUserAccounts(t.Context(), session.User.ID)
			if err != nil || len(accounts) != 1 {
				t.Fatal("account selection", err)
			}
			info, err := api.AccountInfo(t.Context(), nil, auth.AccountSelection{AccountID: accounts[0].ID, UserID: session.User.ID})
			if err != nil || !reflect.DeepEqual(info.Data, sample.Expected) {
				t.Fatal("unexpected account info", info, err)
			}
			subject, exists := sample.Expected["id"]
			if !exists {
				subject = sample.Expected["sub"]
			}
			if info.Account.AccountID != subject {
				t.Fatal("provider subject mismatch")
			}
		})
	}
}

func TestProfilePresetMissingIdentity(t *testing.T) {
	for name := range profilePresets {
		t.Run(name, func(t *testing.T) {
			p, err := New(name, "fixture", "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.Resolve(t.Context(), &oauth2.Token{}, ""); err == nil {
				t.Fatal("accepted empty token")
			}
			if _, err = presetProfile(name, profileData{}); err == nil {
				t.Fatal("accepted incomplete profile")
			}
		})
	}
}

func TestHubSpotTokenIntrospection(t *testing.T) {
	p, err := New("hubspot", "fixture", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		active      bool
		client, use string
		allowed     bool
	}{
		{"active token", true, "fixture", "access_token", true},
		{"inactive token", false, "fixture", "access_token", false},
		{"different client", true, "other", "access_token", false},
		{"refresh token", true, "fixture", "refresh_token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				payload := map[string]any{"active": tc.active, "client_id": tc.client, "token_use": tc.use, "user": "jo@example.org", "signed_access_token": map[string]int{"userId": 321}}
				body, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, client)
			got, err := p.Resolve(ctx, &oauth2.Token{AccessToken: "test-access"}, "")
			if tc.allowed {
				if err != nil || got.Subject != "321" || got.EmailVerified {
					t.Fatal("expected signed user identifier and unverified email", got, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid introspection response")
			}
		})
	}
}
