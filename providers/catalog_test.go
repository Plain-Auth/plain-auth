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
	"strings"
	"testing"

	auth "github.com/FineStack/finestack-auth"
	"github.com/FineStack/finestack-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

func TestCatalogBrowserFlows(t *testing.T) {
	var cases map[string]struct {
		Input, ExpectedData json.RawMessage
		Expected            auth.OAuthProfile
	}
	data, err := os.ReadFile("testdata/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(catalog) {
		t.Fatalf("%d fixtures for %d catalog entries", len(cases), len(catalog))
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			settings := catalog[name]
			provider, err := New(name, "fixture-client", "fixture-secret")
			if err != nil {
				t.Fatal(err)
			}
			var challenge string
			tokenCalls, profileCalls := 0, 0
			provider.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body []byte
				endpoint := r.URL.String()
				if name == "wechat" {
					endpoint, _, _ = strings.Cut(endpoint, "?")
				}
				switch endpoint {
				case settings.Token:
					tokenCalls++
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					id, secret, hasBasic := r.BasicAuth()
					if hasBasic != settings.Basic {
						t.Fatalf("unexpected client auth for %s", name)
					}
					if !hasBasic {
						id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
						if name == "wechat" {
							id, secret = r.Form.Get("appid"), r.Form.Get("secret")
							if r.Method != "GET" {
								t.Fatal("invalid WeChat exchange")
							}
						}
						if name == "tiktok" {
							id = r.Form.Get("client_key")
							if r.Form.Get("client_id") != "" {
								t.Fatal("unexpected client_id")
							}
						}
						if name == "vk" && r.Form.Get("device_id") != "device" {
							t.Fatal("missing VK device ID")
						}
					}
					if id != "fixture-client" || secret != "fixture-secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "fixture-code" {
						t.Fatal("invalid token contract")
					}
					verifier := r.Form.Get("code_verifier")
					if settings.PKCE {
						if oauth2.S256ChallengeFromVerifier(verifier) != challenge {
							t.Fatal("PKCE mismatch")
						}
					} else if verifier != "" && name != "tiktok" {
						t.Fatal("unexpected PKCE")
					}
					body = []byte(`{"access_token":"fixture-access","token_type":"Bearer","expires_in":3600,"openid":"wechat-open","scope":"snsapi_login"}`)
				case settings.Profile:
					profileCalls++
					if name == "vk" {
						if err := r.ParseForm(); err != nil || r.PostForm.Get("access_token") != "fixture-access" || r.PostForm.Get("client_id") != "fixture-client" {
							t.Fatal("VK profile requirements")
						}
					} else if name == "wechat" {
						if r.URL.Query().Get("access_token") != "fixture-access" || r.URL.Query().Get("openid") != "wechat-open" || r.URL.Query().Get("lang") != "zh_CN" {
							t.Fatal("WeChat profile requirements")
						}
					} else if r.Header.Get("Authorization") != "Bearer fixture-access" {
						t.Fatal("missing bearer")
					}
					if r.Method != settings.Method {
						t.Fatal("incorrect profile request")
					}
					for k, v := range settings.Headers {
						if r.Header.Get(k) != v {
							t.Fatalf("missing header %s", k)
						}
					}
					if settings.ProfileBody != "" {
						data, err := io.ReadAll(r.Body)
						if err != nil || string(data) != settings.ProfileBody {
							t.Fatalf("profile request body, %v", err)
						}
					}
					body = fixture.Input
				default:
					switch {
					case name == "facebook" && r.URL.Host == "graph.facebook.com" && r.URL.Path == "/debug_token":
						if r.URL.Query().Get("input_token") != "fixture-access" || r.URL.Query().Get("access_token") != "fixture-client|fixture-secret" {
							t.Fatal("Facebook binding")
						}
						body = []byte(`{"data":{"app_id":"fixture-client","is_valid":true,"user_id":"fb-person"}}`)
					case name == "twitter" && r.URL.String() == "https://api.x.com/2/users/me?user.fields=confirmed_email":
						if r.Header.Get("Authorization") != "Bearer fixture-access" {
							t.Fatal("Twitter email credential")
						}
						body = []byte(`{"data":{"confirmed_email":"person@example.org"}}`)
					default:
						t.Fatalf("unexpected remote endpoint %s", r.URL)
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			const base = "https://app.example.org"
			h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, SocialProviders: map[string]auth.OAuthProvider{name: provider}})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(map[string]string{"provider": name, "callbackURL": "/done"})
			req := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", base)
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != 200 {
				t.Fatalf("start %d %s", res.Code, res.Body)
			}
			target, err := url.Parse(res.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			q := target.Query()
			target.RawQuery = ""
			if target.String() != settings.Authorization || q.Get("scope") != strings.Join(settings.Scopes, " ") {
				t.Fatal("unexpected authorization contract")
			}
			for k, v := range settings.Params {
				if q.Get(k) != v {
					t.Fatalf("param %s", k)
				}
			}
			if name == "wechat" && (q.Get("appid") != "fixture-client" || q.Has("client_id")) {
				t.Fatal("invalid WeChat authorization")
			}
			if name == "tiktok" && (q.Get("client_key") != "fixture-client" || q.Has("client_id")) {
				t.Fatal("invalid TikTok authorization")
			}
			challenge = q.Get("code_challenge")
			if (challenge != "") != settings.PKCE {
				t.Fatal("authorization PKCE mismatch")
			}
			req = httptest.NewRequest("GET", base+"/api/auth/callback/"+name+"?code=fixture-code&device_id=device&state="+url.QueryEscape(q.Get("state")), nil)
			for _, c := range res.Result().Cookies() {
				req.AddCookie(c)
			}
			res = httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != 302 || tokenCalls != 1 || profileCalls != 1 {
				t.Fatalf("finish %d %s (token/profile %d/%d)", res.Code, res.Body, tokenCalls, profileCalls)
			}
			req = httptest.NewRequest("GET", base+"/api/auth/get-session", nil)
			for _, c := range res.Result().Cookies() {
				if strings.HasSuffix(c.Name, "session_token") {
					req.AddCookie(c)
				}
			}
			res = httptest.NewRecorder()
			h.ServeHTTP(res, req)
			var result auth.SessionResult
			if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			actual := result.User
			want := fixture.Expected
			if actual.Email != want.Email || actual.EmailVerified != want.EmailVerified || actual.Name != want.Name || !reflect.DeepEqual(actual.Image, want.Image) {
				t.Fatalf("profile %#v, want %#v", actual, want)
			}
			// The account-info route returns the provider-defined profile object.
			linked, err := store.ListUserAccounts(context.Background(), actual.ID)
			if err != nil || len(linked) != 1 {
				t.Fatalf("linked account %v %v", linked, err)
			}
			// WeChat supplies its openID only in the initial code exchange.
			// Its userinfo API needs that transient field even when an account
			// is linked by unionID and credentials are stored without it.
			if name != "wechat" {
				info, err := h.AccountInfo(context.Background(), nil, auth.AccountSelection{AccountID: linked[0].ID, UserID: actual.ID})
				if err != nil {
					t.Fatal(err)
				}
				var wantData, actualData any
				db, err := json.Marshal(info.Data)
				if err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(fixture.ExpectedData, &wantData); err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(db, &actualData); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actualData, wantData) {
					t.Fatalf("account data %#v, want %#v", actualData, wantData)
				}
			}
			// A second lookup checks the stable subject separately from user.id.
			dec := json.NewDecoder(bytes.NewReader(fixture.Input))
			dec.UseNumber()
			var profile profileData
			if err := dec.Decode(&profile); err != nil {
				t.Fatal(err)
			}
			mapped, err := mapProfile(name, profile)
			if err != nil || mapped.Subject != want.Subject {
				t.Fatalf("subject %q, want %q (%v)", mapped.Subject, want.Subject, err)
			}
		})
	}
}

func TestCatalogIdentityBinding(t *testing.T) {
	for _, tc := range []struct {
		name, profile, secondary, token string
		valid, verified                 bool
	}{
		{"facebook", `{"id":"person","email":"person@example.org"}`, `{"data":{"app_id":"other","user_id":"person","is_valid":true}}`, "", false, false},
		{"facebook", `{"id":"other","email":"person@example.org"}`, `{"data":{"app_id":"client","user_id":"person","is_valid":true}}`, "", false, false},
		{"twitter", `{"data":{"id":"person","name":"X User"}}`, `{}`, "", true, false},
		{"kakao", `{"id":28,"kakao_account":{"is_email_valid":false,"is_email_verified":true,"email":"person@example.org"}}`, "", "", true, false},
		{"paypal", `{"user_id":"one","email":"person@example.org","email_verified":true}`, "", "header.eyJzdWIiOiJ0d28ifQ.signature", false, false},
		{"paypal", `{"user_id":"one","sub":"two","email":"person@example.org","email_verified":true}`, "", "header.eyJzdWIiOiJ0d28ifQ.signature", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(tc.name, "client", "secret")
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := tc.profile
				if r.URL.Path == "/debug_token" || r.URL.Query().Get("user.fields") == "confirmed_email" {
					body = tc.secondary
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": tc.token})
			actual, err := p.Resolve(ctx, token, "")
			if (err == nil) != tc.valid || actual.EmailVerified != tc.verified {
				t.Fatalf("result %#v, err %v", actual, err)
			}
		})
	}
}

func TestCatalogRefreshContracts(t *testing.T) {
	for name, e := range catalog {
		t.Run(name, func(t *testing.T) {
			p, err := New(name, "client", "secret")
			if err != nil {
				t.Fatal(err)
			}
			if e.Refresh == nil {
				if !p.DisableRefresh {
					t.Fatal("unexpected refresh support")
				}
				return
			}
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				endpoint := *r.URL
				endpoint.RawQuery = ""
				if endpoint.String() != e.Refresh.URL || r.Method != e.Refresh.Method {
					t.Fatalf("unexpected refresh %s %s", r.Method, endpoint.String())
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("refresh_token") != "rotate" || r.Form.Get("grant_type") != "refresh_token" {
					t.Fatal("unexpected refresh grant")
				}
				u, pw, basic := r.BasicAuth()
				if basic != e.Refresh.Basic || (basic && (u != "client" || pw != "secret")) {
					t.Fatal("refresh auth style")
				}
				if len(r.Form) != len(e.Refresh.Fields) {
					t.Fatalf("unexpected field count %d", len(r.Form))
				}
				for _, k := range e.Refresh.Fields {
					if r.Form.Get(k) == "" {
						t.Fatalf("missing refresh field %s", k)
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"access_token":"new","refresh_token":"new-refresh","expires_in":480,"token_type":"Bearer"}`))}, nil
			})}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			token, err := p.Refresh(ctx, p.Config, "rotate")
			if err != nil || token.AccessToken != "new" || token.RefreshToken != "new-refresh" || token.Expiry.IsZero() {
				t.Fatalf("refresh %v %v", token, err)
			}
		})
	}
}
