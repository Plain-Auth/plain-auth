package stonewrit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlite"
	"github.com/Stonewrit/stonewrit-auth/client"
	"golang.org/x/oauth2"
)

func TestOAuthExplicitRegistration(t *testing.T) {
	for _, direct := range []bool{false, true} {
		mode := "browser"
		if direct {
			mode = "ID token"
		}
		t.Run(mode, func(t *testing.T) {
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			profile := auth.OAuthProfile{Subject: "person", Email: "person@example.org", Name: "Person"}
			p := auth.OAuthProvider{
				Config:                oauth2.Config{ClientID: "test", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
				DisableImplicitSignUp: true,
				ExchangeCode: func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
					return &oauth2.Token{AccessToken: "fixture"}, nil
				},
				Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return profile, nil },
				VerifyIDToken: func(context.Context, string, string) (auth.OAuthProfile, time.Time, error) {
					return profile, time.Now().Add(time.Hour), nil
				},
			}
			closed := p
			closed.DisableSignUp = true
			api, err := auth.New(auth.Options{Store: store, BaseURL: base, BasePath: "/identity", Secret: strings.Repeat("s", 32), SocialProviders: map[string]auth.OAuthProvider{"invite": p, "closed": closed}})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = api
			app.Start()
			defer app.Close()
			signin := func(provider, token string, optIn bool) string {
				t.Helper()
				jar, err := cookiejar.New(nil)
				if err != nil {
					t.Fatal(err)
				}
				browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				c, err := client.New(base+"/identity", browser)
				if err != nil {
					t.Fatal(err)
				}
				in := client.SocialSignInRequest{Provider: provider, RequestSignUp: optIn, DisableRedirect: true, CallbackURL: "/signed-in", NewUserCallbackURL: "/welcome", ErrorCallbackURL: "/declined?source=choice"}
				if direct {
					in.IDToken = &client.SocialIDToken{Token: token, Nonce: "nonce"}
				}
				out, err := c.SignInSocial(t.Context(), in)
				if direct {
					var ae *auth.APIError
					if errors.As(err, &ae) && ae.Status == 401 && ae.Code == "OAUTH_LINK_ERROR" {
						return "declined"
					}
					if err != nil || out.User == nil || out.Token == "" || out.User.Email != profile.Email {
						t.Fatal(out, err)
					}
					return "signed-in"
				}
				if err != nil || out.Redirect || out.URL == "" {
					t.Fatal(out, err)
				}
				idp, err := url.Parse(out.URL)
				if err != nil {
					t.Fatal(err)
				}
				cb, err := url.Parse(idp.Query().Get("redirect_uri"))
				if err != nil {
					t.Fatal(err)
				}
				// Consent belongs to the saved authorization request. Callback parameters cannot change it.
				cb.RawQuery = url.Values{"code": {"grant"}, "state": {idp.Query().Get("state")}, "requestSignUp": {"true"}}.Encode()
				response, err := browser.Get(cb.String())
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				next, err := response.Location()
				if err != nil || response.StatusCode != 302 {
					t.Fatal(response.StatusCode, err)
				}
				if next.Path == "/declined" && (next.Query().Get("error") != "signup_disabled" || next.Query().Get("source") != "choice") {
					t.Fatal("unexpected rejection redirect", next)
				}
				return strings.TrimPrefix(next.Path, "/")
			}
			if got := signin("invite", "first", false); got != "declined" {
				t.Fatal("implicit registration", got)
			}
			want := "welcome"
			if direct {
				want = "signed-in"
			}
			if got := signin("invite", "second", true); got != want {
				t.Fatal("explicit registration", got)
			}
			if got := signin("invite", "third", false); got != "signed-in" {
				t.Fatal("existing identity", got)
			}
			profile.Subject, profile.Email = "other", "other@example.org"
			if got := signin("closed", "fourth", true); got != "declined" {
				t.Fatal("disabled registration", got)
			}
		})
	}
}
