package stonewrit_test

import (
	"context"
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

func TestProviderLogoutRevokesOwnerSession(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := httptest.NewUnstartedServer(nil)
	base := "http://" + h.Listener.Addr().String()
	profile := auth.OAuthProfile{Subject: "user", Email: "jo@example.org", Name: "Jo"}
	p := auth.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}}, EndSessionEndpoint: "https://id.example/end?tenant=work", PostLogoutRedirectURI: "/bye",
		Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return profile, nil },
		VerifyIDToken: func(context.Context, string, string) (auth.OAuthProfile, time.Time, error) {
			return profile, time.Now().Add(time.Hour), nil
		},
	}
	api, err := auth.New(auth.Options{BaseURL: base, BasePath: "/account", Secret: strings.Repeat("x", 32), Store: store, EncryptOAuthTokens: true, SocialProviders: map[string]auth.OAuthProvider{"work": p}})
	if err != nil {
		t.Fatal(err)
	}
	h.Config.Handler = api
	h.Start()
	defer h.Close()
	for _, disable := range []bool{true, false} {
		c, err := client.New(base+"/account", nil)
		if err != nil {
			t.Fatal(err)
		}
		raw := "test-id-grant"
		if disable {
			raw += "-one"
		}
		_, err = c.SignInSocial(t.Context(), client.SocialSignInRequest{Provider: "work", IDToken: &client.SocialIDToken{Token: raw, Nonce: "bound"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.SignOutProvider(t.Context(), client.ProviderSignOutRequest{CallbackURL: "https://foreign.example/return"}); err == nil {
			t.Fatal("accepted external return URI")
		}
		in := client.ProviderSignOutRequest{DisableRedirect: disable, State: "return-123"}
		returnPath := "/bye"
		if disable {
			in.CallbackURL = "/return"
			returnPath = in.CallbackURL
		}
		result, err := c.SignOutProvider(t.Context(), in)
		if err != nil || !result.Success || result.Redirect == disable {
			t.Fatal(result, err)
		}
		location, err := url.Parse(result.URL)
		if err != nil {
			t.Fatal(err)
		}
		q := location.Query()
		if location.Host != "id.example" || location.Path != "/end" || q.Get("tenant") != "work" || q.Get("id_token_hint") != raw || q.Get("state") != "return-123" || q.Get("client_id") != "client" || q.Get("post_logout_redirect_uri") != base+returnPath {
			t.Fatal("incorrect end-session request")
		}
		session, err := c.GetSession(t.Context())
		if err != nil || session != nil {
			t.Fatal("local session still present", err)
		}
		again, err := c.SignOutProvider(t.Context(), in)
		if err != nil || again.URL != "" || !again.Success {
			t.Fatal("signed-out user received a provider hint", err)
		}
	}
}
