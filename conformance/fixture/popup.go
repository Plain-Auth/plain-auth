package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

// Credentials only travel between loopback servers. The token and profile are local fixtures.
func popupProvider(origin string) (auth.OAuthProvider, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.RequestURI() != "/" || !net.ParseIP(u.Hostname()).IsLoopback() {
		return auth.OAuthProvider{}, errors.New("popup fixture requires an exact loopback origin")
	}
	return auth.OAuthProvider{Config: oauth2.Config{ClientID: "popup-client", Scopes: []string{"profile"}, Endpoint: oauth2.Endpoint{AuthURL: origin + "/authorize", TokenURL: origin + "/token"}}, DisableImplicitSignUp: true,
		ExchangeCode: func(_ context.Context, _ oauth2.Config, code, verifier string, _ url.Values) (*oauth2.Token, error) {
			if code != "fixture" || verifier == "" {
				return nil, errors.New("invalid fixture code")
			}
			return &oauth2.Token{AccessToken: "local-access"}, nil
		}, Resolve: func(ctx context.Context, _ *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
			d := auth.OAuthPopupAdditionalData(ctx)
			if nonce == "" || d["campaign"] != "local" || d["link"] != nil || d["serverContext"] != nil {
				return auth.OAuthProfile{}, errors.New("unexpected popup state")
			}
			return auth.OAuthProfile{Subject: "popup-user", Email: "popup@example.org", Name: "Popup", EmailVerified: true}, nil
		}}, nil
}

func popupCORS(next http.Handler, origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.WriteHeader(204)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
