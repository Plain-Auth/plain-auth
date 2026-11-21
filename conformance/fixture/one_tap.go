package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	authn "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/providers"
)

type fixtureGoogleKeys string

func (keys fixtureGoogleKeys) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != "https://www.googleapis.com/oauth2/v3/certs" {
		return nil, fmt.Errorf("unexpected signing keys endpoint")
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(keys)))}, nil
}

const fixtureAudience = "fixture.apps.googleusercontent.com"

func oneTapFixtureProvider(keys string) map[string]authn.OAuthProvider {
	p := providers.GoogleWithOptions(providers.GoogleOptions{ClientID: fixtureAudience, HTTPClient: &http.Client{Transport: fixtureGoogleKeys(keys)}})
	return map[string]authn.OAuthProvider{"google": p}
}
func oneTapFixtureHandler(origin string, a *authn.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/test/host-challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != origin {
			w.WriteHeader(403)
			return
		}
		nonce := rand.Text()
		if err := a.BindOneTapNonce(w, origin, fixtureAudience, nonce); err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"nonce": nonce, "clientId": fixtureAudience})
	})
	mux.Handle("/", a)
	return mux
}
