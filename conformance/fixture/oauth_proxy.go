package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlite"
	"github.com/Plain-Auth/plain-auth/plugins/oauthpopup"
	"github.com/Plain-Auth/plain-auth/plugins/oauthproxy"
	"golang.org/x/oauth2"
)

// Both ports are assigned before installation so each app can use an exact trusted origin.
func serveProxyPair(preview net.Listener, filename string) error {
	production, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer production.Close()
	origin := "http://" + preview.Addr().String()
	registered := fmt.Sprintf("http://localhost:%d", production.Addr().(*net.TCPAddr).Port)
	var handlers []http.Handler
	for _, host := range []string{origin, registered} {
		file := filename
		if host == registered {
			file += ".production"
		}
		db, err := sqlite.Open(file)
		if err != nil {
			return err
		}
		defer db.Close()
		plugin, err := oauthproxy.New(oauthproxy.Options{CurrentURL: host, ProductionURL: registered, Secret: "shared only across local oauth proxy fixtures"})
		if err != nil {
			return err
		}
		p := auth.OAuthProvider{Config: oauth2.Config{ClientID: "work", Endpoint: oauth2.Endpoint{AuthURL: registered + "/fixture/authorize", TokenURL: registered + "/fixture/token"}}, ExchangeCode: func(_ context.Context, cfg oauth2.Config, code, verifier string, _ url.Values) (*oauth2.Token, error) {
			if host != registered || cfg.RedirectURL != registered+"/identity/callback/work" || code != "approved" || verifier == "" {
				return nil, errors.New("unexpected fixture exchange")
			}
			return &oauth2.Token{AccessToken: "private provider fixture token"}, nil
		}, Resolve: func(ctx context.Context, t *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
			if nonce == "" || t.AccessToken != "private provider fixture token" {
				return auth.OAuthProfile{}, errors.New("unexpected fixture identity")
			}
			name := "Employee"
			if metadata := auth.OAuthPopupAdditionalData(ctx); metadata["source"] == "popup" {
				name = "Popup Employee"
			}
			return auth.OAuthProfile{Subject: "employee", Email: "employee@example.test", Name: name, EmailVerified: true}, nil
		}}
		off := false
		node, err := auth.New(auth.Options{Store: db, BaseURL: host, BasePath: "/identity", Secret: "local environment session fixture key " + host, Plugins: []auth.Plugin{plugin, oauthpopup.New()}, TrustedOrigins: []string{origin}, SocialProviders: map[string]auth.OAuthProvider{"work": p}, RateLimit: &off})
		if err != nil {
			return err
		}
		mux := http.NewServeMux()
		mux.Handle("/identity/", node)
		if host == registered {
			mux.HandleFunc("GET /fixture/authorize", func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				callback := registered + "/identity/callback/work"
				if q.Get("redirect_uri") != callback || q.Get("client_id") != "work" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
					http.Error(w, "unexpected authorization request", http.StatusBadRequest)
					return
				}
				response := url.Values{"state": {q.Get("state")}, "code": {"approved"}}
				http.Redirect(w, r, callback+"?"+response.Encode(), http.StatusFound)
			})
		} else {
			mux.HandleFunc("GET /welcome", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprintln(w, "<!doctype html><title>Preview</title><p>Welcome to the preview</p>")
			})
		}
		handlers = append(handlers, mux)
	}
	done := make(chan error, 2)
	go func() { done <- http.Serve(production, handlers[1]) }()
	go func() { done <- http.Serve(preview, handlers[0]) }()
	fmt.Println(origin)
	return <-done
}
