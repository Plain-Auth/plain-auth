// Package onetap adds Google Identity Services browser sign-in.
package onetap

import (
	_ "embed"
	"net/http"

	authn "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/providers"
)

type Options = authn.OneTapOptions

func New(o Options) authn.Plugin {
	var fallback authn.OAuthProvider
	if o.ClientID != "" {
		fallback = providers.Google(o.ClientID, "")
	}
	return authn.NewOneTap(o, fallback)
}

//go:embed browser.mjs
var browser []byte

// BrowserModule serves the optional same-origin ES module for a Go web host.
func BrowserModule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodHead {
		_, _ = w.Write(browser)
	}
}
