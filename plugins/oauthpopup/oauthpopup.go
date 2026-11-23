// Package oauthpopup supports OAuth sign-in in a first-party popup window.
package oauthpopup

import (
	_ "embed"
	"net/http"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/popupwire"
)

// Browser protocol constants for custom host integrations.
const (
	MessageType      = popupwire.MessageType
	DataElementID    = popupwire.DataElementID
	MarkerCookie     = popupwire.MarkerCookie
	CompletionScript = popupwire.CompletionScript
	ScriptCSPHash    = popupwire.ScriptCSPHash
)

type Options = plainauth.OAuthPopupOptions

type Message = popupwire.Message
type Data = popupwire.Data
type Error = popupwire.Error

// New installs popup start and completion handling for configured OAuth providers.
func New() plainauth.Plugin { return plainauth.NewOAuthPopup() }

// NewWithOptions selects the message type used by a host-supplied browser client.
func NewWithOptions(options Options) (plainauth.Plugin, error) {
	return plainauth.NewOAuthPopupWithOptions(options)
}

//go:embed browser.mjs
var browser []byte

// BrowserModule serves the optional browser client as an ES module.
func BrowserModule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodGet {
		_, _ = w.Write(browser)
	}
}
