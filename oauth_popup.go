package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"github.com/Plain-Org/plain-auth/internal/popupwire"
)

type popupOpener struct {
	Origin      string `json:"targetOrigin"`
	Nonce       string `json:"nonce"`
	MessageType string `json:"type"`
}

type popupError = popupwire.Error
type popupDataKey struct{}

// OAuthPopupAdditionalData returns application data from the initiating browser
// to the provider's exchange and profile callbacks. Values are untrusted input.
func OAuthPopupAdditionalData(ctx context.Context) map[string]any {
	data, _ := ctx.Value(popupDataKey{}).(map[string]any)
	return data
}

// OAuthPopupOptions configures the fixed browser message protocol for a deployment.
type OAuthPopupOptions struct {
	// MessageType defaults to plainauth:oauth-popup. A custom value is namespace:event.
	MessageType string
}

var popupMessageFormat = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// NewOAuthPopup installs popup sign-in with the standard message type.
func NewOAuthPopup() Plugin { return oauthPopupPlugin(popupwire.MessageType) }

// NewOAuthPopupWithOptions installs a client-specific message type selected by the host.
func NewOAuthPopupWithOptions(options OAuthPopupOptions) (Plugin, error) {
	if options.MessageType == "" {
		return NewOAuthPopup(), nil
	}
	if !popupMessageFormat.MatchString(options.MessageType) {
		return Plugin{}, errors.New("auth: popup message type must be namespace:event")
	}
	return oauthPopupPlugin(options.MessageType), nil
}

func oauthPopupPlugin(messageType string) Plugin {
	start := Endpoint{
		Method:  http.MethodGet,
		Path:    "/oauth-popup/start",
		Handler: func(c EndpointContext) (any, error) { return startOAuthPopup(c, messageType) },
	}
	return Plugin{ID: "oauth-popup", Endpoints: []Endpoint{start}}
}

func startOAuthPopup(c EndpointContext, messageType string) (any, error) {
	a, r := c.Auth, c.Request
	q := r.URL.Query()
	origin, err := httporigin.Parse(q.Get("popupOrigin"))
	if err != nil || len(q["popupOrigin"]) != 1 || strings.ContainsAny(origin, "*?") || !a.trustedWebOrigin(r.Context(), origin) {
		return nil, &APIError{403, "INVALID_ORIGIN", "Invalid origin"}
	}
	opener := popupOpener{Origin: origin, Nonce: q.Get("popupNonce"), MessageType: messageType}
	failure := func(code, description string) (any, error) {
		return opener.page(c.ResponseHeader, "", "", &popupError{Code: code, Description: description}), nil
	}
	if len(opener.Nonce) > 256 || len(origin) > 1024 || len(q["popupNonce"]) > 1 {
		return nil, validationError("Invalid popup origin or nonce")
	}
	body := wireBody{}
	for _, field := range []struct{ name, code string }{
		{"callbackURL", "invalid_callback_url"},
		{"errorCallbackURL", "invalid_error_callback_url"},
		{"newUserCallbackURL", "invalid_new_user_callback_url"},
	} {
		if v := q.Get(field.name); v != "" {
			if !a.trustedURL(r.Context(), v, true) {
				return failure(field.code, "Untrusted URL: "+v)
			}
			body[field.name] = v
		}
	}
	if !q.Has("provider") {
		return nil, validationError("A provider is required")
	}
	id := q.Get("provider")
	p, err := a.providerConfig(id)
	if err != nil {
		return failure("provider_not_found", "Unknown provider: "+id)
	}
	if scopes := q.Get("scopes"); scopes != "" {
		var items []any
		for scope := range strings.SplitSeq(scopes, ",") {
			items = append(items, scope)
		}
		body["scopes"] = items
	}
	params, err := authorizationOptions(body, p.Config.Scopes)
	if err != nil {
		return failure("popup_sign_in_failed", "Invalid OAuth scopes")
	}
	flow := OAuthFlow{Provider: id, RequestSignUp: q.Get("requestSignUp") == "true"}
	if body["callbackURL"] == nil {
		body["callbackURL"] = a.opts.BaseURL + strings.TrimRight(a.opts.BasePath, "/")
	}
	if raw := q.Get("additionalData"); raw != "" {
		if len(raw) > 8192 {
			return failure("popup_sign_in_failed", "Additional data is too large")
		}
		if json.Unmarshal([]byte(raw), &flow.PopupAdditionalData) == nil {
			for _, key := range []string{"callbackURL", "codeVerifier", "errorURL", "newUserURL", "expiresAt", "oauthState", "link", "requestSignUp", "idTokenNonce", "serverContext"} {
				delete(flow.PopupAdditionalData, key)
			}
		} else {
			flow.PopupAdditionalData = nil
		}
	}
	target, state, err := a.beginBrowserOAuth(c.ResponseHeader, r, p, body, flow, params)
	if err != nil {
		return failure("popup_sign_in_failed", "Failed to start the OAuth flow.")
	}
	raw, _ := json.Marshal(opener)
	value, err := a.sealRecord("oauth-popup:"+state, raw)
	if err != nil {
		return failure("popup_sign_in_failed", "Failed to start the OAuth flow.")
	}
	c.ResponseHeader.Add("Set-Cookie", a.oauthCookie(popupwire.MarkerCookie, value, 600).String())
	return Redirect(target), nil
}

func (a *Auth) callbackPopup(h http.Header, r *http.Request, state string) *popupOpener {
	if !a.HasPlugin("oauth-popup") {
		return nil
	}
	marker := a.oauthCookie(popupwire.MarkerCookie, "", -1)
	cookies := r.CookiesNamed(marker.Name)
	if len(cookies) != 1 {
		return nil
	}
	raw, err := a.openRecord("oauth-popup:"+state, cookies[0].Value)
	if err != nil {
		return nil
	}
	h.Add("Set-Cookie", marker.String())
	var opener popupOpener
	if json.Unmarshal(raw, &opener) != nil || !popupMessageFormat.MatchString(opener.MessageType) || !a.trustedWebOrigin(r.Context(), opener.Origin) {
		return nil
	}
	return &opener
}

func (opener popupOpener) page(h http.Header, token, redirect string, failure *popupError) HTMLPage {
	p := popupwire.Data{
		TargetOrigin: opener.Origin,
		Message:      popupwire.Message{Type: opener.MessageType, Nonce: opener.Nonce, Token: token, RedirectTo: redirect, Error: failure},
	}
	data, _ := json.Marshal(p) // Escapes HTML metacharacters and script line separators.
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src '"+popupwire.ScriptCSPHash+"'; base-uri 'none'; frame-ancestors 'none'")
	return HTMLPage(`<!doctype html><html><head><meta charset="utf-8"><title>Completing sign-in</title></head><body><script type="application/json" id="` + popupwire.DataElementID + `">` + string(data) + `</script><script>` + popupwire.CompletionScript + `</script></body></html>`)
}
