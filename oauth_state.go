package plainauth

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// OAuthStateStrategy chooses where a browser OAuth flow waits for the
// provider's callback.
type OAuthStateStrategy string

const (
	// OAuthStateDatabase stores the flow through OAuthFlowStore, and the
	// callback consumes it once. It is the default.
	OAuthStateDatabase OAuthStateStrategy = "database"
	// OAuthStateCookie seals the whole flow into the state cookie, so no flow
	// is stored. The cookie is expired on use, but a copy captured before
	// then stays valid until it expires, so a replay is stopped by the
	// provider's single-use authorization code rather than by the store.
	OAuthStateCookie OAuthStateStrategy = "cookie"
)

// sealedOAuthFlow is what OAuthStateCookie keeps in the state cookie: the
// browser value the binding was made from, and the flow.
type sealedOAuthFlow struct {
	Browser string
	Flow    OAuthFlow
}

// oauthStatePurpose binds a sealed flow to its cookie and its URL state, so
// it opens in no other cookie and for no other state.
func oauthStatePurpose(cookie, state string) string { return "oauth-state:" + cookie + ":" + state }

// keepOAuthFlow saves flow for its callback, and adds the state cookie c,
// whose base name is name, to h. browser is the value the binding was made
// from.
func (a *Auth) keepOAuthFlow(ctx context.Context, h http.Header, name string, c *http.Cookie, browser string, flow OAuthFlow, now time.Time) error {
	if a.opts.OAuthStateStrategy == OAuthStateCookie {
		raw, err := json.Marshal(sealedOAuthFlow{Browser: browser, Flow: flow})
		if err != nil {
			return err
		}
		if c.Value, err = a.sealRecord(oauthStatePurpose(name, flow.State), raw); err != nil {
			return err
		}
		if len(c.String()) > maxSessionChunkSize {
			return validationError("OAuth state is too large for a cookie")
		}
	} else {
		store, ok := a.opts.Store.(OAuthFlowStore)
		if !ok {
			return errors.New("auth: OAuth sign-in requires an OAuthFlowStore, or OAuthStateCookie")
		}
		if err := store.SaveOAuthFlow(ctx, flow, now); err != nil {
			return err
		}
		c.Value = browser
	}
	h.Add("Set-Cookie", c.String())
	return nil
}

// takeOAuthFlow returns the flow for state from the state cookie's value,
// once. binding recomputes the flow's binding from the browser value. A
// missing, altered, expired or foreign flow is ErrNotFound.
func (a *Auth) takeOAuthFlow(ctx context.Context, name, value, state string, binding func(browser string) string, now time.Time) (OAuthFlow, error) {
	if a.opts.OAuthStateStrategy != OAuthStateCookie {
		store, ok := a.opts.Store.(OAuthFlowStore)
		if !ok {
			return OAuthFlow{}, ErrNotFound
		}
		return store.ConsumeOAuthFlow(ctx, state, binding(value), now)
	}
	raw, err := a.openRecord(oauthStatePurpose(name, state), value)
	if err != nil {
		return OAuthFlow{}, ErrNotFound
	}
	var sealed sealedOAuthFlow
	if json.Unmarshal(raw, &sealed) != nil || sealed.Flow.State != state || !sealed.Flow.ExpiresAt.After(now) ||
		!hmac.Equal([]byte(binding(sealed.Browser)), []byte(sealed.Flow.Binding)) {
		return OAuthFlow{}, ErrNotFound
	}
	return sealed.Flow, nil
}
