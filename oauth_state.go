package plainauth

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"time"
)

type oauthDataKey struct{}

type oauthStateKey struct{}

// OAuthState is what hooks may read of a browser OAuth flow. It leaves out
// the flow's secrets: its PKCE verifier, nonce, URL state and browser
// binding. Do not modify its maps.
type OAuthState struct {
	// CallbackURL, NewUserURL and ErrorURL are the destinations the start
	// chose. During the callback of a redirect flow, ErrorURL is where a
	// failure returns: the error page when the start chose none. A popup flow
	// posts its failures to the opener instead.
	CallbackURL, NewUserURL, ErrorURL string
	// LinkUserID is the user /link-social links the provider account to, or
	// "" for a sign-in.
	LinkUserID string
	// RequestSignUp reports whether the start asked to create an account.
	RequestSignUp bool
	// ExpiresAt is when the flow expires, ten minutes after it started.
	ExpiresAt time.Time
	// AdditionalData is the browser's additionalData: untrusted input.
	// Numbers decode as float64.
	AdditionalData map[string]any
	// ServerContext holds what hooks added with
	// HookContext.AddOAuthServerContext before the flow started. The browser
	// cannot read or set it. Numbers decode as float64.
	ServerContext map[string]any
}

// OAuthStateFrom returns the state of the browser OAuth flow ctx belongs to.
// A start has it once it has built its flow, so after hooks on
// /sign-in/social, /link-social and /oauth-popup/start read it through
// c.Request.Context(). A callback has it once it has read the flow: in the
// provider's ExchangeCode, Resolve and GetAccountFields, in ValidateUserInfo
// and database hooks, and through c.Request.Context() in after hooks on
// /callback/:id and, behind the OAuth proxy, on the preview's
// /callback/:id/oauth-proxy. It reports false in before hooks, in the
// verification delete hooks that spend the flow, for an ID-token sign-in,
// which starts no flow, and on the OAuth proxy's production instance, which
// relays the provider's answer without completing a sign-in.
func OAuthStateFrom(ctx context.Context) (OAuthState, bool) {
	s, ok := ctx.Value(oauthStateKey{}).(OAuthState)
	return s, ok
}

// withOAuthState puts what hooks may read of flow in the request context,
// and in the endpoint's hook request so after hooks read it too.
func (a *Auth) withOAuthState(r *http.Request, flow OAuthFlow) *http.Request {
	state := OAuthState{CallbackURL: flow.CallbackURL, NewUserURL: flow.NewUserCallbackURL, ErrorURL: flow.ErrorCallbackURL,
		LinkUserID: flow.LinkUserID, RequestSignUp: flow.RequestSignUp, ExpiresAt: flow.ExpiresAt,
		AdditionalData: flow.AdditionalData, ServerContext: flow.ServerContext}
	if c := a.hookContext(r.Context()); c != nil {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), oauthStateKey{}, state))
	}
	return r.WithContext(context.WithValue(r.Context(), oauthStateKey{}, state))
}

// OAuthAdditionalData returns the additionalData object the browser sent to
// /sign-in/social, /link-social or /oauth-popup/start, during that flow's
// callback. The values are browser input: treat them as untrusted and do not
// modify the map. Numbers decode as float64. OAuthStateFrom returns the same
// data with the rest of the flow's state. On the OAuth proxy's production
// instance OAuthStateFrom reports false, but OAuthAdditionalData still
// returns the data to the provider's callbacks and the hooks.
func OAuthAdditionalData(ctx context.Context) map[string]any {
	data, _ := ctx.Value(oauthDataKey{}).(map[string]any)
	return data
}

// maxOAuthAdditionalData bounds the additional data an anonymous start can
// store or seal.
const maxOAuthAdditionalData = 8 << 10

// oauthStateKeys are names the flow's own state uses. Additional data under
// these names is dropped.
var oauthStateKeys = []string{"callbackURL", "codeVerifier", "errorURL", "newUserURL", "expiresAt", "oauthState", "link", "requestSignUp", "idTokenNonce", "serverContext"}

// oauthAdditionalData reads a start request's additionalData object.
func oauthAdditionalData(body wireBody) (map[string]any, error) {
	value, present := body["additionalData"]
	if !present {
		return nil, nil
	}
	data, ok := value.(map[string]any)
	if !ok {
		return nil, fieldTypeError("additionalData", "record", body)
	}
	data = maps.Clone(data)
	for _, key := range oauthStateKeys {
		delete(data, key)
	}
	return plainOAuthData(data)
}

// plainOAuthData copies additional data through JSON, so numbers are
// float64 on every path and nothing is shared with the request body. Data
// over maxOAuthAdditionalData, or with a number no float64 holds, is refused.
func plainOAuthData(data map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, validationError("Invalid additional data")
	}
	if len(raw) > maxOAuthAdditionalData {
		return nil, validationError("Additional data is too large")
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, validationError("Invalid additional data")
	}
	return out, nil
}

// withOAuthAdditionalData puts a flow's additional data in the request
// context, and in the endpoint's hook request so after hooks read it too.
func (a *Auth) withOAuthAdditionalData(r *http.Request, data map[string]any) *http.Request {
	if data == nil {
		return r
	}
	if c := a.hookContext(r.Context()); c != nil {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), oauthDataKey{}, data))
	}
	return r.WithContext(context.WithValue(r.Context(), oauthDataKey{}, data))
}

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

// oauthStatePurpose binds a sealed flow to its cookie, so it opens in no
// other cookie. The sealed flow carries its URL state, which the callback
// compares, so another flow's cookie is told apart from an altered one.
func oauthStatePurpose(cookie string) string { return "oauth-state:" + cookie }

// stateFailure is a callback state that cannot be used. code is its browser
// error code. It unwraps to a 400 INVALID_OAUTH_STATE, so a handler that
// returns it unchanged still answers JSON.
type stateFailure struct{ code, message string }

func (e *stateFailure) Error() string { return e.message }
func (e *stateFailure) Unwrap() error {
	return &APIError{Status: 400, Code: "INVALID_OAUTH_STATE", Message: e.message}
}

// OAuthStateFailure returns the browser error code of a state failure from
// ConsumeEnterpriseFlow or ConsumeEnterprisePostFlow: state_not_found,
// state_mismatch or state_invalid. It returns "" for any other error.
func OAuthStateFailure(err error) string {
	var failure *stateFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return ""
}

const oauthStateMessage = "Invalid or expired OAuth state"

// keepOAuthFlow saves flow for its callback, and adds the state cookie c,
// whose base name is name, to h. browser is the value the binding was made
// from.
func (a *Auth) keepOAuthFlow(ctx context.Context, h http.Header, name string, c *http.Cookie, browser string, flow OAuthFlow, now time.Time) error {
	if a.opts.OAuthStateStrategy == OAuthStateCookie {
		raw, err := json.Marshal(sealedOAuthFlow{Browser: browser, Flow: flow})
		if err != nil {
			return err
		}
		if c.Value, err = a.sealRecord(oauthStatePurpose(name), raw); err != nil {
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
		declined, err := a.createVerification(ctx, oauthFlowRecord(flow), func() error { return store.SaveOAuthFlow(ctx, flow, now) })
		if err != nil {
			return err
		}
		if declined {
			return &APIError{500, "STATE_GENERATION_ERROR", "Unable to create verification"}
		}
		c.Value = browser
	}
	h.Add("Set-Cookie", c.String())
	return nil
}

// takeOAuthFlow returns the flow for state from the state cookie's value,
// once. binding recomputes the flow's binding from the browser value. A
// missing, expired or foreign flow is a state_mismatch failure, and a sealed
// cookie this instance cannot open is state_invalid.
func (a *Auth) takeOAuthFlow(ctx context.Context, name, value, state string, binding func(browser string) string, now time.Time) (OAuthFlow, error) {
	mismatch := &stateFailure{"state_mismatch", oauthStateMessage}
	if a.opts.OAuthStateStrategy != OAuthStateCookie {
		store, ok := a.opts.Store.(OAuthFlowStore)
		if !ok {
			return OAuthFlow{}, mismatch
		}
		bound := binding(value)
		find := func() (VerificationRecord, error) {
			finder, ok := store.(OAuthFlowFinder)
			if !ok {
				return VerificationRecord{}, ErrNotFound
			}
			f, err := finder.FindOAuthFlow(ctx, state, bound, now)
			return oauthFlowRecord(f), err
		}
		var flow OAuthFlow
		refused, err := a.spendVerification(ctx, find, func() (err error) {
			flow, err = store.ConsumeOAuthFlow(ctx, state, bound, now)
			return err
		})
		if err != nil {
			return OAuthFlow{}, err
		}
		// A declined spend keeps the flow, and the callback is refused.
		if refused {
			return OAuthFlow{}, mismatch
		}
		return flow, nil
	}
	raw, err := a.openRecord(oauthStatePurpose(name), value)
	var sealed sealedOAuthFlow
	if err != nil || json.Unmarshal(raw, &sealed) != nil {
		return OAuthFlow{}, &stateFailure{"state_invalid", oauthStateMessage}
	}
	if sealed.Flow.State != state || !sealed.Flow.ExpiresAt.After(now) || !hmac.Equal([]byte(binding(sealed.Browser)), []byte(sealed.Flow.Binding)) {
		return OAuthFlow{}, mismatch
	}
	return sealed.Flow, nil
}
