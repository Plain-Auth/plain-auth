package plainauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// OAuthProxyOptions configures an OAuth callback shared by production and previews.
// ProductionURL is the origin registered with the identity provider. CurrentURL
// overrides current-origin discovery. MaxAge controls the lifetime of a returned
// profile. All participating hosts must have the same dedicated secret or key ring.
type OAuthProxyOptions struct {
	ProductionURL, CurrentURL string
	MaxAge                    time.Duration
	Secret                    string
	Secrets                   []VersionedSecret

	vendorOrigin string
}

// NewOAuthProxy enables provider code exchange on production followed by a
// browser-bound sign-in or account link on the originating preview.
func NewOAuthProxy(o OAuthProxyOptions) (Plugin, error) {
	if o.ProductionURL == "" {
		o.ProductionURL = os.Getenv("AUTH_URL")
	}
	for _, configured := range []*string{&o.ProductionURL, &o.CurrentURL} {
		if *configured != "" {
			origin := proxyOrigin(*configured)
			if origin == "" {
				return Plugin{}, errors.New("oauth proxy: expected an HTTPS origin or local HTTP origin")
			}
			*configured = origin
		}
	}
	if o.MaxAge == 0 {
		o.MaxAge = time.Minute
	}
	if o.MaxAge < 0 {
		return Plugin{}, errors.New("oauth proxy: MaxAge must be positive")
	}
	if o.Secret != "" {
		if o.Secrets != nil {
			return Plugin{}, errors.New("oauth proxy: configure Secret or Secrets")
		}
		o.Secrets = []VersionedSecret{{Value: o.Secret}}
		o.Secret = ""
	}
	if o.Secrets != nil {
		if len(o.Secrets) == 0 {
			return Plugin{}, errors.New("oauth proxy: empty key ring")
		}
		o.Secrets = slices.Clone(o.Secrets)
		seen := map[int]bool{}
		for _, k := range o.Secrets {
			if k.Version < 0 || len(k.Value) < 32 || seen[k.Version] {
				return Plugin{}, errors.New("oauth proxy: keys require distinct non-negative versions and at least 32 bytes")
			}
			seen[k.Version] = true
		}
	}
	// Capture platform configuration at startup. Some platforms expose
	// function names instead of URLs, which cannot identify a callback origin.
	for _, key := range []string{"VERCEL_URL", "NETLIFY_URL", "RENDER_URL", "AWS_LAMBDA_FUNCTION_NAME", "GOOGLE_CLOUD_FUNCTION_NAME", "AZURE_FUNCTION_NAME"} {
		raw := os.Getenv(key)
		if raw == "" {
			continue
		}
		if key == "VERCEL_URL" {
			raw = "https://" + raw
		}
		if origin := proxyOrigin(raw); origin != "" {
			o.vendorOrigin = origin
			break
		}
	}
	return Plugin{ID: "oauth-proxy", oauthProxy: &o}, nil
}

func proxyOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return ""
	}
	origin := canonicalOrigin(u)
	if u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		if host != "localhost" && !strings.HasSuffix(host, ".localhost") && !net.ParseIP(host).IsLoopback() {
			return ""
		}
	}
	return origin
}

// Use the host's public scheme behind TLS termination. An incoming authority
// may select only an origin explicitly trusted by the auth instance.
func (a *Auth) proxyRequestOrigin(r *http.Request) string {
	base, _ := url.Parse(a.opts.BaseURL)
	scheme := base.Scheme
	if r.TLS != nil {
		scheme = "https"
	}
	return proxyOrigin((&url.URL{Scheme: scheme, Host: r.Host}).String())
}

func (a *Auth) proxyCurrentOrigin(r *http.Request) string {
	if configured := a.oauthProxy.CurrentURL; configured != "" {
		return configured
	}
	if origin := a.proxyRequestOrigin(r); origin != "" && a.trustedURL(origin, false) {
		return origin
	}
	if origin := a.oauthProxy.vendorOrigin; origin != "" {
		return origin
	}
	return proxyOrigin(a.opts.BaseURL)
}

type oauthProxyState struct {
	State, Provider, ClientID, Preview, Production, Callback, Verifier, Nonce, BasePath string
	ExpiresAt                                                                           time.Time
	RequestSignUp                                                                       bool
	PopupAdditionalData                                                                 map[string]any `json:",omitempty"`
}

type oauthProxyResult struct {
	State, Provider, Preview, Production, Callback, BasePath string
	IssuedAt                                                 time.Time
	Profile                                                  OAuthProfile
	GoogleHostedDomain                                       string         `json:",omitempty"`
	Fields                                                   map[string]any `json:",omitempty"`
	Tokens                                                   OAuthTokens
	DisableSignUp                                            bool
	RequireEmailVerification                                 bool   `json:",omitempty"`
	Error                                                    string `json:",omitempty"`
}

const proxyStatePurpose = "oauth-proxy-state"
const proxyProfilePurpose = "oauth-proxy-profile"
const maxProxyRecord = 64 << 10

func (a *Auth) sealProxy(purpose string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	record, err := sealSecretRecord(a.oauthProxy.Secrets[0], purpose, raw)
	if len(record) > maxProxyRecord {
		return "", validationError("OAuth proxy response is too large")
	}
	return record, err
}

func (a *Auth) openProxy(purpose, value string, dest any) bool {
	if value == "" || len(value) > maxProxyRecord {
		return false
	}
	raw, err := openSecretRecord(a.oauthProxy.Secrets, purpose, value)
	if err != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(dest) == nil
}

func (a *Auth) packProxyState(flow OAuthFlow) (string, error) {
	return a.sealProxy(proxyStatePurpose, oauthProxyState{
		State: flow.State, Provider: flow.Provider, ClientID: a.opts.SocialProviders[flow.Provider].Config.ClientID,
		Preview: flow.ProxyOrigin, Production: a.oauthProxy.ProductionURL, Callback: flow.CallbackURL, BasePath: a.opts.BasePath,
		Verifier: flow.Verifier, Nonce: flow.Nonce, ExpiresAt: flow.ExpiresAt, RequestSignUp: flow.RequestSignUp, PopupAdditionalData: flow.PopupAdditionalData,
	})
}

func invalidProxyCallback() error {
	return &APIError{400, "INVALID_OAUTH_PROXY_CALLBACK", "Invalid or expired OAuth proxy callback"}
}

func (a *Auth) exchangeProxyCallback(w http.ResponseWriter, r *http.Request, id string, provider OAuthProvider) error {
	w.Header().Set("Referrer-Policy", "no-referrer")
	q := r.URL.Query()
	var grant oauthProxyState
	now := a.now().UTC()
	if len(q["state"]) != 1 || len(q["code"]) > 1 || len(q["error"]) > 1 ||
		!a.openProxy(proxyStatePurpose, q.Get("state"), &grant) ||
		grant.Provider != id || grant.State == "" || grant.Verifier == "" || grant.Nonce == "" ||
		grant.ClientID != provider.Config.ClientID || grant.BasePath != a.opts.BasePath ||
		grant.Production != a.oauthProxy.ProductionURL || a.proxyRequestOrigin(r) != grant.Production || a.proxyCurrentOrigin(r) != grant.Production ||
		proxyOrigin(grant.Preview) != grant.Preview || grant.Preview == grant.Production || !a.trustedURL(grant.Preview, false) ||
		!grant.ExpiresAt.After(now) || grant.ExpiresAt.After(now.Add(10*time.Minute+10*time.Second)) {
		return invalidProxyCallback()
	}
	result := oauthProxyResult{State: grant.State, Provider: id, Preview: grant.Preview, Production: grant.Production, Callback: grant.Callback, BasePath: grant.BasePath,
		DisableSignUp: provider.DisableSignUp || provider.DisableImplicitSignUp && !grant.RequestSignUp, RequireEmailVerification: provider.RequireEmailVerification}
	if code := q.Get("error"); code != "" {
		result.Error = "OAUTH_CALLBACK_ERROR"
		if len(code) <= 128 && errorCodeFormat.MatchString(code) {
			result.Error = code
		}
	} else if q.Get("code") == "" {
		result.Error = "no_code"
	} else {
		ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, provider.HTTPClient), 30*time.Second)
		defer cancel()
		if grant.PopupAdditionalData != nil {
			ctx = context.WithValue(ctx, popupDataKey{}, grant.PopupAdditionalData)
		}
		provider.Config.RedirectURL = grant.Production + grant.BasePath + "/callback/" + id
		exchange, failure := a.exchangeProviderCode(ctx, provider, OAuthFlow{Verifier: grant.Verifier, Nonce: grant.Nonce}, q)
		profile, tokens := exchange.Profile, exchange.Tokens
		if failure == "" && id == "google" && !googleDomainAllowed(provider.GoogleHostedDomain, profile) {
			failure = "INVALID_TOKEN"
		}
		result.Error = failure
		if failure == "" {
			result.Profile, result.Tokens, result.Fields = profile, tokens, profile.AdditionalFields
			if claims, ok := profile.Data.(map[string]any); ok && id == "google" {
				result.GoogleHostedDomain, _ = claims["hd"].(string)
			}
		}
	}
	result.IssuedAt = a.now().UTC()
	profile, err := a.sealProxy(proxyProfilePurpose, result)
	if err != nil {
		return err
	}
	target, err := url.Parse(grant.Preview + grant.BasePath + "/callback/" + id + "/oauth-proxy")
	if err != nil {
		return invalidProxyCallback()
	}
	target.RawQuery = url.Values{"callbackURL": {grant.Callback}, "profile": {profile}}.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
	return nil
}

type proxyBrowserError string

func (e proxyBrowserError) Error() string { return string(e) }

func (a *Auth) serveOAuthProxyCompletion(w http.ResponseWriter, r *http.Request, route string) bool {
	var id string
	legacy := route == "/oauth-proxy-callback"
	if !legacy {
		name, ok := strings.CutPrefix(route, "/callback/")
		if !ok {
			return false
		}
		name, ok = strings.CutSuffix(name, "/oauth-proxy")
		if !ok || !providerName.MatchString(name) {
			return false
		}
		id = name
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return true
	}
	path := "/callback/:id/oauth-proxy"
	if legacy {
		path = route
	}
	if _, disabled := a.disabledPaths[path]; disabled {
		http.NotFound(w, r)
		return true
	}
	if a.rejectRateLimited(w, r, path) {
		return true
	}
	if err := a.completeProxyCallback(w, r, id); err != nil {
		var failure proxyBrowserError
		if errors.As(err, &failure) {
			target := a.opts.BasePath + "/error?" + url.Values{"error": {string(failure)}}.Encode()
			http.Redirect(w, r, target, http.StatusFound)
		} else {
			a.writeAuthError(w, r, err)
		}
	}
	return true
}

func (a *Auth) completeProxyCallback(w http.ResponseWriter, r *http.Request, id string) error {
	q := r.URL.Query()
	var result oauthProxyResult
	if len(q["callbackURL"]) != 1 || !a.trustedURL(q.Get("callbackURL"), true) || len(q["profile"]) > 1 {
		return invalidProxyCallback()
	}
	if q.Get("profile") == "" {
		return proxyBrowserError("missing_profile")
	}
	if !a.openProxy(proxyProfilePurpose, q.Get("profile"), &result) {
		return proxyBrowserError("invalid_profile")
	}
	if id != "" && id != result.Provider {
		return proxyBrowserError("provider_mismatch")
	}
	if result.Callback != q.Get("callbackURL") || result.Production != a.oauthProxy.ProductionURL ||
		result.BasePath != a.opts.BasePath || result.Preview != a.proxyRequestOrigin(r) || result.Preview != a.proxyCurrentOrigin(r) {
		return invalidProxyCallback()
	}
	age := a.now().UTC().Sub(result.IssuedAt)
	if age < -10*time.Second || age > a.oauthProxy.MaxAge {
		return proxyBrowserError("payload_expired")
	}
	provider, err := a.providerConfig(result.Provider)
	if err != nil {
		return err
	}
	err = a.finishBrowserOAuth(w, r, result.Provider, provider, result.State, nil, &result)
	var api *APIError
	if errors.As(err, &api) && api.Code == "INVALID_OAUTH_STATE" {
		return proxyBrowserError("state_mismatch")
	}
	return err
}
