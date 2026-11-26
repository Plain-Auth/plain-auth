package plainauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"golang.org/x/oauth2"
)

// TokenAuthMethod is how a social provider's client authenticates at the
// token endpoint.
type TokenAuthMethod string

const (
	// TokenAuthClientSecretBasic sends the client ID and secret in an HTTP
	// Basic header.
	TokenAuthClientSecretBasic TokenAuthMethod = "client_secret_basic"
	// TokenAuthClientSecretPost sends them in the form.
	TokenAuthClientSecretPost TokenAuthMethod = "client_secret_post"
	// TokenAuthNone sends only the client ID, for a public client using PKCE.
	TokenAuthNone TokenAuthMethod = "none"
	// TokenAuthPrivateKeyJWT sends a signed client assertion from
	// TokenEndpointAuth.ClientAssertion.
	TokenAuthPrivateKeyJWT TokenAuthMethod = "private_key_jwt"
	// TokenAuthCustom lets TokenEndpointAuth.CustomizeRequest set the client
	// ID and credentials.
	TokenAuthCustom TokenAuthMethod = "custom"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// TokenRequest identifies one request to a provider's token endpoint. It
// carries no secret.
type TokenRequest struct {
	ClientID, TokenURL string
	// GrantType is "authorization_code" or "refresh_token".
	GrantType string
}

// ClientAssertionFunc returns a fresh signed client assertion for one token
// request; providers.PrivateKeyJWT builds one. It may run concurrently.
type ClientAssertionFunc func(context.Context, TokenRequest) (string, error)

// TokenEndpointAuth authenticates a social provider's code exchange and
// refresh. The zero value keeps Config.Endpoint.AuthStyle; a Method replaces
// it. New refuses a Method that does not fit the configuration, such as a
// secret method without a secret.
type TokenEndpointAuth struct {
	Method TokenAuthMethod
	// ClientAssertion is required with TokenAuthPrivateKeyJWT and refused
	// otherwise.
	ClientAssertion ClientAssertionFunc
	// CustomizeRequest is required with TokenAuthCustom and refused
	// otherwise. It sets the client ID and credentials in form or header;
	// form holds the grant fields and any TokenParams or RefreshParams
	// fields, which it must not change.
	CustomizeRequest func(ctx context.Context, r TokenRequest, form url.Values, header http.Header) error
}

// prepareTokenEndpointAuth checks the provider's token authentication and
// sets the matching AuthStyle.
func prepareTokenEndpointAuth(id string, p *OAuthProvider) error {
	t := p.TokenEndpointAuth
	refuse := func(why string) error { return fmt.Errorf("auth: OAuth provider %q: %s", id, why) }
	if t.Method == "" {
		if t.ClientAssertion != nil || t.CustomizeRequest != nil {
			return refuse("a token endpoint callback needs its TokenEndpointAuth.Method")
		}
		if p.Config.Endpoint.AuthStyle == oauth2.AuthStyleInHeader && p.Config.ClientSecret == "" {
			return refuse("HTTP Basic client authentication needs a client secret")
		}
		return nil
	}
	if p.ExchangeCode != nil || p.Refresh != nil {
		return refuse("TokenEndpointAuth cannot be combined with ExchangeCode or Refresh")
	}
	if (t.ClientAssertion != nil) != (t.Method == TokenAuthPrivateKeyJWT) {
		return refuse("ClientAssertion goes with the private_key_jwt method only")
	}
	if (t.CustomizeRequest != nil) != (t.Method == TokenAuthCustom) {
		return refuse("CustomizeRequest goes with the custom method only")
	}
	switch t.Method {
	case TokenAuthClientSecretBasic, TokenAuthClientSecretPost:
		if p.Config.ClientSecret == "" {
			return refuse("the " + string(t.Method) + " method needs a client secret")
		}
	case TokenAuthNone, TokenAuthPrivateKeyJWT:
		if p.Config.ClientSecret != "" {
			return refuse("the " + string(t.Method) + " method is used without a client secret")
		}
	case TokenAuthCustom:
	default:
		return refuse("unknown token endpoint authentication method")
	}
	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	if t.Method == TokenAuthClientSecretBasic {
		p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	return nil
}

// tokenContext returns ctx carrying the provider's HTTP client for token
// endpoint requests: TokenHeaders go to the token endpoint's origin, and the
// private_key_jwt and custom methods authenticate each request.
func (p OAuthProvider) tokenContext(ctx context.Context) context.Context {
	origin := ""
	if u, err := url.Parse(p.Config.Endpoint.TokenURL); err == nil {
		origin = httporigin.Canonical(u)
	}
	c := httporigin.WithHeaders(p.HTTPClient, origin, p.TokenHeaders)
	if m := p.TokenEndpointAuth.Method; m == TokenAuthPrivateKeyJWT || m == TokenAuthCustom {
		authenticated := *c
		authenticated.Transport = tokenAuthTransport{base: c.Transport, auth: p.TokenEndpointAuth, clientID: p.Config.ClientID, tokenURL: p.Config.Endpoint.TokenURL}
		c = &authenticated
	}
	if c == p.HTTPClient {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, c)
}

var grantFields = []string{"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token"}

type tokenAuthTransport struct {
	base               http.RoundTripper
	auth               TokenEndpointAuth
	clientID, tokenURL string
}

func (t tokenAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, errors.New("auth: unreadable token request")
	}
	req := TokenRequest{ClientID: t.clientID, TokenURL: t.tokenURL, GrantType: form.Get("grant_type")}
	out := r.Clone(r.Context())
	switch t.auth.Method {
	case TokenAuthPrivateKeyJWT:
		assertion, err := t.auth.ClientAssertion(r.Context(), req)
		if err != nil || assertion == "" {
			return nil, errors.New("auth: the client assertion could not be created")
		}
		form.Set("client_id", t.clientID)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	case TokenAuthCustom:
		form.Del("client_id")
		form.Del("client_secret")
		before := make(map[string][]string, len(grantFields))
		for _, key := range grantFields {
			before[key] = slices.Clone(form[key])
		}
		if err := t.auth.CustomizeRequest(r.Context(), req, form, out.Header); err != nil {
			return nil, errors.New("auth: the token request could not be authenticated")
		}
		for _, key := range grantFields {
			if !slices.Equal(before[key], form[key]) {
				return nil, errors.New("auth: the token request's grant fields were changed")
			}
		}
		if form.Has("client_assertion") != form.Has("client_assertion_type") {
			return nil, errors.New("auth: a client assertion needs its type")
		}
	}
	body := []byte(form.Encode())
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(out)
}
