// Package client calls the authentication HTTP API on behalf of a single user.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"

	authn "github.com/Plain-Auth/plain-auth"
	"golang.org/x/net/publicsuffix"
)

// Client holds the server URL and the user's session cookies. Create a separate
// client and cookie jar for each user.
type Client struct {
	bearer string
	base   string
	origin string
	http   *http.Client
}

// New takes an HTTP(S) origin or a full URL with a custom auth mount path.
// An empty base URL reads AUTH_URL once at construction.
// Passing nil creates an HTTP client with an in-memory cookie jar. A supplied
// client's transport, timeout, jar and same-origin redirect policy are reused.
func New(baseURL string, httpClient *http.Client) (*Client, error) {
	if baseURL == "" {
		baseURL = os.Getenv("AUTH_URL")
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(baseURL, "#") {
		return nil, errors.New("authn/client: expected an absolute HTTP(S) base URL")
	}
	mount := strings.TrimSuffix(u.Path, "/")
	if mount == "" {
		mount = "/api/auth"
	} else if path.Clean(mount) != mount || u.RawPath != "" || strings.Contains(mount, "\\") {
		return nil, errors.New("authn/client: invalid auth mount path")
	}
	origin := u.Scheme + "://" + u.Host
	base := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: mount}).String()
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	jar := httpClient.Jar
	if jar == nil {
		jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			return nil, err
		}
	}
	check := httpClient.CheckRedirect
	configured := &http.Client{
		Transport: httpClient.Transport, Timeout: httpClient.Timeout, Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Credentials and request bodies must stay on the configured origin.
			if req.URL.Scheme != u.Scheme || !strings.EqualFold(req.URL.Host, u.Host) || check == nil {
				return http.ErrUseLastResponse
			}
			return check(req, via)
		},
	}
	return &Client{base: base, origin: origin, http: configured}, nil
}

// Do calls an API endpoint under the client's auth mount. Route starts with "/"
// and may include a query. Non-nil input is encoded as JSON. Supply a pointer
// for output, or nil to discard the response. HTTP errors match *plainauth.APIError through errors.As.
func (c *Client) Do(ctx context.Context, method, route string, input, output any) error {
	_, err := c.DoWithHeaders(ctx, method, route, input, output)
	return err
}

// DoWithHeaders performs the same request as Do and returns response headers,
// including Set-Auth-Token when the server issues a signed bearer credential.
// A transport or request construction error returns nil headers.
func (c *Client) DoWithHeaders(ctx context.Context, method, route string, input, output any) (http.Header, error) {
	return c.doWithHeaders(ctx, method, route, input, output, nil)
}

func (c *Client) doWithHeaders(ctx context.Context, method, route string, input, output any, headers http.Header) (http.Header, error) {
	ref, err := url.ParseRequestURI(route)
	if err != nil || !strings.HasPrefix(route, "/") || ref.Host != "" || strings.Contains(route, "#") ||
		path.Clean(ref.Path) != ref.Path || strings.Contains(ref.Path, "\\") {
		return nil, errors.New("authn/client: expected a clean API route")
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+route, body)
	if err != nil {
		return nil, err
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for name, values := range headers {
		req.Header[name] = slices.Clone(values)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", c.origin)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		apiErr := &authn.APIError{Status: res.StatusCode}
		wire := struct {
			*authn.APIError
			OriginalMessage *string `json:"originalMessage"`
			OAuthCode       string  `json:"error"`
			Description     string  `json:"error_description"`
		}{APIError: apiErr}
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&wire)
		if apiErr.Code == "" && wire.OAuthCode != "" {
			apiErr.Code, apiErr.Message = wire.OAuthCode, wire.Description
		}
		if apiErr.Message == "" {
			apiErr.Message = fmt.Sprintf("Authentication server returned HTTP %d", res.StatusCode)
		}
		if wire.OriginalMessage != nil {
			return res.Header, &authn.LocalizedError{APIError: apiErr, OriginalMessage: *wire.OriginalMessage}
		}
		return res.Header, apiErr
	}
	if output == nil {
		_, err = io.Copy(io.Discard, res.Body)
		return res.Header, err
	}
	return res.Header, json.NewDecoder(res.Body).Decode(output)
}

// SignUpRequest configures email/password registration.
type SignUpRequest struct {
	OAuthQuery       string         `json:"oauth_query,omitempty"`
	AdditionalFields map[string]any `json:"-"`
	Username         *string        `json:"username,omitempty"`
	DisplayUsername  *string        `json:"displayUsername,omitempty"`
	Name             string         `json:"name"`
	Email            string         `json:"email"`
	Password         string         `json:"password"`
	Image            *string        `json:"image,omitempty"`
	RememberMe       *bool          `json:"rememberMe,omitempty"`
	CallbackURL      string         `json:"callbackURL,omitempty"`
}

// SignInRequest configures email/password login.
type SignInRequest struct {
	OAuthQuery  string `json:"oauth_query,omitempty"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	RememberMe  *bool  `json:"rememberMe,omitempty"`
	CallbackURL string `json:"callbackURL,omitempty"`
}

// EmailResult contains the public profile and, when issued, the session token.
type EmailResult struct {
	TwoFactorRedirect bool       `json:"twoFactorRedirect,omitempty"`
	TwoFactorMethods  []string   `json:"twoFactorMethods,omitempty"`
	User              authn.User `json:"user"`
	Token             *string    `json:"token"`
	Redirect          bool       `json:"redirect"`
	URL               string     `json:"url"`
}

func (c *Client) SignUpEmail(ctx context.Context, input SignUpRequest) (*EmailResult, error) {
	var out EmailResult
	if err := c.Do(ctx, http.MethodPost, "/sign-up/email", input, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SignInEmail(ctx context.Context, input SignInRequest) (*EmailResult, error) {
	var out EmailResult
	if err := c.Do(ctx, http.MethodPost, "/sign-in/email", input, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSession returns nil, nil when the caller has no active session.
func (c *Client) GetSession(ctx context.Context) (*authn.SessionResult, error) {
	return GetSessionView[authn.SessionResult](ctx, c)
}

// GetSessionView decodes the configured HTTP session response into T.
// An unauthenticated request returns nil, nil.
func GetSessionView[T any](ctx context.Context, c *Client) (*T, error) {
	return GetSessionViewWithOptions[T](ctx, c, SessionReadOptions{})
}

// SessionReadOptions controls whether a browser session read may refresh or use
// a cached session on a server that supports it. False fields are omitted.
type SessionReadOptions struct{ DisableRefresh, DisableCookieCache bool }

// GetSessionViewWithOptions decodes the projected response after applying query controls.
func GetSessionViewWithOptions[T any](ctx context.Context, c *Client, options SessionReadOptions) (*T, error) {
	query := url.Values{}
	if options.DisableRefresh {
		query.Set("disableRefresh", "true")
	}
	if options.DisableCookieCache {
		query.Set("disableCookieCache", "true")
	}
	route := "/get-session"
	if len(query) > 0 {
		route += "?" + query.Encode()
	}
	var view *T
	if err := c.Do(ctx, http.MethodGet, route, nil, &view); err != nil {
		return nil, err
	}
	return view, nil
}

func (c *Client) ListSessions(ctx context.Context) ([]authn.Session, error) {
	var out []authn.Session
	err := c.Do(ctx, http.MethodGet, "/list-sessions", nil, &out)
	return out, err
}

func (c *Client) SignOut(ctx context.Context) error {
	return c.Do(ctx, http.MethodPost, "/sign-out", struct{}{}, nil)
}

func (c *Client) RevokeSession(ctx context.Context, token string) error {
	return c.Do(ctx, http.MethodPost, "/revoke-session", map[string]string{"token": token}, nil)
}

func (c *Client) RevokeOtherSessions(ctx context.Context) error {
	return c.Do(ctx, http.MethodPost, "/revoke-other-sessions", struct{}{}, nil)
}

func (c *Client) RevokeSessions(ctx context.Context) error {
	return c.Do(ctx, http.MethodPost, "/revoke-sessions", struct{}{}, nil)
}
