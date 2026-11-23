package oauthprovider

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

type loginClientKey struct{}

func interactionFields(original url.Values, issue BrowserCodeIssue) url.Values {
	fields := url.Values{}
	for key, value := range issue.Query {
		fields.Set(key, value)
	}
	fields.Set("client_id", issue.Client.ClientID)
	fields.Set("response_type", "code")
	fields.Set("scope", strings.Join(issue.Scopes, " "))
	if original.Has("max_age") {
		fields.Set("max_age", original.Get("max_age"))
	}
	return fields
}

func interactionURL(c auth.EndpointContext, path string, fields url.Values, expires time.Time) (string, error) {
	page, err := c.Auth.CallbackURL(path)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(page)
	if err != nil {
		return "", err
	}
	signed := c.Auth.SignOAuthQuery(fields, expires)
	// Preconfigured page fields must never shadow issuer-owned parameters.
	host := target.Query()
	for name := range fields {
		host.Del(name)
	}
	for _, name := range []string{"sig", "exp", "ba_iat", "ba_param", "ba_pl"} {
		host.Del(name)
	}
	target.RawQuery = signed
	if len(host) != 0 {
		target.RawQuery += "&" + host.Encode()
	}
	return target.String(), nil
}

func (opts Options) loginPage(prompts []string) string {
	if slices.Contains(prompts, "create") && opts.Authorization.SignupPage != "" {
		return opts.Authorization.SignupPage
	}
	return opts.Authorization.LoginPage
}

func (opts Options) openLoginPage(c auth.EndpointContext, path string, q url.Values, issue BrowserCodeIssue) (any, error) {
	fields := interactionFields(q, issue)
	fields.Set("pa_login", c.Auth.OAuthIssuer())
	fields.Set("pa_client", tokenDigest(issue.Client.RowID))
	target, err := interactionURL(c, path, fields, time.Now().UTC().Truncate(time.Second).Add(issue.Lifetime))
	if err != nil {
		return nil, err
	}
	return c.RegisteredOAuthRedirect(target), nil
}

func signedLogin(c auth.EndpointContext, raw string) (url.Values, error) {
	q, err := c.Auth.VerifyOAuthQuery(raw)
	if err != nil {
		return nil, registrationProblem(400, "invalid_signature", "invalid or expired oauth query")
	}
	if len(q["pa_login"]) != 1 || q.Get("pa_login") != c.Auth.OAuthIssuer() || len(q["pa_client"]) != 1 || q.Get("pa_client") == "" || q.Has("pa_consent") {
		return nil, registrationProblem(400, "invalid_request", "login query required")
	}
	return q, nil
}

func withoutPrompt(q url.Values, value string) {
	if !q.Has("prompt") {
		return
	}
	remaining := slices.DeleteFunc(strings.Fields(q.Get("prompt")), func(p string) bool { return p == value })
	if len(remaining) == 0 {
		q.Del("prompt")
	} else {
		q.Set("prompt", strings.Join(remaining, " "))
	}
}

// Build a new authorization request from verified fields. Preserve the
// registration identity across re-entry, including when a public ID is reused.
func loginAuthorizationRequest(c auth.EndpointContext, q url.Values) *http.Request {
	ctx := context.WithValue(c.Request.Context(), loginClientKey{}, q.Get("pa_client"))
	for _, k := range []string{"sig", "exp", "ba_iat", "ba_param", "pa_login", "pa_client"} {
		q.Del(k)
	}
	r := c.Request.Clone(ctx)
	r.Method = http.MethodGet
	r.URL.Path = strings.TrimRight(c.Auth.BasePath(), "/") + "/oauth2/authorize"
	r.URL.RawPath, r.URL.RawQuery = "", q.Encode()
	r.RequestURI = r.URL.RequestURI()
	r.Body, r.GetBody, r.ContentLength, r.TransferEncoding = nil, nil, 0, nil
	r.Header.Del("Content-Type")
	r.Header.Del("Content-Length")
	mode := strings.ToLower(r.Header.Get("Sec-Fetch-Mode"))
	accept := strings.ToLower(r.Header.Get("Accept"))
	if mode == "navigate" || (mode == "" && (strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml"))) {
		r.Header.Set("Accept", "text/html")
	} else {
		r.Header.Set("Accept", "application/json")
	}
	return r
}

func (opts Options) prepareLogin(c auth.EndpointContext, raw string) (auth.OAuthLoginContinuation, error) {
	if _, err := signedLogin(c, raw); err != nil {
		return nil, err
	}
	return func(session auth.Session) (*http.Request, error) {
		// Credential checks and two-factor verification can outlive the query.
		q, err := signedLogin(c, raw)
		if err != nil {
			return nil, err
		}
		issuedAt, err := strconv.ParseInt(q.Get("ba_iat"), 10, 64)
		if err != nil {
			return nil, registrationProblem(400, "invalid_signature", "missing login issue time")
		}
		if session.CreatedAt.UnixMilli() >= issuedAt {
			withoutPrompt(q, "login")
			q.Del("max_age")
		}
		return loginAuthorizationRequest(c, q), nil
	}, nil
}

func (opts Options) continueSignup(c auth.EndpointContext) (any, error) {
	if created, ok := c.Body["created"].(bool); !ok || !created {
		return nil, registrationProblem(400, "invalid_request", "created must be true")
	}
	raw, _ := c.Body["oauth_query"].(string)
	if raw == "" {
		return nil, registrationProblem(400, "invalid_request", "missing oauth query")
	}
	q, err := signedLogin(c, raw)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(strings.Fields(q.Get("prompt")), "create") {
		return nil, registrationProblem(400, "invalid_request", "account creation was not requested")
	}
	session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if session == nil || session.Session.RequireOwner() != nil || !c.DirectBrowserSession(session.Session.Token) {
		return nil, registrationProblem(401, "unauthorized", "browser session required")
	}
	withoutPrompt(q, "create")
	r := loginAuthorizationRequest(c, q)
	r.Header.Set("Accept", "application/json")
	return c.ResumeOAuthAuthorization(r)
}

const continueSignupOperation = `{"summary":"Continue browser authorization after account creation","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["created","oauth_query"],"properties":{"created":{"type":"boolean","enum":[true]},"oauth_query":{"type":"string"}}}}}},"responses":{"200":{"description":"Authorization redirect instructions"},"400":{"description":"Invalid or expired signup query"},"401":{"description":"Browser session required"}}}`
