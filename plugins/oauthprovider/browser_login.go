package oauthprovider

import (
	"context"
	"github.com/Plain-Org/plain-auth/internal/jsjson"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

type continuedClientKey struct{}

type browserContinuation struct {
	client, clearedSession, binding string
	postLogin                       bool
}

func interactionFields(original url.Values, issue BrowserCodeIssue) url.Values {
	fields := url.Values{}
	for key, value := range issue.Query {
		fields.Set(key, value)
	}
	fields.Set("client_id", issue.Client.ClientID)
	fields.Set("response_type", "code")
	fields.Set("scope", strings.Join(issue.Scopes, " "))
	if len(issue.Resources) > 0 {
		fields["resource"] = slices.Clone(issue.Resources)
	}
	if original.Has("max_age") {
		fields.Set("max_age", original.Get("max_age"))
	}
	return fields
}

func interactionURL(c auth.EndpointContext, path string, fields url.Values, expires time.Time, clearedSession string) (string, error) {
	page, err := c.CallbackURL(path)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(page)
	if err != nil {
		return "", err
	}
	signed := c.Auth.SignOAuthConsentQuery(fields, expires, clearedSession)
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

func (opts Options) openAccountPage(c auth.EndpointContext, path, marker string, q url.Values, issue BrowserCodeIssue) (any, error) {
	fields := interactionFields(q, issue)
	fields.Set(marker, c.Auth.OAuthIssuer())
	fields.Set("pa_client", tokenDigest(issue.Client.RowID))
	target, err := interactionURL(c, path, fields, time.Now().UTC().Truncate(time.Second).Add(issue.Lifetime), "")
	if err != nil {
		return nil, err
	}
	return c.RegisteredOAuthRedirect(target), nil
}

func signedAccountPage(c auth.EndpointContext, raw string, markers ...string) (url.Values, error) {
	q, err := c.Auth.VerifyOAuthQuery(raw)
	if err != nil {
		return nil, registrationProblem(400, "invalid_signature", "invalid or expired oauth query")
	}
	if len(q["pa_client"]) == 1 && q.Get("pa_client") != "" {
		for _, marker := range markers {
			if len(q[marker]) != 1 || q.Get(marker) != c.Auth.OAuthIssuer() {
				continue
			}
			if marker == "pa_post_issuer" {
				if q.Get("pa_consent") == "" || q.Get("ba_pl") == "" || q.Get("pa_post_binding") == "" {
					continue
				}
			} else if q.Has("pa_consent") {
				continue
			}
			return q, nil
		}
	}
	return nil, registrationProblem(400, "invalid_request", "signed query does not belong to the requested account step")
}

func requireBrowserOwner(c auth.EndpointContext) (*auth.SessionResult, error) {
	session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if session == nil || session.Session.RequireOwner() != nil || !c.DirectBrowserSession(session.Session.Token) {
		return nil, registrationProblem(401, "unauthorized", "browser session required")
	}
	return session, nil
}

func withoutPrompt(q url.Values, value string) {
	if !q.Has("prompt") {
		return
	}
	remaining := slices.DeleteFunc(promptValues(q.Get("prompt")), func(p string) bool { return p == value })
	if len(remaining) == 0 {
		q.Del("prompt")
	} else {
		q.Set("prompt", strings.Join(remaining, " "))
	}
}

// Build a new authorization request from verified fields. Preserve the
// registration identity across re-entry, including when a public ID is reused.
func accountAuthorizationRequest(c auth.EndpointContext, q url.Values, postLogin bool) *http.Request {
	next := browserContinuation{client: q.Get("pa_client"), postLogin: postLogin}
	if postLogin && q.Has("pa_consent") {
		next.clearedSession, next.binding = q.Get("ba_pl"), q.Get("pa_post_binding")
	}
	ctx := context.WithValue(c.Request.Context(), continuedClientKey{}, next)
	for _, k := range []string{"sig", "exp", "ba_iat", "ba_param", "pa_login", "pa_signup", "pa_select", "pa_client", "pa_post", "pa_post_issuer", "pa_post_binding", "pa_consent", "ba_pl"} {
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
	if _, err := signedAccountPage(c, raw, "pa_login"); err != nil {
		return nil, err
	}
	return func(session auth.Session) (*http.Request, error) {
		// Credential checks and two-factor verification can outlive the query.
		q, err := signedAccountPage(c, raw, "pa_login")
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
		return accountAuthorizationRequest(c, q, false), nil
	}, nil
}

// checkBodyQuery verifies a truthy oauth_query before anything else reads
// the body, as another runtime's plugin hook does before body validation
// and the session check; a non-string value never verifies.
func checkBodyQuery(c auth.EndpointContext) error {
	raw := c.Body["oauth_query"]
	if !jsjson.Truthy(raw) {
		return nil
	}
	if s, ok := raw.(string); ok {
		if _, err := c.Auth.VerifyOAuthQuery(s); err == nil {
			return nil
		}
	}
	return registrationProblem(400, "invalid_signature", "invalid or expired oauth query")
}

// bodyField names a body field, its JSON type and whether it is required.
// The type "string|object" accepts a string or a non-array object.
type bodyField struct {
	name, want string
	required   bool
}

// checkBodyTypes checks the fields' JSON types in schema order and reports
// every mismatch together, in another runtime's body validation form.
func checkBodyTypes(body map[string]any, fields ...bodyField) error {
	var issues []string
	for _, f := range fields {
		raw, ok := body[f.name]
		received := "undefined"
		if ok {
			received = jsjson.TypeName(raw)
		}
		switch {
		case !ok && !f.required, received == f.want:
		case f.want == "string|object":
			if received != "string" && received != "object" {
				issues = append(issues, "[body."+f.name+"] Invalid input")
			}
		default:
			issues = append(issues, "[body."+f.name+"] Invalid input: expected "+f.want+", received "+received)
		}
	}
	if len(issues) > 0 {
		return &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: strings.Join(issues, "; ")}
	}
	return nil
}

func (opts Options) continueAccount(c auth.EndpointContext) (any, error) {
	// As in another runtime, a present signed query is verified first, then
	// the body's types, the session, and the account step and its query.
	if err := checkBodyQuery(c); err != nil {
		return nil, err
	}
	if err := checkBodyTypes(c.Body, bodyField{"selected", "boolean", false}, bodyField{"created", "boolean", false},
		bodyField{"postLogin", "boolean", false}, bodyField{"oauth_query", "string", false}); err != nil {
		return nil, err
	}
	if _, err := requireBrowserOwner(c); err != nil {
		return nil, err
	}
	// The first true flag, in the order selected, created and postLogin,
	// picks the step. Each step accepts only a query signed for its own
	// page, where another runtime resumes from any signed query: a query
	// signed for a login or consent page cannot skip a chooser or a
	// post-login gate that never ran.
	var markers []string
	var prompt string
	switch {
	case c.Body["selected"] == true:
		markers, prompt = []string{"pa_select"}, "select_account"
	case c.Body["created"] == true:
		markers, prompt = []string{"pa_login", "pa_signup"}, "create"
	case c.Body["postLogin"] == true:
		markers = []string{"pa_post", "pa_post_issuer"}
	default:
		return nil, registrationProblem(400, "invalid_request", "Missing parameters")
	}
	raw, _ := c.Body["oauth_query"].(string)
	if raw == "" {
		return nil, registrationProblem(400, "invalid_request", "missing oauth query")
	}
	q, err := signedAccountPage(c, raw, markers...)
	if err != nil {
		return nil, err
	}
	if prompt != "" {
		withoutPrompt(q, prompt)
	}
	r := accountAuthorizationRequest(c, q, prompt == "")
	r.Header.Set("Accept", "application/json")
	return c.ResumeOAuthAuthorization(r)
}

const continueAccountOperation = `{"summary":"Continue browser authorization after a host account step","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["oauth_query"],"anyOf":[{"required":["created"]},{"required":["selected"]},{"required":["postLogin"]}],"properties":{"postLogin":{"type":"boolean","enum":[true]},"selected":{"type":"boolean","enum":[true]},"created":{"type":"boolean","enum":[true]},"oauth_query":{"type":"string"}}}}}},"responses":{"200":{"description":"Authorization redirect instructions"},"400":{"description":"Invalid or expired account page query"},"401":{"description":"Browser session required"}}}`
