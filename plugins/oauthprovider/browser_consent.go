package oauthprovider

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

// BrowserConsentPrompt binds a single decision to the original browser, client,
// issuer and tenant. Its identifier is carried in the signed interaction query.
type BrowserConsentPrompt struct {
	ID, Binding string
	ExpiresAt   time.Time
}

var ErrBrowserConsentExpired = errors.New("oauthprovider: consent request expired, changed or already used")

type BrowserConsentStore interface {
	BrowserAuthorizationStore
	SaveBrowserConsent(context.Context, BrowserConsentPrompt) error
	// FinishBrowserConsent consumes a live bound prompt. An acceptance writes
	// the consent and its code in the same transaction. A denial writes neither.
	FinishBrowserConsent(context.Context, BrowserCodeIssue, BrowserConsentPrompt, bool) error
}

type browserConsentDecision struct {
	clientFingerprint string
	session           *auth.SessionResult
	store             BrowserConsentStore
	request           BrowserConsentPrompt
	scopes            []string
	accept            bool
}

func consentBinding(issuer string, fingerprint string, issue BrowserCodeIssue) string {
	raw, _ := json.Marshal([]string{issuer, fingerprint, issue.Client.ClientID, issue.UserID, issue.SessionID, issue.ReferenceID})
	return tokenDigest(string(raw))
}

func consentDecisionError(err error) error {
	if errors.Is(err, ErrBrowserConsentExpired) {
		return registrationProblem(400, "invalid_request", "consent request expired, changed or already used")
	}
	return err
}

func (opts Options) openConsentPage(c auth.EndpointContext, original url.Values, issue BrowserCodeIssue) (any, error) {
	page, err := c.Auth.CallbackURL(opts.Authorization.ConsentPage)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(page)
	if err != nil {
		return nil, err
	}
	// Sign only normalized authorization parameters. The host may have its own page query.
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
	fingerprint := tokenDigest(issue.Client.RowID)
	fields.Set("pa_client", fingerprint)
	request := BrowserConsentPrompt{ID: rand.Text(), Binding: consentBinding(c.Auth.OAuthIssuer(), fingerprint, issue), ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(issue.Lifetime)}
	fields.Set("pa_consent", request.ID)
	signed := c.Auth.SignOAuthQuery(fields, request.ExpiresAt)
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
	if err := c.Store().(BrowserConsentStore).SaveBrowserConsent(c.Request.Context(), request); err != nil {
		return nil, err
	}
	return c.RegisteredOAuthRedirect(target.String()), nil
}

func (opts Options) browserConsent(c auth.EndpointContext) (any, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	raw, _ := c.Body["oauth_query"].(string)
	if raw == "" {
		return nil, registrationProblem(400, "invalid_request", "missing oauth query")
	}
	q, err := c.Auth.VerifyOAuthQuery(raw)
	if err != nil {
		return nil, registrationProblem(400, "invalid_signature", "invalid or expired oauth query")
	}
	accept, ok := c.Body["accept"].(bool)
	if !ok {
		return nil, registrationProblem(400, "invalid_request", "accept must be a boolean")
	}
	if len(q["pa_consent"]) != 1 || q.Get("pa_consent") == "" || len(q["pa_client"]) != 1 || q.Get("pa_client") == "" {
		return nil, consentDecisionError(ErrBrowserConsentExpired)
	}
	decision := browserConsentDecision{store: c.Store().(BrowserConsentStore), clientFingerprint: q.Get("pa_client"), accept: accept, request: BrowserConsentPrompt{ID: q.Get("pa_consent")}}
	if raw, present := c.Body["scope"]; present {
		value, ok := raw.(string)
		if !ok {
			return nil, registrationProblem(400, "invalid_request", "scope must be a space-separated string")
		}
		decision.scopes = distinct(strings.Split(value, " "))
	}
	if _, present := c.Body["claims"]; present {
		return nil, registrationProblem(400, "invalid_request", "claim selection requires OpenID authorization")
	}
	session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if session == nil || session.Session.RequireOwner() != nil || !c.DirectBrowserSession(session.Session.Token) {
		return nil, registrationProblem(401, "unauthorized", "browser session required")
	}
	decision.session = session
	requested := distinct(strings.Split(q.Get("scope"), " "))
	for _, scope := range decision.scopes {
		if !slices.Contains(requested, scope) {
			return nil, registrationProblem(400, "invalid_request", "Scope not originally requested")
		}
	}
	if !accept {
		// Consume the user's refusal even when the application has since been
		// disabled or removed. The destination is checked after consumption.
		issue := BrowserCodeIssue{Client: BrowserClient{ClientID: q.Get("client_id")}, UserID: session.User.ID, SessionID: session.Session.ID, SessionToken: session.Session.Token}
		if resolve := opts.Authorization.ConsentReference; resolve != nil {
			issue.ReferenceID, err = resolve(c.Request.Context(), RegistrationAccess{SessionResult: *session, Headers: c.Request.Header.Clone()}, requested)
			if err != nil {
				return nil, err
			}
		}
		decision.request.Binding = consentBinding(c.Auth.OAuthIssuer(), decision.clientFingerprint, issue)
		err = decision.store.FinishBrowserConsent(c.Request.Context(), issue, decision.request, false)
		if errors.Is(err, ErrAuthorizationSessionExpired) {
			return nil, registrationProblem(401, "unauthorized", "browser session required")
		}
		if err != nil {
			return nil, consentDecisionError(err)
		}
	}
	for _, k := range []string{"sig", "exp", "ba_iat", "ba_param", "pa_consent", "pa_client"} {
		q.Del(k)
	}
	c.Request = c.Request.Clone(c.Request.Context())
	c.Request.Header.Set("Accept", "application/json")
	return opts.runBrowserAuthorization(c, q, &decision)
}

const browserConsentOperation = `{"summary":"Approve or decline an OAuth authorization request","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["accept","oauth_query"],"properties":{"accept":{"type":"boolean"},"oauth_query":{"type":"string"},"scope":{"type":"string"}}}}}},"responses":{"200":{"description":"Redirect instruction to the application callback or issuer error page"},"400":{"description":"Invalid, expired or previously decided request"},"401":{"description":"Browser session required"}}}`
