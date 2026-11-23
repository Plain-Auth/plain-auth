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

// DeferredConsentStore supports recording approval when a host signup check
// requires another step before the issuer can issue a code.
type DeferredConsentStore interface {
	// ApproveBrowserConsent validates the live client, session and bound prompt,
	// consumes the prompt and records the selected scopes in one transaction.
	ApproveBrowserConsent(context.Context, BrowserCodeIssue, BrowserConsentPrompt) error
}

type browserConsentDecision struct {
	clientFingerprint string
	clearedSession    string
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
	fields := interactionFields(original, issue)
	fingerprint := tokenDigest(issue.Client.RowID)
	fields.Set("pa_client", fingerprint)
	request := BrowserConsentPrompt{ID: rand.Text(), Binding: consentBinding(c.Auth.OAuthIssuer(), fingerprint, issue), ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(issue.Lifetime)}
	fields.Set("pa_consent", request.ID)
	var clearedSession string
	if opts.Authorization.PostLogin != nil {
		clearedSession = issue.SessionID
		fields.Set("pa_post_issuer", c.Auth.OAuthIssuer())
		fields.Set("pa_post_binding", request.Binding)
	}
	target, err := interactionURL(c, opts.Authorization.ConsentPage, fields, request.ExpiresAt, clearedSession)
	if err != nil {
		return nil, err
	}
	if err := c.Store().(BrowserConsentStore).SaveBrowserConsent(c.Request.Context(), request); err != nil {
		return nil, err
	}
	return c.RegisteredOAuthRedirect(target), nil
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
	// A selector page can only restart the remaining steps. It cannot grant
	// consent until the issuer has actually presented a bound consent form.
	if accept && opts.Authorization.PostLogin != nil && !q.Has("pa_consent") && q.Get("pa_post") == c.Auth.OAuthIssuer() && len(q["pa_client"]) == 1 && q.Get("pa_client") != "" {
		if _, err := requireBrowserOwner(c); err != nil {
			return nil, err
		}
		q.Set("prompt", "consent")
		next := accountAuthorizationRequest(c, q, false)
		next.Header.Set("Accept", "application/json")
		return c.ResumeOAuthAuthorization(next)
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
	session, err := requireBrowserOwner(c)
	if err != nil {
		return nil, err
	}
	decision.session = session
	if q.Get("pa_post_issuer") == c.Auth.OAuthIssuer() {
		decision.clearedSession = q.Get("ba_pl")
	}
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
	for _, k := range []string{"sig", "exp", "ba_iat", "ba_param", "pa_consent", "pa_client", "ba_pl", "pa_post_issuer", "pa_post_binding"} {
		q.Del(k)
	}
	c.Request = c.Request.Clone(c.Request.Context())
	c.Request.Header.Set("Accept", "application/json")
	return opts.runBrowserAuthorization(c, q, &decision)
}

const browserConsentOperation = `{"summary":"Approve or decline an OAuth authorization request","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["accept","oauth_query"],"properties":{"accept":{"type":"boolean"},"oauth_query":{"type":"string"},"scope":{"type":"string"}}}}}},"responses":{"200":{"description":"Redirect instruction to the application callback or issuer error page"},"400":{"description":"Invalid, expired or previously decided request"},"401":{"description":"Browser session required"}}}`
