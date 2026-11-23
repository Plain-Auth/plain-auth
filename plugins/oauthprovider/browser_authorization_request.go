package oauthprovider

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

type browserAuthorizationRequest struct {
	BrowserCodeIssue
	prompts []string
}

func (opts Options) browserGrant(client BrowserClient, q url.Values) (browserAuthorizationRequest, *auth.OAuthError) {
	fail := func(code, description string) (browserAuthorizationRequest, *auth.OAuthError) {
		return browserAuthorizationRequest{}, &auth.OAuthError{Status: 400, Code: code, Description: description}
	}
	for name, values := range q {
		if name != "resource" && len(values) != 1 {
			return fail("invalid_request", "authorization parameters must not be repeated")
		}
	}
	if q.Has("request") && q.Has("request_uri") {
		return fail("invalid_request", "request and request_uri cannot be used together")
	}
	if q.Has("request") {
		return fail("request_not_supported", "request object not supported")
	}
	if q.Has("request_uri") {
		return fail("request_uri_not_supported", "request_uri not supported")
	}
	if q.Get("response_type") == "" {
		return fail("invalid_request", "response_type is required")
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "unsupported response type")
	}
	if q.Has("response_mode") && q.Get("response_mode") != "query" {
		return fail("invalid_request", "only query response mode is supported for authorization codes")
	}
	allowed := client.Scopes
	if allowed == nil {
		allowed = opts.Scopes
	}
	scopes := allowed
	if q.Has("scope") {
		scopes = distinct(strings.Split(q.Get("scope"), " "))
		for _, s := range scopes {
			if !slices.Contains(allowed, s) {
				return fail("invalid_scope", "The following scope is invalid: "+s)
			}
		}
	}
	policy := AuthorizationCodeClient{MachineClient: MachineClient{AuthMethod: client.AuthMethod}, RequirePKCE: client.RequirePKCE}
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	if reason := policy.PKCERequirement(scopes, q.Get("nonce")); reason != "" && (challenge == "" || method == "") {
		return fail("invalid_request", reason)
	}
	if (challenge != "" || method != "") && (challenge == "" || method != "S256") {
		return fail("invalid_request", "PKCE requires a challenge and the S256 method")
	}
	if q.Has("claims") && !slices.Contains(scopes, "openid") {
		return fail("invalid_request", "openid scope must be requested when using the claims parameter")
	}
	if q.Has("resource") {
		return fail("invalid_target", "resource-targeted browser authorization is unavailable")
	}
	if q.Has("dpop_jkt") || client.RequireDPoP || slices.Contains(scopes, "openid") {
		return fail("invalid_request", "this authorization request requires an unsupported token binding or ID token")
	}
	prompts := distinct(strings.Fields(q.Get("prompt")))
	for _, prompt := range prompts {
		if !slices.Contains([]string{"none", "login", "consent", "create", "select_account"}, prompt) {
			return fail("invalid_request", "unsupported prompt value")
		}
	}
	if q.Has("prompt") && (len(prompts) == 0 || len(prompts) > 1 && slices.Contains(prompts, "none")) {
		return fail("invalid_request", "invalid combination of prompts")
	}
	request := browserAuthorizationRequest{BrowserCodeIssue: BrowserCodeIssue{Client: client, Scopes: scopes, Lifetime: opts.Authorization.CodeLifetime}, prompts: prompts}
	if q.Has("max_age") {
		age, err := strconv.ParseInt(strings.TrimSpace(q.Get("max_age")), 10, 64)
		if err != nil || age < 0 {
			return fail("invalid_request", "max_age must be a non-negative integer")
		}
		request.MaxAge = &age
	}
	request.Query = map[string]string{"redirect_uri": q.Get("redirect_uri")}
	for _, k := range []string{"state", "code_challenge", "code_challenge_method", "nonce", "prompt", "display", "ui_locales", "login_hint", "response_mode"} {
		if q.Has(k) {
			request.Query[k] = q.Get(k)
		}
	}
	return request, nil
}

func browserFragmentError(q url.Values) bool {
	if len(q["response_mode"]) == 1 {
		switch q.Get("response_mode") {
		case "fragment":
			return true
		case "query":
			return false
		}
	}
	if len(q["response_type"]) != 1 {
		return false
	}
	types := strings.Fields(q.Get("response_type"))
	return slices.Contains(types, "token") || slices.Contains(types, "id_token")
}

func (c BrowserClient) matchesCallback(raw string) bool {
	if slices.Contains(c.RedirectURIs, raw) {
		return true
	}
	if c.ApplicationType == "web" {
		return false
	}
	key := loopbackCallback(raw)
	return key != "" && slices.ContainsFunc(c.RedirectURIs, func(uri string) bool { return loopbackCallback(uri) == key })
}

// Compare original URI bytes apart from the port, including escapes, host
// spelling, query ordering and the distinction between an empty path and "/".
func loopbackCallback(raw string) string {
	u, err := redirectURL(raw)
	if err != nil || u.Scheme != "http" || !exactLoopback(u.Hostname()) {
		return ""
	}
	start := strings.Index(raw, "://") + 3
	if start < 3 {
		return ""
	}
	end := start + len(u.Host)
	if end > len(raw) || raw[start:end] != u.Host {
		return ""
	}
	host := u.Host
	if port := u.Port(); port != "" {
		host = strings.TrimSuffix(host, ":"+port)
	}
	return raw[:start] + host + raw[end:]
}
