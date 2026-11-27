package oauthprovider

import (
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
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
		// Every unknown scope is named in request order, as in another runtime.
		var invalid []string
		for _, s := range strings.Split(q.Get("scope"), " ") {
			if s != "" && !slices.Contains(allowed, s) {
				invalid = append(invalid, s)
			}
		}
		if len(invalid) > 0 {
			return fail("invalid_scope", "The following scopes are invalid: "+strings.Join(invalid, ", "))
		}
		scopes = distinct(strings.Split(q.Get("scope"), " "))
	}
	if opts.Authorization.RequireOpenID && (!q.Has("scope") || !slices.Contains(scopes, "openid")) {
		return fail("invalid_scope", "the openid scope is required")
	}
	request := browserAuthorizationRequest{BrowserCodeIssue: BrowserCodeIssue{Client: client, Scopes: scopes, Lifetime: opts.Authorization.CodeLifetime}}
	request.Query = map[string]string{"redirect_uri": q.Get("redirect_uri")}
	if q.Has("claims") && !slices.Contains(scopes, "openid") {
		return fail("invalid_request", "openid scope must be requested when using the claims parameter")
	}
	if q.Has("claims") {
		doc, problem := parseOIDCClaims(q.Get("claims"))
		if problem != nil {
			return browserAuthorizationRequest{}, problem
		}
		names, err := opts.authorizedUserInfoClaims(json.RawMessage(q.Get("claims")))
		if err != nil {
			return fail("invalid_request", "invalid UserInfo claim request")
		}
		request.RequestedUserInfoClaims = names
		if encoded := filterUserInfoClaims(doc, names); encoded != "" {
			request.Query["claims"] = encoded
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
	// Resource indicators are checked against the resource registry after
	// these request checks, where another runtime checks them first.
	if len(q["resource"]) > 64 {
		return fail("invalid_target", "at most 64 resource parameters are supported")
	}
	for _, id := range q["resource"] {
		if !ValidResourceIdentifier(id) {
			return fail("invalid_request", "resource must be an absolute URI without a fragment")
		}
	}
	request.Resources = distinct(q["resource"])
	if q.Has("dpop_jkt") || client.RequireDPoP {
		return fail("invalid_request", "this authorization request requires an unsupported token binding")
	}
	prompts := distinct(promptValues(q.Get("prompt")))
	for _, prompt := range prompts {
		if !slices.Contains([]string{"none", "login", "consent", "create", "select_account"}, prompt) {
			return fail("invalid_request", "unsupported prompt value")
		}
	}
	if q.Has("prompt") && (len(prompts) == 0 || len(prompts) > 1 && slices.Contains(prompts, "none")) {
		return fail("invalid_request", "invalid combination of prompts")
	}
	request.prompts = prompts
	if q.Has("max_age") {
		age, err := strconv.ParseInt(strings.TrimSpace(q.Get("max_age")), 10, 64)
		if err != nil || age < 0 {
			return fail("invalid_request", "max_age must be a non-negative integer")
		}
		request.MaxAge = &age
	}
	for _, k := range []string{"state", "code_challenge", "code_challenge_method", "nonce", "acr_values", "prompt", "display", "ui_locales", "login_hint", "response_mode"} {
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
	// As in another runtime, a callback with a fragment or credentials, or
	// one that does not parse, never matches, even when stored that way.
	u, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") || u.User != nil {
		return false
	}
	if slices.Contains(c.RedirectURIs, raw) {
		return true
	}
	if c.ApplicationType == "web" {
		return false
	}
	key := loopbackCallback(raw)
	return key != "" && slices.ContainsFunc(c.RedirectURIs, func(uri string) bool { return loopbackCallback(uri) == key })
}

// redirectSyntax describes why a requested callback fails the redirect URI
// syntax another runtime's authorization query schema applies, or returns "".
func redirectSyntax(raw string) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs():
		return "Invalid URL"
	case u.Scheme == "javascript" || u.Scheme == "data" || u.Scheme == "vbscript":
		return "URL cannot use javascript:, data:, or vbscript: scheme"
	case strings.Contains(raw, "#"):
		return "Redirect URI must not contain a fragment component"
	}
	return ""
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
