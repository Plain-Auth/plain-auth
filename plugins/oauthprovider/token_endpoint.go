package oauthprovider

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/jsjson"
)

type tokenRequest struct {
	id, secret, method string
	scopes, resources  []string
	proof              string
	assertion          *clientAssertion
	// extension is an assertion an extension strategy checks; proven marks
	// a client it proved, with the confirmation it returned.
	extension    *ClientAuthenticationInput
	strategy     ClientAuthenticationStrategy
	proven       bool
	confirmation *Confirmation
}

const tokenFormType = "application/x-www-form-urlencoded"

const machineTokenOperation = `{
  "summary":"Exchange application credentials, a delegated authorization code or a refresh token",
  "security":[{"clientSecretBasic":[]},{}],
  "description":"Machine clients use their registered HTTP Basic, client_secret_post or private_key_jwt method and may bind tokens with DPoP. A delegated opaque exchange uses the registered client method, the code, its original redirect URI and its S256 verifier when PKCE was used. Public clients always use PKCE at authorization. An untargeted bearer refresh grant may retain or narrow its scopes. An offline parent rotates on success.",
  "parameters":[{"name":"DPoP","in":"header","schema":{"type":"string"},"description":"A signed proof for a sender-bound machine token"}],
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{
    "type":"object","required":["grant_type"],"properties":{
      "grant_type":{"type":"string","enum":["client_credentials","authorization_code","refresh_token"]},"client_id":{"type":"string"},
      "refresh_token":{"type":"string","description":"Credential to exchange on a refresh_token grant"},
      "code":{"type":"string"},"code_verifier":{"type":"string"},"redirect_uri":{"type":"string","format":"uri"},
      "client_secret":{"type":"string","format":"password"},"client_assertion_type":{"type":"string","enum":["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]},
      "client_assertion":{"type":"string","format":"jwt"},"scope":{"type":"string"},
      "resource":{"type":"array","items":{"type":"string","format":"uri"},"description":"Repeat this form parameter to request multiple resource audiences"}
    }}}}},
  "responses":{"200":{"description":"Access token","content":{"application/json":{"schema":{
    "type":"object","required":["access_token","token_type","expires_in","expires_at","scope"],"properties":{
      "access_token":{"type":"string"},"id_token":{"type":"string","format":"jwt","description":"Signed ID token for a supported OpenID Connect grant"},"refresh_token":{"type":"string","description":"Returned on supported delegated offline grants"},"token_type":{"type":"string","enum":["Bearer","DPoP"]},
      "expires_in":{"type":"integer"},"expires_at":{"type":"integer"},"scope":{"type":"string"}
    }}}}},"400":{"description":"OAuth grant, client or scope rejected"},"401":{"description":"HTTP client authentication failed"},"415":{"description":"Unsupported token request media type"}}
}`

func (opts Options) token(c auth.EndpointContext) (any, error) {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	form, err := readTokenForm(c.Request)
	if err != nil {
		return nil, err
	}
	grants, ok := form["grant_type"]
	if !ok {
		return nil, registrationProblem(400, "invalid_request", "grant_type is required")
	}
	grant := jsjson.TrimSpace(grants[len(grants)-1])
	if grant == "" {
		return nil, registrationProblem(400, "invalid_request", "grant_type: Too small: expected string to have >=1 characters")
	}
	if len(form["resource"]) > 64 {
		return nil, registrationProblem(400, "invalid_target", "at most 64 resource parameters are supported")
	}
	for _, id := range form["resource"] {
		if !ValidResourceIdentifier(id) {
			return nil, registrationProblem(400, "invalid_request", "resource must be an absolute URI without a fragment")
		}
	}
	// An extension grant gets the request before any credential is read,
	// as in another runtime.
	if handler := opts.grantHandler(grant); handler != nil {
		provider := &ProviderAPI{opts: opts, c: c, form: form, grant: grant}
		response, err := handler(GrantInput{Endpoint: c, Form: form, GrantType: grant, Provider: provider})
		if err != nil {
			return nil, tokenEndpointError(c.ResponseHeader, provider.challenge, err)
		}
		return response, nil
	}
	if !slices.Contains(opts.GrantTypes, grant) || (grant != "client_credentials" && grant != "authorization_code" && grant != "refresh_token") {
		return nil, registrationProblem(400, "unsupported_grant_type", "unsupported grant_type "+grant)
	}
	in, challenge, err := opts.readCredentials(c, form, "/oauth2/token")
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, challenge, err)
	}
	if in.id == "" {
		return nil, registrationProblem(400, "invalid_request", "Missing required client_id")
	}
	if c, err = opts.discoverRequestClient(c, in.id); err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, challenge, err)
	}
	in.resources = form["resource"]
	if scopes := form["scope"]; len(scopes) != 0 {
		in.scopes = strings.Split(scopes[len(scopes)-1], " ")
	}
	in.proof = c.Request.Header.Get("DPoP")
	if grant == "refresh_token" {
		token, err := opts.exchangeRefreshGrant(c, in, form)
		if err != nil {
			return token, tokenEndpointError(c.ResponseHeader, challenge, err)
		}
		if token.replay != nil {
			return token.replay, nil
		}
		return tokenBody(token, token.fields)
	}
	if grant == "authorization_code" {
		token, err := opts.redeemAuthorizationCode(c, in, form)
		if err != nil {
			return token, tokenEndpointError(c.ResponseHeader, challenge, err)
		}
		return tokenBody(token, token.fields)
	}
	store, ok := c.Store().(MachineTokenStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_TOKEN_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth machine tokens"}
	}
	first, err := opts.authenticateClient(c, store, in, "/oauth2/token")
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, challenge, err)
	}
	if len(c.Request.Header.Values("DPoP")) > 1 {
		return nil, proofError("DPoP proof header must not be repeated")
	}
	token, err := opts.issueMachineToken(c, store, in, first)
	if err != nil {
		return token, tokenEndpointError(c.ResponseHeader, challenge, err)
	}
	return tokenBody(token, token.fields)
}

func tokenEndpointError(headers http.Header, challenge string, err error) error {
	if errors.Is(err, ErrClientNotFound) {
		err = invalidClient("client not found")
	}
	var problem *auth.OAuthError
	if errors.As(err, &problem) && problem.Code == "invalid_client" && (challenge != "" || problem.Status == 401) {
		if challenge == "" {
			challenge = "Basic"
		}
		headers.Set("WWW-Authenticate", challenge)
		headers.Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		return registrationProblem(401, problem.Code, problem.Description)
	}
	return err
}

func readTokenForm(r *http.Request) (url.Values, error) {
	data, err := io.ReadAll(r.Body) // Raw plugin requests are bounded by the auth handler.
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &auth.APIError{Status: 413, Code: "PAYLOAD_TOO_LARGE", Message: "Request body too large"}
		}
		return nil, registrationProblem(400, "invalid_request", "Invalid request body")
	}
	media := r.Header.Get("Content-Type")
	base, _, _ := strings.Cut(media, ";")
	if (len(data) != 0 || media != "") && !strings.EqualFold(strings.TrimSpace(base), tokenFormType) {
		msg := "Content-Type is required. Allowed types: " + tokenFormType
		if media != "" {
			msg = `Content-Type "` + media + `" is not allowed. Allowed types: ` + tokenFormType
		}
		return nil, &auth.APIError{Status: 415, Code: "UNSUPPORTED_MEDIA_TYPE", Message: msg}
	}
	form := url.Values{}
	for pair := range strings.SplitSeq(string(data), "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		form.Add(decodeTokenFormValue(k), decodeTokenFormValue(v))
	}
	return form, nil
}

// A URL-encoded form treats a percent sign without two hex digits as literal data.
// QueryUnescape handles the common case, including form-encoded plus signs.
func decodeTokenFormValue(s string) string {
	v, err := url.QueryUnescape(s)
	if err != nil {
		var fixed strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '%' && (i+3 > len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2])) {
				fixed.WriteString("%25")
			} else {
				fixed.WriteByte(s[i])
			}
		}
		v, _ = url.QueryUnescape(fixed.String())
	}
	return strings.ToValidUTF8(v, "�")
}

func isHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

var authScheme = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// readCredentials parses the client's credentials and runs an extension
// strategy for an extension assertion, before any store call, with the
// public URL of endpoint as the expected audience.
func (opts Options) readCredentials(c auth.EndpointContext, form url.Values, endpoint string) (tokenRequest, string, error) {
	in, challenge, err := parseTokenCredentials(form, c.Request.Header.Values("Authorization"), opts.clientAuthStrategy)
	if err != nil || in.extension == nil {
		return in, challenge, err
	}
	input := *in.extension
	input.ExpectedAudience = c.Auth.PublicURL() + endpoint
	input.Header = c.Request.Header.Clone()
	input.limits = opts.Assertions
	input.replay, _ = c.Store().(ClientAssertionReplayStore)
	result, err := in.strategy.Authenticate(c.Request.Context(), input)
	if err != nil {
		var problem *auth.OAuthError
		if errors.As(err, &problem) {
			return in, challenge, err
		}
		return in, challenge, fmt.Errorf("oauthprovider: client authentication strategy: %w", err)
	}
	if result.ClientID == "" {
		return in, challenge, invalidClient("client assertion did not identify a client")
	}
	// A form client_id must name the proven client, as with
	// private_key_jwt, where another runtime takes the strategy's value.
	if input.ClientID != "" && input.ClientID != result.ClientID {
		return in, challenge, invalidClient("client_id does not match the client assertion")
	}
	in.id, in.proven, in.confirmation = result.ClientID, true, result.Confirmation
	return in, challenge, nil
}

// parseTokenCredentials reads the client's credentials. strategy finds an
// extension method for a client_assertion_type, or reports none.
func parseTokenCredentials(form url.Values, headers []string, strategy func(string) (string, ClientAuthenticationStrategy, bool)) (tokenRequest, string, error) {
	var in tokenRequest
	fields := make(map[string]string, 4)
	for _, key := range []string{"client_id", "client_secret", "client_assertion", "client_assertion_type"} {
		for _, value := range form[key] {
			if value == "" {
				continue
			}
			if fields[key] != "" {
				return in, "", registrationProblem(400, "invalid_request", key+" must not be repeated")
			}
			fields[key] = value
		}
	}
	secret := fields["client_secret"]
	assertion := fields["client_assertion"] != "" || fields["client_assertion_type"] != ""
	if len(headers) > 1 {
		return in, "", registrationProblem(400, "invalid_request", "Authorization must not be repeated")
	}
	var header string
	if len(headers) == 1 {
		header = headers[0]
	}
	if header != "" && (secret != "" || assertion) || secret != "" && assertion {
		return in, "", registrationProblem(400, "invalid_request", "A request must use only one client authentication method")
	}
	if assertion {
		if fields["client_assertion"] == "" || fields["client_assertion_type"] == "" {
			return in, "", invalidClient("client_assertion and client_assertion_type must both be provided")
		}
		if strategy != nil {
			if method, s, ok := strategy(fields["client_assertion_type"]); ok {
				in.method, in.strategy = method, s
				in.extension = &ClientAuthenticationInput{Assertion: fields["client_assertion"], AssertionType: fields["client_assertion_type"], ClientID: fields["client_id"]}
				return in, "", nil
			}
		}
		a, err := parseClientAssertion(fields["client_assertion_type"], fields["client_assertion"], fields["client_id"])
		if err != nil {
			return in, "", err
		}
		in.id, in.method, in.assertion = a.clientID, "private_key_jwt", a
		return in, "", nil
	}
	if header != "" {
		scheme, payload, space := strings.Cut(header, " ")
		if !space || !strings.EqualFold(scheme, "Basic") {
			if i := strings.IndexAny(scheme, "\t\r\n"); i >= 0 {
				scheme = scheme[:i]
			}
			if !authScheme.MatchString(scheme) {
				return in, "", registrationProblem(400, "invalid_request", "Invalid authorization header format")
			}
			return in, scheme, invalidClient("unsupported authorization scheme")
		}
		payload = strings.TrimLeft(payload, " ")
		data, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			data, err = base64.RawStdEncoding.DecodeString(payload)
		}
		id, raw, ok := strings.Cut(string(data), ":")
		if err != nil || !ok || id == "" || raw == "" {
			return in, "Basic", invalidClient("invalid authorization header format")
		}
		in.id, in.secret, in.method = decodeTokenFormValue(id), decodeTokenFormValue(raw), "client_secret_basic"
		return in, "Basic", nil
	}
	in.id, in.secret = fields["client_id"], secret
	in.method = "none"
	if in.secret != "" {
		in.method = "client_secret_post"
	}
	return in, "", nil
}
