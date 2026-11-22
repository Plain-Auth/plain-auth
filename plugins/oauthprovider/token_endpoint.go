package oauthprovider

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

type tokenRequest struct {
	id, secret, method string
	scopes, resources  []string
	dpop               bool
	assertion          *clientAssertion
}

const tokenFormType = "application/x-www-form-urlencoded"

const machineTokenOperation = `{
  "summary":"Exchange confidential application credentials for an opaque access token",
  "security":[{"clientSecretBasic":[]},{}],
  "description":"Use the registered HTTP Basic, client_secret_post or private_key_jwt method. A signed assertion replaces the client secret and must be fresh for each request.",
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{
    "type":"object","required":["grant_type"],"properties":{
      "grant_type":{"type":"string","enum":["client_credentials"]},"client_id":{"type":"string"},
      "client_secret":{"type":"string","format":"password"},"client_assertion_type":{"type":"string","enum":["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]},
      "client_assertion":{"type":"string","format":"jwt"},"scope":{"type":"string"}
    }}}}},
  "responses":{"200":{"description":"Machine access token","content":{"application/json":{"schema":{
    "type":"object","required":["access_token","token_type","expires_in","expires_at","scope"],"properties":{
      "access_token":{"type":"string"},"token_type":{"type":"string","enum":["Bearer"]},
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
	if grant != "client_credentials" || !slices.Contains(opts.GrantTypes, grant) {
		return nil, registrationProblem(400, "unsupported_grant_type", "unsupported grant_type "+grant)
	}
	in, challenge, err := parseTokenCredentials(form, c.Request.Header.Values("Authorization"))
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, challenge, err)
	}
	if in.id == "" {
		return nil, registrationProblem(400, "invalid_request", "Missing required client_id")
	}
	in.resources = form["resource"]
	if scopes := form["scope"]; len(scopes) != 0 {
		in.scopes = strings.Split(scopes[len(scopes)-1], " ")
	}
	in.dpop = len(c.Request.Header.Values("DPoP")) != 0
	store, ok := c.Store().(MachineTokenStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_TOKEN_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth machine tokens"}
	}
	first, err := opts.authenticateClient(c, store, in, "/oauth2/token")
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, challenge, err)
	}
	token, err := opts.issueMachineToken(c.Request.Context(), store, in, first)
	return token, tokenEndpointError(c.ResponseHeader, challenge, err)
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

func parseTokenCredentials(form url.Values, headers []string) (tokenRequest, string, error) {
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
