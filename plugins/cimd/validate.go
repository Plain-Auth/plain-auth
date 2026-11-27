package cimd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// Profile names a protocol profile of metadata documents.
type Profile string

// ProfileMCP20260728 is the Model Context Protocol 2026-07-28 profile, which
// requires client_name and redirect_uris.
const ProfileMCP20260728 Profile = "mcp-2026-07-28"

// ValidationOptions configures ValidateMetadata.
type ValidationOptions struct {
	// OriginBoundFields are the members whose URLs must share the client
	// ID's origin. Nil means post_logout_redirect_uris; an empty, non-nil
	// list binds none, as another runtime's [] does.
	OriginBoundFields []string
	Profile           Profile
}

var dotSegment = regexp.MustCompile(`(?i)/(?:\.|%2e)(?:\.|%2e)?(?:/|$|#|\?)`)

// IsClientIDURLCandidate reports whether a client ID looks like a metadata
// document URL: an https URL that names a host, including the forms without
// "//" another runtime's URL parser repairs, which ValidateClientIDURL then
// refuses. It is a routing check and resolves nothing.
func IsClientIDURLCandidate(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" {
		return false
	}
	rest := strings.TrimLeft(clientID[len("https:"):], `/\`)
	if i := strings.IndexAny(rest, `/\?#`); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	return rest != ""
}

// ValidateClientIDURL checks a client ID URL as draft-02 §3 requires, in
// another runtime's order: no dot segments or fragment, a valid URL, HTTPS
// with an explicit authority and path, no credentials and a public host.
func ValidateClientIDURL(raw string) error {
	if dotSegment.MatchString(raw) {
		return errors.New("client_id URL MUST NOT contain dot segments")
	}
	if strings.Contains(raw, "#") {
		return errors.New("client_id URL MUST NOT contain a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || !validPort(u.Port()) || !validHost(u.Hostname()) {
		return errors.New("client_id is not a valid URL")
	}
	if u.Scheme != "https" {
		return errors.New("client_id URL must use HTTPS")
	}
	if len(raw) < len("https://") || !strings.EqualFold(raw[:len("https://")], "https://") || strings.Contains(raw, `\`) {
		return errors.New("client_id URL MUST use an explicit HTTPS authority form")
	}
	rest := raw[len("https://"):]
	end := strings.IndexAny(rest, "/?#")
	if end == 0 {
		return errors.New("client_id URL MUST use an explicit HTTPS authority form")
	}
	if end < 0 || rest[end] != '/' {
		return errors.New("client_id URL MUST contain an explicit path component")
	}
	if u.User != nil {
		return errors.New("client_id URL MUST NOT contain credentials")
	}
	if !publicnet.PublicHost(u.Hostname()) {
		return errors.New("client_id URL must not target a private or reserved address")
	}
	return nil
}

func validPort(port string) bool {
	if port == "" {
		return true
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n <= 65535
}

func validHost(host string) bool {
	if host == "" || strings.Contains(host, ":") {
		return true
	}
	_, err := publicnet.HostASCII(host)
	return err == nil
}

var symmetricMethods = map[string]bool{"client_secret_post": true, "client_secret_basic": true, "client_secret_jwt": true}

// ValidateMetadata checks a fetched metadata document as draft-02 §4.1
// requires, in another runtime's order, and returns it with unknown members
// stripped and token_endpoint_auth_method defaulted to none, plus warnings
// about the client ID URL. Type errors use the provider's registration
// wording, not the other runtime's schema library text.
func ValidateMetadata(clientIDURL string, raw []byte, opts ValidationOptions) (oauthprovider.ClientMetadataDocument, []string, error) {
	var none oauthprovider.ClientMetadataDocument
	field, err := firstForbiddenMember(raw)
	if err != nil {
		return none, nil, err
	}
	if field != "" {
		return none, nil, fmt.Errorf(`metadata document MUST NOT contain "%s"`, field)
	}
	doc, err := oauthprovider.ParseClientMetadataDocument(raw)
	if err != nil {
		var problem *auth.OAuthError
		if errors.As(err, &problem) {
			return none, nil, errors.New(problem.Description)
		}
		return none, nil, err
	}
	doc.Extensions = nil
	if doc.ClientID != clientIDURL {
		return none, nil, fmt.Errorf(`client_id "%s" does not match the metadata document URL`, doc.ClientID)
	}
	if opts.Profile == ProfileMCP20260728 && (doc.Name == nil || strings.TrimSpace(*doc.Name) == "") {
		return none, nil, errors.New("client_name must be a non-empty string")
	}
	if doc.BackchannelLogoutURI != nil {
		return none, nil, errors.New(`metadata document MUST NOT contain "backchannel_logout_uri"`)
	}
	if doc.BackchannelLogoutSessionRequired != nil {
		return none, nil, errors.New(`metadata document MUST NOT contain "backchannel_logout_session_required"`)
	}
	if method := doc.TokenEndpointAuthMethod; method != "" {
		switch {
		case symmetricMethods[method]:
			return none, nil, fmt.Errorf(`symmetric auth method "%s" is prohibited for Client ID Metadata Document clients`, method)
		case method != "none" && method != "private_key_jwt":
			return none, nil, errors.New(`token_endpoint_auth_method must be "none" or "private_key_jwt" for Client ID Metadata Document clients`)
		case method == "private_key_jwt" && doc.JWKS == nil && doc.JWKSURI == nil:
			return none, nil, errors.New("private_key_jwt requires either jwks or jwks_uri in the metadata document")
		}
	}
	if doc.JWKS != nil && oauthprovider.ValidatePublicClientJWKS(doc.JWKS) != nil {
		return none, nil, errors.New("jwks must contain only structurally valid public keys")
	}
	if doc.JWKSURI != nil {
		u, err := url.Parse(*doc.JWKSURI)
		switch {
		case err != nil || !u.IsAbs():
			return none, nil, errors.New("jwks_uri must be a valid URL")
		case u.User != nil:
			return none, nil, errors.New("jwks_uri must not contain credentials")
		case strings.Contains(*doc.JWKSURI, "#"):
			return none, nil, errors.New("jwks_uri must not contain a fragment")
		}
	}
	redirects := errors.New("redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs")
	if opts.Profile == ProfileMCP20260728 && doc.RedirectURIs == nil {
		return none, nil, redirects
	}
	for _, raw := range doc.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Scheme != "http" && u.Scheme != "https" && !privateUse(u) {
			return none, nil, redirects
		}
	}
	for _, f := range []struct {
		name  string
		value *string
	}{{"client_uri", doc.URI}, {"logo_uri", doc.LogoURI}, {"tos_uri", doc.TermsURI}, {"policy_uri", doc.PolicyURI}} {
		if f.value == nil {
			continue
		}
		u, err := url.Parse(*f.value)
		switch {
		case err != nil || !u.IsAbs():
			return none, nil, fmt.Errorf("%s is not a valid URL", f.name)
		case u.Scheme != "https" && u.Scheme != "http":
			return none, nil, fmt.Errorf("%s must use HTTP(S)", f.name)
		case u.User != nil:
			return none, nil, fmt.Errorf("%s must not contain credentials", f.name)
		case !publicnet.PublicHost(u.Hostname()):
			return none, nil, fmt.Errorf("%s must not point to a private or reserved address", f.name)
		}
	}
	if err := checkOrigins(clientIDURL, doc, opts.OriginBoundFields); err != nil {
		return none, nil, err
	}
	var warnings []string
	if u, err := url.Parse(clientIDURL); err == nil {
		if u.Path == "/" {
			warnings = append(warnings, "client_id URL path / is NOT RECOMMENDED (§3)")
		}
		if u.RawQuery != "" {
			warnings = append(warnings, "client_id URL SHOULD NOT contain a query string (§3)")
		}
	}
	if doc.TokenEndpointAuthMethod == "" {
		doc.TokenEndpointAuthMethod = "none"
	}
	return doc, warnings, nil
}

// firstForbiddenMember returns the first top-level member, in document
// order, that a metadata document must not carry.
func firstForbiddenMember(raw []byte) (string, error) {
	notObject := errors.New("metadata document is not a JSON object")
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", notObject
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", notObject
		}
		name, _ := token.(string)
		if oauthprovider.IsForbiddenMetadataDocumentField(name) {
			return name, nil
		}
		var skip json.RawMessage
		if err := decoder.Decode(&skip); err != nil {
			return "", notObject
		}
	}
	return "", nil
}

// checkOrigins requires the origin-bound members' URLs to share the client
// ID's origin. A private-use redirect URI has no origin and is exempt, in
// post_logout_redirect_uris only in its reverse-domain form, and loopback
// HTTP(S) redirect URIs are exempt for native apps.
func checkOrigins(clientIDURL string, doc oauthprovider.ClientMetadataDocument, fields []string) error {
	if fields == nil {
		fields = []string{"post_logout_redirect_uris"}
	}
	clientID, err := url.Parse(clientIDURL)
	if err != nil {
		return errors.New("client_id is not a valid URL")
	}
	clientOrigin, ok := origin(clientID)
	if !ok {
		return errors.New("client_id is not a valid URL")
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var members map[string]any
	if err := json.Unmarshal(encoded, &members); err != nil {
		return err
	}
	for _, key := range fields {
		value, present := members[key]
		if !present {
			continue
		}
		var values []string
		switch v := value.(type) {
		case string:
			values = []string{v}
		case []any:
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("%s must be a string or an array of strings", key)
				}
				values = append(values, s)
			}
		default:
			return fmt.Errorf("%s must be a string or an array of strings", key)
		}
		redirect := key == "redirect_uris" || key == "post_logout_redirect_uris"
		for _, raw := range values {
			u, err := url.Parse(raw)
			if err != nil || !u.IsAbs() {
				return fmt.Errorf(`%s contains an invalid URL: "%s"`, key, raw)
			}
			web := u.Scheme == "http" || u.Scheme == "https"
			native := redirect && privateUse(u)
			if !web && !native {
				return fmt.Errorf("all values for %s must use HTTP(S) or a private-use scheme", key)
			}
			if native && (key == "redirect_uris" || reverseDomain(u)) {
				continue
			}
			// An opaque origin is empty and never matches.
			if o, _ := origin(u); o != clientOrigin && !(redirect && web && publicnet.Loopback(u.Hostname())) {
				return fmt.Errorf(`%s value "%s" must have the same origin as client_id (%s)`, key, raw, clientOrigin)
			}
		}
	}
	return nil
}

// origin is an HTTP(S) URL's web origin as a browser serializes it: the
// scheme, the host in ASCII and a port other than the default, without
// credentials. ok is false for a URL without one, whose origin is opaque.
func origin(u *url.URL) (string, bool) {
	host := u.Hostname()
	if u.Scheme != "http" && u.Scheme != "https" || host == "" {
		return "", false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
		if ip.Is6() {
			host = "[" + host + "]"
		}
	} else {
		ascii, err := publicnet.HostASCII(host)
		if err != nil {
			return "", false
		}
		host = strings.ToLower(ascii)
	}
	if port := u.Port(); port != "" && !(u.Scheme == "http" && port == "80" || u.Scheme == "https" && port == "443") {
		host += ":" + port
	}
	return u.Scheme + "://" + host, true
}

var reverseDomainScheme = regexp.MustCompile(`(?i)^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

var nonPrivateUseSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "file": true, "ftp": true, "mailto": true,
	"javascript": true, "data": true, "vbscript": true, "blob": true, "about": true, "view-source": true}

// reverseDomain reports an authority-free private-use URI whose scheme is a
// reversed domain name, such as com.example.app:/callback.
func reverseDomain(u *url.URL) bool {
	rest := strings.TrimPrefix(u.String(), u.Scheme+":")
	return u.Scheme != "http" && u.Scheme != "https" && u.Host == "" && strings.HasPrefix(rest, "/") && !strings.HasPrefix(rest, "//") && reverseDomainScheme.MatchString(u.Scheme)
}

// privateUse reports a native app's private-use redirect URI: the
// reverse-domain form, or a host-bearing URI of a non-reserved scheme with
// a path.
func privateUse(u *url.URL) bool {
	if reverseDomain(u) {
		return true
	}
	return !nonPrivateUseSchemes[u.Scheme] && u.Host != "" && strings.HasPrefix(u.EscapedPath(), "/")
}
