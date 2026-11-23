package oauthprovider

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
	"golang.org/x/net/idna"
)

// Only exact wire field names cross this boundary. Server-assigned fields and
// unknown metadata cannot set a client's credentials, ownership or privileges.
func readRegistration(body map[string]any) (RegistrationMetadata, error) {
	var m RegistrationMetadata
	value := reflect.ValueOf(&m).Elem()
	for i := 0; i < value.NumField(); i++ {
		name, _, _ := strings.Cut(value.Type().Field(i).Tag.Get("json"), ",")
		input, ok := body[name]
		if !ok {
			continue
		}
		raw, err := json.Marshal(input)
		if err != nil || input == nil || json.Unmarshal(raw, value.Field(i).Addr().Interface()) != nil {
			return m, fieldProblem(name, "invalid value for "+name)
		}
		if xs, ok := input.([]any); ok {
			for _, x := range xs {
				if _, ok := x.(string); !ok {
					return m, fieldProblem(name, "expected strings in "+name)
				}
			}
		}
	}
	if _, ok := body["skip_consent"]; ok {
		return m, metadataProblem("skip_consent cannot be set during dynamic client registration")
	}
	if m.Name != nil && strings.TrimSpace(*m.Name) == "" {
		return m, metadataProblem("client_name cannot be empty")
	}
	if _, ok := body["token_endpoint_auth_method"]; ok {
		m.TokenEndpointAuthMethod = strings.TrimSpace(m.TokenEndpointAuthMethod)
		if m.TokenEndpointAuthMethod == "" {
			return m, metadataProblem("token_endpoint_auth_method must not be empty")
		}
	}
	if _, ok := body["application_type"]; ok && m.ApplicationType != "native" && m.ApplicationType != "web" {
		return m, metadataProblem("application_type must be web or native")
	}
	if _, ok := body["subject_type"]; ok && m.SubjectType != "public" && m.SubjectType != "pairwise" {
		return m, metadataProblem("subject_type must be public or pairwise")
	}
	for _, field := range []struct {
		name string
		list []string
	}{{"redirect_uris", m.RedirectURIs}, {"post_logout_redirect_uris", m.PostLogoutRedirectURIs}, {"contacts", m.Contacts}, {"grant_types", m.GrantTypes}} {
		if field.list != nil && len(field.list) == 0 {
			return m, fieldProblem(field.name, field.name+" must contain at least one value")
		}
		for i, item := range field.list {
			switch field.name {
			case "grant_types":
				field.list[i] = strings.TrimSpace(item)
			case "redirect_uris", "post_logout_redirect_uris":
				if _, err := redirectURL(item); err != nil {
					return m, err
				}
			}
			if field.list[i] == "" {
				return m, fieldProblem(field.name, field.name+" must contain nonempty values")
			}
		}
	}
	for _, response := range m.ResponseTypes {
		if response != "code" {
			return m, metadataProblem("unsupported response_type " + response)
		}
	}
	for _, resource := range m.Resources {
		if !ValidResourceIdentifier(resource) {
			return m, registrationProblem(400, "invalid_target", "invalid resource identifier")
		}
	}
	if m.JWKS != nil {
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(m.JWKS, &set); err != nil || len(set.Keys) == 0 {
			return m, metadataProblem("jwks must be an RFC 7517 JWK Set object with a non-empty keys array")
		}
		// Keep the exact JSON numbers and custom public members of each key.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(m.JWKS, &fields); err != nil || fields["keys"] == nil {
			return m, metadataProblem("jwks must have a keys member")
		}
		m.JWKS, _ = json.Marshal(map[string]json.RawMessage{"keys": fields["keys"]})
	}
	return m, nil
}

func fieldProblem(key, msg string) error {
	switch key {
	case "redirect_uris", "post_logout_redirect_uris":
		return registrationProblem(400, "invalid_redirect_uri", msg)
	case "resources":
		return registrationProblem(400, "invalid_target", msg)
	case "software_statement":
		return registrationProblem(400, "invalid_software_statement", msg)
	default:
		return metadataProblem(msg)
	}
}

func (o Options) prepareMetadata(host *auth.Auth, m *RegistrationMetadata, authorized bool) error {
	r := o.Registration
	if m.GrantTypes == nil {
		m.GrantTypes = []string{"authorization_code"}
	} else {
		requested := m.GrantTypes
		m.GrantTypes = slices.DeleteFunc(slices.Clone(requested), func(v string) bool { return !slices.Contains(o.GrantTypes, v) })
		if len(m.GrantTypes) == 0 {
			return metadataProblem("no mutually supported grant_type among " + strings.Join(requested, ", "))
		}
		if slices.Contains(requested, "authorization_code") && !slices.Contains(m.GrantTypes, "authorization_code") {
			m.ResponseTypes = nil
		}
	}
	if !authorized && slices.Contains(m.GrantTypes, "client_credentials") {
		return metadataProblem("client_credentials grant requires authenticated registration")
	}
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = "client_secret_basic"
	}
	switch m.TokenEndpointAuthMethod {
	case "none", "client_secret_basic", "client_secret_post", "private_key_jwt":
	default:
		return metadataProblem("unsupported token_endpoint_auth_method " + m.TokenEndpointAuthMethod)
	}
	code := slices.Contains(m.GrantTypes, "authorization_code")
	if code && len(m.RedirectURIs) == 0 {
		return fieldProblem("redirect_uris", "Redirect URIs are required for authorization_code and implicit grant types")
	}
	if m.RedirectURIs == nil {
		m.RedirectURIs = []string{}
	}
	if m.ApplicationType == "" {
		m.ApplicationType = r.DefaultApplicationType
	}
	if m.ApplicationType == "infer" {
		m.ApplicationType = "web"
		for _, raw := range m.RedirectURIs {
			u, err := redirectURL(raw)
			if err != nil {
				return err
			}
			if u.Scheme != "https" && (u.Scheme != "http" || exactLoopback(u.Hostname())) {
				m.ApplicationType = "native"
				break
			}
		}
	}
	for _, raw := range m.RedirectURIs {
		if err := r.validateRedirect(raw, m.ApplicationType); err != nil {
			return err
		}
	}
	for _, raw := range m.PostLogoutRedirectURIs {
		u, err := redirectURL(raw)
		if err != nil {
			return err
		}
		if u.Scheme == "http" && !loopback(u.Hostname()) && !r.allowsHTTP(u) {
			return fieldProblem("post_logout_redirect_uris", "Redirect URI must use HTTPS (HTTP allowed only for loopback hosts): "+raw)
		}
	}
	if code && !slices.Contains(o.GrantTypes, "authorization_code") {
		return metadataProblem("unsupported grant_type authorization_code")
	}
	if m.ResponseTypes == nil && code {
		m.ResponseTypes = []string{"code"}
	}
	if code && !slices.Contains(m.ResponseTypes, "code") {
		return metadataProblem("When 'authorization_code' grant type is used, 'code' response type must be included")
	}
	if !code && slices.Contains(m.ResponseTypes, "code") {
		return metadataProblem("When 'code' response type is used, 'authorization_code' grant type must be included")
	}
	if m.SubjectType == "pairwise" {
		if o.PairwiseSecret == "" {
			return metadataProblem("pairwise subject_type requires server pairwiseSecret configuration")
		}
		var first string
		for i, raw := range m.RedirectURIs {
			u, _ := redirectURL(raw)
			if u.Host != "" && u.Scheme != "http" && u.Scheme != "https" {
				return metadataProblem("pairwise clients cannot use custom-scheme redirect URIs that include a host")
			}
			h, err := pairwiseSector(u.Hostname(), u.Port(), u.Scheme)
			if err != nil {
				return metadataProblem("invalid pairwise redirect URI host")
			}
			if i > 0 && h != first {
				return metadataProblem("pairwise clients with redirect_uris on different hosts require a sector_identifier_uri, which is not yet supported. All redirect_uris must share the same host.")
			}
			first = h
		}
	}
	for _, scope := range strings.Split(m.Scope, " ") {
		if scope != "" && !slices.Contains(r.AllowedScopes, scope) {
			return registrationProblem(400, "invalid_scope", "cannot request scope "+scope)
		}
	}
	if m.JWKS != nil && m.JWKSURI != nil {
		return metadataProblem("jwks and jwks_uri are mutually exclusive")
	}
	if m.JWKS != nil {
		if err := ValidatePublicClientJWKS(m.JWKS); err != nil {
			return err
		}
	}
	if m.JWKSURI != nil {
		if err := validateServerURI("jwks_uri", *m.JWKSURI, host); err != nil {
			return err
		}
	}
	if m.TokenEndpointAuthMethod == "private_key_jwt" && m.JWKS == nil && m.JWKSURI == nil {
		return metadataProblem("private_key_jwt requires either jwks or jwks_uri")
	}
	if m.BackchannelLogoutURI != nil {
		if err := validateServerURI("backchannel_logout_uri", *m.BackchannelLogoutURI, host); err != nil {
			return err
		}
	}
	for _, id := range m.Resources {
		if !slices.Contains(r.AllowedResources, id) {
			return registrationProblem(400, "invalid_target", "requested resource "+id+" is not allowed for client registration")
		}
	}
	m.Resources = distinct(slices.Concat(r.DefaultResources, m.Resources))
	m.Scope = strings.Join(r.AllowedScopes, " ")
	return nil
}

var reverseDomain = regexp.MustCompile(`(?i)^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

func redirectURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || strings.ContainsAny(raw, "\\ \t\r\n") || ((u.Scheme == "http" || u.Scheme == "https") && u.Hostname() == "") {
		return nil, fieldProblem("redirect_uris", "redirect URI must be an absolute URI: "+raw)
	}
	if u.User != nil || strings.Contains(raw, "#") {
		return nil, fieldProblem("redirect_uris", "redirect URI must not include credentials or a fragment: "+raw)
	}
	if p := u.Port(); p != "" {
		if _, err := strconv.ParseUint(p, 10, 16); err != nil {
			return nil, fieldProblem("redirect_uris", "invalid redirect URI port")
		}
	}
	switch u.Scheme {
	case "data", "javascript", "vbscript":
		return nil, fieldProblem("redirect_uris", "URL cannot use javascript:, data:, or vbscript: scheme")
	}
	return u, nil
}

func exactLoopback(name string) bool {
	return strings.EqualFold(name, "localhost") || name == "127.0.0.1" || name == "::1"
}
func loopback(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Unmap().IsLoopback()
	}
	return name == "localhost" || strings.HasSuffix(name, ".localhost")
}
func (r RegistrationOptions) allowsHTTP(u *url.URL) bool {
	return r.AllowHTTPRedirect != nil && r.AllowHTTPRedirect(u)
}

func (r RegistrationOptions) validateRedirect(raw, app string) error {
	u, err := redirectURL(raw)
	if err != nil {
		return err
	}
	originalName := strings.ToLower(u.Hostname())
	name := originalName
	if name != "" {
		if addr, err := netip.ParseAddr(name); err == nil {
			if addr.Zone() != "" {
				return fieldProblem("redirect_uris", "redirect URI must not have an IPv6 zone")
			}
		} else {
			ascii, err := idna.Lookup.ToASCII(name)
			if err != nil {
				return fieldProblem("redirect_uris", "invalid redirect URI host")
			}
			name = strings.ToLower(ascii)
		}
	}
	if strings.TrimRight(name, ".") == "localhost" && name != "localhost" {
		return fieldProblem("redirect_uris", "redirect URI localhost must not include trailing dots: "+raw)
	}
	if u.Host != "" && ambiguousHost(name) {
		return fieldProblem("redirect_uris", "redirect URI must have an unambiguous host: "+raw)
	}
	local := exactLoopback(name)
	if ip, err := netip.ParseAddr(name); err == nil {
		local = ip.Unmap().IsLoopback()
	}
	if app == "web" {
		if (u.Scheme == "https" && !local) || (u.Scheme == "http" && r.allowsHTTP(u)) {
			return nil
		}
		return fieldProblem("redirect_uris", "web clients require https redirect URIs on non-loopback hosts: "+raw)
	}
	switch u.Scheme {
	case "https":
		if local {
			return fieldProblem("redirect_uris", "native clients must not use https loopback redirect URIs: "+raw)
		}
		return nil
	case "http":
		if exactLoopback(originalName) || (!loopback(name) && r.allowsHTTP(u)) {
			return nil
		}
		return fieldProblem("redirect_uris", "native clients may use http only on the exact loopback hosts localhost, 127.0.0.1, or [::1]: "+raw)
	case "ws", "wss", "file", "ftp", "mailto", "blob", "about", "view-source":
	default:
		if u.Hostname() != "" && strings.HasPrefix(u.EscapedPath(), "/") {
			return nil
		}
		if u.Host == "" && strings.HasPrefix(raw[len(u.Scheme)+1:], "/") && !strings.HasPrefix(raw[len(u.Scheme)+1:], "//") && reverseDomain.MatchString(u.Scheme) {
			return nil
		}
	}
	return fieldProblem("redirect_uris", "invalid native private-use redirect URI: "+raw)
}

// Browsers also interpret noncanonical numeric hosts as IP addresses. Accept
// IP literals only in the unambiguous spelling parsed by netip.
func ambiguousHost(name string) bool {
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	tail := parts[len(parts)-1]
	if tail == "" {
		return true
	}
	_, err := strconv.ParseUint(tail, 10, 64)
	return err == nil || strings.HasPrefix(strings.ToLower(tail), "0x")
}

func validateServerURI(field, raw string, host *auth.Auth) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || strings.ContainsAny(raw, "\\ \t\r\n") {
		return metadataProblem(field + " must be an absolute URL")
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return metadataProblem(field + " must have a valid port")
		}
	}
	if u.Scheme != "https" {
		return metadataProblem(field + " must use HTTPS")
	}
	if u.User != nil {
		return metadataProblem(field + " must not contain credentials")
	}
	if strings.Contains(raw, "#") {
		return metadataProblem(field + " must not include a fragment component")
	}
	name := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip, err := netip.ParseAddr(name); err == nil {
		if !publicnet.Address(ip) {
			return metadataProblem(field + " must not point to a private or reserved address")
		}
	} else {
		ascii, err := idna.Lookup.ToASCII(name)
		if err != nil || !strings.Contains(ascii, ".") || ambiguousHost(ascii) || loopback(ascii) || ascii == "metadata.goog" || strings.HasSuffix(ascii, ".internal") || strings.HasSuffix(ascii, ".local") {
			return metadataProblem(field + " must not point to a private or reserved address")
		}
	}
	if field == "jwks_uri" && !host.ExplicitlyTrustedOrigin(raw) {
		return metadataProblem("jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin")
	}
	return nil
}
