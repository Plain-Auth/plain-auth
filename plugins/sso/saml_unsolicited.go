package sso

import (
	"context"
	"errors"
	"net/url"
	"path"
	"strings"
	"unicode"

	auth "github.com/Plain-Org/plain-auth"
)

// SAMLDirectory identifies the current registration for a host's IdP-initiated
// login policy. RecordID changes on re-registration. Reference identifies the
// current catalog configuration, including its trusted signing certificates.
type SAMLDirectory struct {
	RecordID, Reference, ProviderID, Issuer, EntryPoint, OrganizationID string
}

// SAMLDirectoryPolicy authorizes unsolicited browser sign-in for a reviewed
// directory. A nil policy disables the flow. Return an error to fail closed
// when the authority supplying the host's decision is unavailable.
type SAMLDirectoryPolicy func(context.Context, SAMLDirectory) (bool, error)

func (p SAMLDirectoryPolicy) authorize(ctx context.Context, d SAMLDirectory) (allowed bool, err error) {
	defer func() {
		if recover() != nil {
			allowed = false
			err = errors.New("SAML directory authorization failed")
		}
	}()
	return p(ctx, d)
}

func samlDirectory(p BrowserProvider) SAMLDirectory {
	a := p.SAML.authority()
	d := SAMLDirectory{RecordID: p.ID, Reference: p.Reference, ProviderID: p.ProviderID, Issuer: a.entity, EntryPoint: a.redirect}
	if p.OrganizationID != nil {
		d.OrganizationID = *p.OrganizationID
	}
	return d
}

func validSAMLLanding(raw string) bool {
	if raw == "" {
		return true
	}
	if strings.ContainsRune(raw, '\\') || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return false
	}
	if strings.HasPrefix(raw, "/") {
		escaped := strings.ToLower(u.EscapedPath())
		return !strings.HasPrefix(raw, "//") && !strings.Contains(escaped, "%2f") && !strings.Contains(escaped, "%5c")
	}
	return (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != ""
}

func samlLanding(c auth.EndpointContext, acs string, candidates ...string) string {
	endpoint, _ := url.Parse(acs)
	for _, candidate := range candidates {
		if candidate == "" || !validSAMLLanding(candidate) {
			continue
		}
		target, err := c.CallbackURL(candidate)
		if err != nil {
			continue
		}
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		if equalWebOrigin(u, endpoint) && path.Clean(u.Path) == path.Clean(endpoint.Path) {
			continue
		}
		return target
	}
	root, _ := c.CallbackURL("/")
	return root
}

func equalWebOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	// Reuse the SAML browser comparison, including default ports.
	return sameSAMLOrigin(a.Scheme+"://"+a.Host, b.String())
}

// A form with RelayState belongs to the browser-bound SP flow even when the
// state is invalid. Unsolicited login is considered only for a form without it.
func incomingSAMLFlow(c *auth.EndpointContext, form url.Values) (auth.OAuthFlow, bool, error) {
	if relay, ok := form["RelayState"]; ok {
		if len(relay) != 1 || relay[0] == "" {
			return auth.OAuthFlow{}, false, errSAMLResponse
		}
		f, err := c.ConsumeEnterprisePostFlow(relay[0])
		return f, false, err
	}
	prefix := strings.TrimRight(c.Auth.BasePath(), "/") + "/sso/saml2/sp/acs/"
	id, ok := strings.CutPrefix(c.Request.URL.EscapedPath(), prefix)
	if !ok || !MutableProviderID(id) {
		return auth.OAuthFlow{}, true, errSAMLResponse
	}
	endpoint, err := samlACS(*c, id)
	if err != nil {
		return auth.OAuthFlow{}, true, err
	}
	if !sameSAMLOrigin("https://"+c.Request.Host, endpoint) {
		return auth.OAuthFlow{}, true, errSAMLResponse
	}
	root, err := c.CallbackURL("/")
	return auth.OAuthFlow{Provider: id, RedirectURI: endpoint, CallbackURL: root}, true, err
}
