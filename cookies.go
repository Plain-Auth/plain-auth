package plainauth

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Plain-Org/plain-auth/internal/configenv"
	"github.com/Plain-Org/plain-auth/internal/popupwire"
)

// CrossSubDomainCookiesOptions selects the host and descendants that receive
// shared cookies. Use a parent domain to share cookies with sibling hosts.
type CrossSubDomainCookiesOptions struct {
	Domain string
}

func secureCookies(opts *Options) bool {
	if opts.UseSecureCookies != nil {
		return *opts.UseSecureCookies
	}
	return strings.HasPrefix(opts.BaseURL, "https://")
}

func prepareCookieScope(opts *Options, dynamic *dynamicBase) error {
	secure := secureCookies(opts)
	opts.UseSecureCookies = &secure
	prefix := strings.ToLower(opts.CookiePrefix)
	hostOnly := strings.HasPrefix(prefix, "__host-")
	if !secure && (hostOnly || strings.HasPrefix(prefix, "__secure-")) {
		return errors.New("auth: a reserved cookie prefix requires Secure cookies")
	}
	base, err := url.Parse(opts.BaseURL)
	if err != nil {
		return err
	}
	// Domain overrides get the same base-host and public-suffix checks as
	// shared cookies. The caller's map stays untouched. With DynamicBaseURL a
	// domain must be explicit and cover every allowed host.
	hosts := []string{base.Hostname()}
	if dynamic != nil {
		hosts = dynamic.cookieHosts
	}
	cookieDomain := func(requested string) (string, error) {
		if dynamic != nil && requested == "" {
			return "", errors.New("auth: a shared cookie domain must be set explicitly with DynamicBaseURL")
		}
		domain := requested
		for _, host := range hosts {
			if domain, err = configenv.CookieDomain(host, requested); err != nil {
				return "", err
			}
		}
		return domain, nil
	}
	if d := opts.DefaultCookieAttributes.Domain; d != "" {
		if opts.DefaultCookieAttributes.Domain, err = cookieDomain(d); err != nil {
			return err
		}
	}
	if len(opts.Cookies) > 0 {
		cookies := make(map[string]CookieOptions, len(opts.Cookies))
		for name, c := range opts.Cookies {
			if c.Attributes.Domain != "" {
				if c.Attributes.Domain, err = cookieDomain(c.Attributes.Domain); err != nil {
					return fmt.Errorf("auth: cookie %q: %w", name, err)
				}
			}
			cookies[name] = c
		}
		opts.Cookies = cookies
	}
	if opts.CrossSubDomainCookies == nil {
		return nil
	}
	if hostOnly {
		return errors.New("auth: a __Host- cookie prefix requires host-only cookies")
	}
	domain, err := cookieDomain(opts.CrossSubDomainCookies.Domain)
	if err != nil {
		return err
	}
	opts.CrossSubDomainCookies = &CrossSubDomainCookiesOptions{Domain: domain}
	return nil
}

// CookieOptions overrides one cookie's name and attributes.
type CookieOptions struct {
	// Name replaces the prefixed name, such as "authn.session_token". With
	// Secure cookies the name still gets the __Secure- prefix.
	Name       string
	Attributes CookieAttributes
}

// CookieAttributes overrides cookie attributes. Zero fields keep the default:
// Path=/, HttpOnly, SameSite=Lax, Secure for an HTTPS base URL and the shared
// domain with cross-subdomain cookies. A Path must cover the auth base path,
// and a Domain gets the same checks as CrossSubDomainCookies.
type CookieAttributes struct {
	Domain, Path     string
	SameSite         http.SameSite
	Secure, HttpOnly *bool
	Partitioned      bool
}

func (attrs CookieAttributes) apply(c *http.Cookie) {
	if attrs.Domain != "" {
		c.Domain = attrs.Domain
	}
	if attrs.Path != "" {
		c.Path = attrs.Path
	}
	if attrs.SameSite != 0 {
		c.SameSite = attrs.SameSite
	}
	if attrs.Secure != nil {
		c.Secure = *attrs.Secure
	}
	if attrs.HttpOnly != nil {
		c.HttpOnly = *attrs.HttpOnly
	}
	if attrs.Partitioned {
		c.Partitioned = true
	}
}

func (a *Auth) browserCookie(name, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{Name: a.prefixedCookieName(name), Value: value, Path: "/", MaxAge: maxAge,
		Secure: secureCookies(&a.opts), HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if a.opts.CrossSubDomainCookies != nil {
		c.Domain = a.opts.CrossSubDomainCookies.Domain
	}
	a.opts.DefaultCookieAttributes.apply(c)
	a.opts.Cookies[name].Attributes.apply(c)
	return c
}

// checkCookieOptions refuses cookie overrides that a browser would reject or
// that would hide a cookie from the auth endpoints. It checks each cookie as
// it is issued.
func (a *Auth) checkCookieOptions() error {
	for _, name := range []string{"admin_session", "last_used_login_method"} {
		if a.opts.Cookies[name].Attributes != (CookieAttributes{}) {
			return fmt.Errorf("auth: cookie %q takes the session_token attributes; override those instead", name)
		}
	}
	preference := a.sessionCookie("value", false)
	preference.Name, preference.Path, preference.HttpOnly = a.prefixedCookieName("last_used_login_method"), "/", false
	issued := map[string]*http.Cookie{"admin_session": a.adminSessionCookie("value", 0), "last_used_login_method": preference, "one_tap": a.oneTapCookie("value", 0)}
	names := []string{"session_token", "session_data", "dont_remember", "two_factor", "trust_device", "passkey_challenge",
		"oauth_state", popupwire.MarkerCookie, "guest_continuation", "sso_state", "saml_state", "saml_logout", "account_data"}
	for _, name := range append(names, slices.Collect(maps.Keys(a.opts.Cookies))...) {
		if issued[name] == nil {
			issued[name] = a.browserCookie(name, "value", 0)
		}
	}
	mount := cmp.Or(a.opts.BasePath, "/")
	owners := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(issued)) {
		c := issued[name]
		lower := strings.ToLower(c.Name)
		switch {
		case c.Valid() != nil:
			return fmt.Errorf("auth: cookie %q is invalid: %w", name, c.Valid())
		case c.SameSite == http.SameSiteNoneMode && !c.Secure:
			return fmt.Errorf("auth: cookie %q needs Secure with SameSite=None", name)
		case strings.HasPrefix(lower, "__host-") && (c.Domain != "" || c.Path != "/" || !c.Secure):
			return fmt.Errorf("auth: cookie %q with the __Host- prefix needs Secure, Path=/ and no Domain", name)
		case strings.HasPrefix(lower, "__secure-") && !c.Secure:
			return fmt.Errorf("auth: cookie %q with the __Secure- prefix needs Secure", name)
		case !pathCovers(c.Path, mount):
			return fmt.Errorf("auth: cookie %q needs a Path that covers %s", name, mount)
		case owners[c.Name] != "":
			return fmt.Errorf("auth: cookies %q and %q share the name %q", owners[c.Name], name, c.Name)
		}
		owners[c.Name] = name
	}
	return nil
}

// pathCovers reports whether a browser sends a cookie with this Path to
// requests for path (RFC 6265 path matching).
func pathCovers(cookiePath, path string) bool {
	if !strings.HasPrefix(path, cookiePath) {
		return false
	}
	return len(path) == len(cookiePath) || strings.HasSuffix(cookiePath, "/") || path[len(cookiePath)] == '/'
}

// expireOtherScopes expires the browser's older copies of c, such as the
// host-only cookie left when a deployment begins sharing this credential or
// the Path=/ cookie left by a new Path. It acts only when the request carries
// a cookie of that name, since a request cookie does not carry its scope.
func expireOtherScopes(h http.Header, r *http.Request, c *http.Cookie) {
	if r == nil {
		return
	}
	if _, err := r.Cookie(c.Name); err != nil {
		return
	}
	for _, old := range otherScopes(c) {
		h.Add("Set-Cookie", old.String())
	}
}

// otherScopes returns expiries for the copies of c that the default scope
// could have left behind: host-only, at Path=/ or unpartitioned. Browsers
// keep those apart from c, so expiring c alone would not remove them.
func otherScopes(c *http.Cookie) []*http.Cookie {
	domains, paths, partitions := []string{c.Domain}, []string{c.Path}, []bool{c.Partitioned}
	if c.Domain != "" {
		domains = append(domains, "")
	}
	if c.Path != "/" {
		paths = append(paths, "/")
	}
	if c.Partitioned {
		partitions = append(partitions, false)
	}
	var out []*http.Cookie
	for _, domain := range domains {
		for _, path := range paths {
			for _, partitioned := range partitions {
				if domain == c.Domain && path == c.Path && partitioned == c.Partitioned {
					continue
				}
				old := *c
				old.Domain, old.Path, old.Partitioned, old.Value, old.MaxAge = domain, path, partitioned, "", -1
				out = append(out, &old)
			}
		}
	}
	return out
}

func (a *Auth) prefixedCookieName(name string) string {
	if custom := a.opts.Cookies[name].Name; custom != "" {
		lower := strings.ToLower(custom)
		if secureCookies(&a.opts) && !strings.HasPrefix(lower, "__secure-") && !strings.HasPrefix(lower, "__host-") {
			return "__Secure-" + custom
		}
		return custom
	}
	namespace := a.opts.CookiePrefix
	if namespace == "" {
		namespace = "authn"
	}
	prefix := strings.ToLower(namespace)
	if secureCookies(&a.opts) && !strings.HasPrefix(prefix, "__secure-") && !strings.HasPrefix(prefix, "__host-") {
		namespace = "__Secure-" + namespace
	}
	return namespace + "." + name
}

func (a *Auth) cookieName() string { return a.prefixedCookieName("session_token") }

func (a *Auth) sessionCookie(token string, persistent bool) *http.Cookie {
	c := a.browserCookie("session_token", url.QueryEscape(token+"."+a.cookieSignature(token)), 0)
	if persistent {
		c.MaxAge = int(a.opts.SessionTTL / time.Second)
	}
	return c
}

// adminSessionCookie carries an impersonating admin's return session. Like
// the multi-session cookies, it takes the session_token attributes.
func (a *Auth) adminSessionCookie(payload string, maxAge int) *http.Cookie {
	c := a.sessionCookie(payload, false)
	c.Name, c.MaxAge = a.prefixedCookieName("admin_session"), maxAge
	if maxAge < 0 {
		c.Value = ""
	}
	return c
}

func (a *Auth) clearSessionCookie() *http.Cookie {
	c := a.sessionCookie("", false)
	c.Value = ""
	c.MaxAge = -1
	return c
}

func (a *Auth) cookieToken(headers http.Header) string {
	for _, p := range a.opts.Plugins {
		if p.SessionToken != nil {
			if token := p.SessionToken(a, headers); token != "" {
				return token
			}
		}
	}
	r := http.Request{Header: headers}
	c, err := r.Cookie(a.cookieName())
	if err != nil {
		return ""
	}
	return a.VerifySignedSessionToken(c.Value)
}

// VerifySignedSessionToken verifies a signed wire credential. Session lookup
// still checks revocation and expiry in the store.
func (a *Auth) VerifySignedSessionToken(signed string) string {
	value, err := url.PathUnescape(signed)
	if err != nil {
		return ""
	}
	separator := strings.LastIndexByte(value, '.')
	if separator <= 0 {
		return ""
	}
	token, sig := value[:separator], value[separator+1:]
	if hmac.Equal([]byte(sig), []byte(a.cookieSignature(token))) {
		return token
	}
	for i := 1; i < len(a.opts.Secrets); i++ {
		if hmac.Equal([]byte(sig), []byte(signCookieValue(token, a.opts.Secrets[i].Value))) {
			return token
		}
	}
	return ""
}

// Cookie signatures cover the raw UTF-8 token and use standard padded base64.
func (a *Auth) cookieSignature(token string) string {
	return signCookieValue(token, a.opts.Secret)
}
func signCookieValue(token, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Cookie returns a cookie named with this instance's cookie prefix and its
// cookie attributes: Path=/, HttpOnly, SameSite=Lax, Secure for an HTTPS base
// URL and the shared domain when cross-subdomain cookies are enabled. The
// session cookie is Cookie("session_token", ...).
func (a *Auth) Cookie(name, value string, maxAge int) *http.Cookie {
	return a.browserCookie(name, value, maxAge)
}

// SignedCookie returns Cookie(name, value, maxAge) with value signed by the
// instance secret, in the same format as the session cookie.
func (a *Auth) SignedCookie(name, value string, maxAge int) *http.Cookie {
	return a.browserCookie(name, url.QueryEscape(value+"."+a.cookieSignature(value)), maxAge)
}

// SignedCookieValue returns the value of the request's SignedCookie of that
// name. It reports false when the cookie is missing or its signature does not
// match the current or a previous secret.
func (a *Auth) SignedCookieValue(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(a.prefixedCookieName(name))
	if err != nil {
		return "", false
	}
	value := a.VerifySignedSessionToken(c.Value)
	return value, value != ""
}

// issuedSessionToken returns the session token this response's last session
// cookie carries, or "" when it issues none or expires the session cookie.
func (a *Auth) issuedSessionToken(h http.Header) string {
	var issued *http.Cookie
	for _, line := range h.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(line); err == nil && c.Name == a.cookieName() {
			issued = c
		}
	}
	if issued == nil || issued.Value == "" || issued.MaxAge < 0 {
		return ""
	}
	return a.VerifySignedSessionToken(issued.Value)
}

// SessionCookie returns the HTTP-only cookie for a token obtained through
// SignUpEmail or SignInEmail. The caller owns the response writer.
func (a *Auth) SessionCookie(token string, persistent bool) *http.Cookie {
	return a.sessionCookie(token, persistent)
}

func (a *Auth) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, persistent bool) error {
	return a.addSessionCookieHeaders(w.Header(), r, token, persistent)
}
func (a *Auth) addSessionCookieHeaders(headers http.Header, r *http.Request, token string, persistent bool) error {
	if err := a.finishAnonymous(r, token); err != nil {
		return err
	}
	if err := a.writeSessionCookieHeaders(headers, r, token, persistent); err != nil {
		return err
	}
	if a.deviceSessions != nil {
		a.rememberDeviceSession(headers, r, token, persistent)
	}
	return nil
}

func (a *Auth) writeSessionCookieHeaders(headers http.Header, r *http.Request, token string, persistent bool) error {
	return a.publishSessionCookie(headers, r, a.sessionCookie(token, persistent))
}

func (a *Auth) publishSessionCookie(headers http.Header, r *http.Request, cookie *http.Cookie) error {
	var snapshot http.Header
	if a.opts.SessionCookieCache != nil {
		snapshot = make(http.Header)
		if err := a.cacheIssuedSession(snapshot, r, cookie); err != nil {
			return sessionVersionIssueError(err)
		}
	}
	a.emitSessionCookieHeaders(headers, r, cookie)
	for _, value := range snapshot.Values("Set-Cookie") {
		headers.Add("Set-Cookie", value)
	}
	return nil
}

func (a *Auth) emitSessionCookieHeaders(headers http.Header, r *http.Request, c *http.Cookie) {
	expireOtherScopes(headers, r, c)
	headers.Add("Set-Cookie", c.String())
	event := SessionCookieEvent{Auth: a, Cookie: *c, Route: strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(a.opts.BasePath, "/")), Request: r, Header: headers}
	for _, p := range a.opts.Plugins {
		if p.OnSessionCookie != nil {
			p.OnSessionCookie(event)
		}
	}
	// Cookie publication includes authentication, renewal, and returning an
	// existing session to another browser. A deletion does not publish a login.
	if a.oneTimeToken != nil && a.oneTimeToken.SetHeaderOnNewSession && c.MaxAge >= 0 {
		if token := a.VerifySignedSessionToken(c.Value); token != "" {
			a.addOneTimeTokenHeader(headers, r, token)
		}
	}
}

func (a *Auth) writeRememberPreference(headers http.Header, r *http.Request, persistent bool) {
	marker := a.SignedCookie("dont_remember", "true", 0)
	expireOtherScopes(headers, r, marker)
	if !persistent {
		headers.Add("Set-Cookie", marker.String())
	} else if _, err := r.Cookie(marker.Name); err == nil {
		marker.Value, marker.MaxAge = "", -1
		headers.Add("Set-Cookie", marker.String())
	}
}

// expireStoredSessionData removes the cache cookies belonging to this auth
// instance. Credential expiration also clears the base name when the browser omitted it.
func (a *Auth) expireStoredSessionData(h http.Header, r *http.Request, expireBase bool) {
	a.reconcileSessionDataCookies(h, r, expireBase, nil)
}

func (a *Auth) reconcileSessionDataCookies(h http.Header, r *http.Request, expireBase bool, replacements map[string]bool) {
	expired := a.browserCookie("session_data", "", -1)
	prefix := expired.Name + "."
	var names []string
	var seen map[string]bool
	hasData := false
	for _, c := range r.Cookies() {
		if c.Name != expired.Name {
			suffix, ok := strings.CutPrefix(c.Name, prefix)
			if !ok {
				continue
			}
			// Chunk indexes use the canonical decimal spelling of a JavaScript safe integer.
			index, err := strconv.ParseUint(suffix, 10, 53)
			if err != nil || strconv.FormatUint(index, 10) != suffix {
				continue
			}
		}
		hasData = hasData || c.Value != ""
		if !seen[c.Name] {
			if seen == nil {
				seen = make(map[string]bool)
			}
			seen[c.Name] = true
			names = append(names, c.Name)
		}
	}
	if !expireBase && !hasData {
		return
	}
	if expireBase && !seen[expired.Name] {
		h.Add("Set-Cookie", expired.String())
	}
	for _, name := range names {
		expired.Name = name
		for _, old := range otherScopes(expired) {
			h.Add("Set-Cookie", old.String())
		}
		if !replacements[name] {
			h.Add("Set-Cookie", expired.String())
		}
	}
}
