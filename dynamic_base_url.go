package plainauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/configenv"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

// dynamicBase is the prepared DynamicBaseURL configuration.
type dynamicBase struct {
	hosts      []httporigin.Rule
	protocol   string
	trustProxy bool
	// https is true unless every host is served over HTTP.
	https bool
	// cookieHosts are the hostnames a shared cookie domain must cover.
	cookieHosts []string
}

// errNoRequestOrigin is returned where a link needs the request's origin but
// the call has neither a request nor a Fallback.
var errNoRequestOrigin = errors.New("auth: DynamicBaseURL needs the request to build this URL; pass a context from Auth.RequestContext or set DynamicBaseURL.Fallback")

// prepareDynamicBaseURL validates DynamicBaseURL, sets BaseURL to the
// fallback origin (or "" without one) and adds the allowed hosts to the
// trusted origins.
func prepareDynamicBaseURL(opts *Options) (*dynamicBase, error) {
	d := opts.DynamicBaseURL
	if opts.BaseURL != "" {
		return nil, errors.New("auth: set BaseURL or DynamicBaseURL, not both")
	}
	if len(d.AllowedHosts) == 0 {
		return nil, errors.New(`auth: DynamicBaseURL.AllowedHosts cannot be empty. Provide at least one allowed host pattern (e.g., "myapp.com", "*.vercel.app")`)
	}
	if !slices.Contains([]string{"", "auto", "http", "https"}, d.Protocol) {
		return nil, errors.New(`auth: DynamicBaseURL.Protocol must be "", "auto", "http" or "https"`)
	}
	if d.TrustedProxyHeaders && len(opts.ClientIP.TrustedProxies) == 0 {
		return nil, errors.New("auth: DynamicBaseURL.TrustedProxyHeaders requires ClientIP.TrustedProxies")
	}
	hosts, err := httporigin.CompileHosts("DynamicBaseURL.AllowedHosts", d.AllowedHosts)
	if err != nil {
		return nil, err
	}
	prepared := &dynamicBase{hosts: hosts, protocol: d.Protocol, trustProxy: d.TrustedProxyHeaders}
	if d.Fallback != "" {
		if opts.BaseURL, opts.BasePath, err = configenv.ServerEndpoint(d.Fallback, opts.BasePath); err != nil {
			return nil, fmt.Errorf("authn: DynamicBaseURL.Fallback: %w", err)
		}
	} else if opts.BasePath, err = configenv.Mount(opts.BasePath); err != nil {
		return nil, fmt.Errorf("authn: BasePath: %w", err)
	}
	// Every allowed host is a trusted origin on the schemes it can serve.
	expanded := make([]string, 0, 2*len(d.AllowedHosts))
	allLoopback := true
	for _, raw := range d.AllowedHosts {
		host := httporigin.ASCIILower(raw)
		if strings.Contains(host, "://") {
			expanded = append(expanded, host)
			host = host[strings.Index(host, "://")+3:]
		} else {
			if d.Protocol != "http" {
				expanded = append(expanded, "https://"+host)
			}
			if d.Protocol == "http" || d.Protocol == "auto" || loopbackHost(host) {
				expanded = append(expanded, "http://"+host)
			}
		}
		allLoopback = allLoopback && loopbackHost(host)
		prepared.cookieHosts = append(prepared.cookieHosts, cookieBaseHost(host))
	}
	opts.TrustedOrigins = append(expanded, opts.TrustedOrigins...)
	if opts.BaseURL != "" {
		fallback, _ := url.Parse(opts.BaseURL)
		allLoopback = allLoopback && loopbackHost(fallback.Host)
		prepared.cookieHosts = append(prepared.cookieHosts, fallback.Hostname())
	}
	prepared.https = d.Protocol == "https" || (d.Protocol != "http" && !allLoopback)
	if opts.UseSecureCookies == nil {
		secure := prepared.https
		opts.UseSecureCookies = &secure
	}
	return prepared, nil
}

// checkDynamicWithoutFallback refuses features that publish one fixed URL
// when DynamicBaseURL has no Fallback to supply it.
func (a *Auth) checkDynamicWithoutFallback() error {
	if a.dynamic == nil || a.opts.BaseURL != "" {
		return nil
	}
	if a.serviceJWT != nil && (a.serviceJWT.Issuer == "" || a.serviceJWT.Audience == "") {
		return errors.New("auth: the JWT plugin needs Issuer and Audience, or DynamicBaseURL.Fallback")
	}
	for _, p := range a.opts.Plugins {
		if p.WellKnown != nil {
			return fmt.Errorf("auth: plugin %q publishes discovery documents and needs DynamicBaseURL.Fallback", p.ID)
		}
	}
	return nil
}

// cookieBaseHost returns the hostname every match of a host pattern ends
// with, so a shared cookie domain can be checked against it.
func cookieBaseHost(pattern string) string {
	host := pattern
	if h, _, err := net.SplitHostPort(pattern); err == nil {
		host = h
	}
	i := strings.LastIndexAny(host, "*?")
	if i < 0 {
		return host
	}
	rest := host[i+1:]
	if !strings.HasPrefix(rest, ".") {
		// The wildcard shares a label with the text after it.
		_, rest, _ = strings.Cut(rest, ".")
		return rest
	}
	return rest[1:]
}

// loopbackHost reports whether a host with an optional port is localhost or
// a loopback address.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().IsLoopback()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// resolveOrigin fills scope with the origin a request reached in
// DynamicBaseURL mode and its public origin: that one when its host is
// allowed, otherwise the fallback.
func (a *Auth) resolveOrigin(r *http.Request, scope *requestScope) error {
	d := a.dynamic
	trusted := false
	if d.trustProxy {
		if peer, err := netip.ParseAddr(remoteIP(r.RemoteAddr)); err == nil {
			trusted = a.opts.ClientIP.trusted(peer)
		}
	}
	host := r.Host
	if values := r.Header.Values("X-Forwarded-Host"); trusted && len(values) == 1 && requestHost(values[0]) {
		host = values[0]
	}
	if requestHost(host) {
		scheme := d.protocol
		if values := r.Header.Values("X-Forwarded-Proto"); scheme != "http" && scheme != "https" {
			switch {
			case trusted && len(values) == 1 && (values[0] == "http" || values[0] == "https"):
				scheme = values[0]
			case r.TLS != nil:
				scheme = "https"
			case loopbackHost(host):
				scheme = "http"
			default:
				scheme = "https"
			}
		}
		scope.reached = httporigin.Canonical(&url.URL{Scheme: scheme, Host: host})
		for _, rule := range d.hosts {
			if rule.MatchesHost(scheme, host) {
				scope.origin, scope.matched = scope.reached, true
				return nil
			}
		}
	}
	if a.opts.BaseURL != "" {
		scope.origin = a.opts.BaseURL
		return nil
	}
	a.Logger().ErrorContext(r.Context(), "auth: request host is not in DynamicBaseURL.AllowedHosts", "host", host)
	return fmt.Errorf("auth: host %q is not in DynamicBaseURL.AllowedHosts; add it or set DynamicBaseURL.Fallback", host)
}

// reachedOrigin returns the origin a request reached in DynamicBaseURL mode,
// from its Host or a trusted X-Forwarded-Host, allowed or not, or "" for an
// invalid host. It reports false without DynamicBaseURL.
func (a *Auth) reachedOrigin(ctx context.Context) (string, bool) {
	s, _ := ctx.Value(requestScopeKey{a}).(*requestScope)
	if a.dynamic == nil || s == nil {
		return "", false
	}
	return s.reached, true
}

// requestHost reports whether a Host or X-Forwarded-Host value is a plain
// ASCII host with an optional port.
func requestHost(host string) bool {
	if host == "" || !httporigin.ASCIIOnly(host) || strings.ContainsAny(host, " \t,/\\@<>'\"") {
		return false
	}
	u, err := url.Parse("http://" + host)
	return err == nil && u.Host == host && u.User == nil && u.Path == "" && httporigin.Canonical(u) != ""
}

// httpsDeployment reports whether the public URL is HTTPS, which turns on
// rate limits and secure One Tap cookies by default.
func (a *Auth) httpsDeployment() bool {
	if a.dynamic != nil {
		return a.dynamic.https
	}
	return strings.HasPrefix(a.opts.BaseURL, "https://")
}

// origin returns the public origin for the request ctx belongs to: the
// resolved host in DynamicBaseURL mode, otherwise BaseURL.
func (a *Auth) origin(ctx context.Context) (string, error) {
	if s, ok := ctx.Value(requestScopeKey{a}).(*requestScope); ok && s.origin != "" {
		return s.origin, nil
	}
	if a.opts.BaseURL == "" {
		return "", errNoRequestOrigin
	}
	return a.opts.BaseURL, nil
}

// publicURL returns the auth handler's public URL for the request ctx
// belongs to.
func (a *Auth) publicURL(ctx context.Context) (string, error) {
	origin, err := a.origin(ctx)
	if err != nil {
		return "", err
	}
	return origin + strings.TrimRight(a.opts.BasePath, "/"), nil
}

// RequestContext returns a context for direct Go calls on behalf of r. It
// carries the origin DynamicBaseURL resolves for r and the origins
// TrustedOriginsForRequest adds, so links and callback checks match a
// request to the handler. Without either option it returns r's context.
func (a *Auth) RequestContext(r *http.Request) (context.Context, error) {
	scoped, err := a.withRequestScope(r)
	if err != nil {
		return nil, err
	}
	return scoped.Context(), nil
}
