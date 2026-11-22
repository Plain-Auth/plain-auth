package plainauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (a *Auth) prefixedCookieName(name string) string {
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
	expireHostCopy(headers, r, c)
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
	marker := a.sessionCookie("true", false)
	marker.Name = strings.TrimSuffix(marker.Name, "session_token") + "dont_remember"
	expireHostCopy(headers, r, marker)
	if !persistent {
		headers.Add("Set-Cookie", marker.String())
	} else if _, err := r.Cookie(marker.Name); err == nil {
		marker.Value, marker.MaxAge = "", -1
		headers.Add("Set-Cookie", marker.String())
	}
}
