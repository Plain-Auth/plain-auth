package authn

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
	if strings.HasPrefix(a.opts.BaseURL, "https://") {
		namespace = "__Secure-" + namespace
	}
	return namespace + "." + name
}

func (a *Auth) cookieName() string { return a.prefixedCookieName("session_token") }

func (a *Auth) sessionCookie(token string, persistent bool) *http.Cookie {
	c := &http.Cookie{Name: a.cookieName(), Value: url.QueryEscape(token + "." + a.cookieSignature(token)), Path: "/", Secure: strings.HasPrefix(a.opts.BaseURL, "https://"), HttpOnly: true, SameSite: http.SameSiteLaxMode}
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

func (a *Auth) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, persistent bool) {
	a.addSessionCookieHeaders(w.Header(), r, token, persistent)
}
func (a *Auth) addSessionCookieHeaders(headers http.Header, r *http.Request, token string, persistent bool) {
	a.writeSessionCookieHeaders(headers, r, token, persistent)
	a.addOneTimeTokenHeader(headers, r, token)
}

func (a *Auth) writeSessionCookieHeaders(headers http.Header, r *http.Request, token string, persistent bool) {
	c := a.sessionCookie(token, persistent)
	headers.Add("Set-Cookie", c.String())
	event := SessionCookieEvent{Cookie: *c, Route: strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(a.opts.BasePath, "/")), Request: r, Header: headers}
	for _, p := range a.opts.Plugins {
		if p.OnSessionCookie != nil {
			p.OnSessionCookie(event)
		}
	}
}
