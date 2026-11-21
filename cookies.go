package betterauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (a *Auth) cookieName() string {
	if strings.HasPrefix(a.opts.BaseURL, "https://") {
		return "__Secure-better-auth.session_token"
	}
	return "better-auth.session_token"
}

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
	if !hmac.Equal([]byte(sig), []byte(a.cookieSignature(token))) {
		return ""
	}
	return token
}

// Cookie signatures cover the raw UTF-8 token and use standard padded base64.
func (a *Auth) cookieSignature(token string) string {
	mac := hmac.New(sha256.New, []byte(a.opts.Secret))
	mac.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SessionCookie returns the HTTP-only cookie for a token obtained through
// SignUpEmail or SignInEmail. The caller owns the response writer.
func (a *Auth) SessionCookie(token string, persistent bool) *http.Cookie {
	return a.sessionCookie(token, persistent)
}

func (a *Auth) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, persistent bool) {
	c := a.sessionCookie(token, persistent)
	http.SetCookie(w, c)
	event := SessionCookieEvent{Cookie: *c, Route: strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(a.opts.BasePath, "/")), Request: r, Header: w.Header()}
	for _, p := range a.opts.Plugins {
		if p.OnSessionCookie != nil {
			p.OnSessionCookie(event)
		}
	}
}
