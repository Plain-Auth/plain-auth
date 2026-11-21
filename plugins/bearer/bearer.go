// Package bearer adds session authentication through the Authorization header.
package bearer

import (
	"net/http"
	"strings"

	auth "github.com/Stonewrit/stonewrit-auth"
)

type Options struct{ RequireSignature bool }

// New accepts bearer session tokens and returns signed tokens in Set-Auth-Token.
func New(opts Options) auth.Plugin {
	return auth.Plugin{ID: "bearer",
		SessionToken: func(a *auth.Auth, h http.Header) string {
			scheme, token, ok := strings.Cut(h.Get("Authorization"), " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") {
				return ""
			}
			token = strings.TrimSpace(token)
			if strings.Contains(token, ".") {
				return a.VerifySignedSessionToken(token)
			}
			if opts.RequireSignature {
				return ""
			}
			return token
		},
		OnSessionCookie: func(e auth.SessionCookieEvent) {
			e.Header.Set("Set-Auth-Token", e.Cookie.Value)
			for _, line := range e.Header.Values("Access-Control-Expose-Headers") {
				for field := range strings.SplitSeq(line, ",") {
					if strings.EqualFold(strings.TrimSpace(field), "set-auth-token") {
						return
					}
				}
			}
			e.Header.Add("Access-Control-Expose-Headers", "set-auth-token")
		},
	}
}
