package authtest

import (
	"errors"
	"net/http"
)

// BrowserCookie is a session cookie in the JSON format accepted by browser
// automation tools. Expires is a Unix timestamp in seconds when present.
type BrowserCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"sameSite"`
	Expires  *int64 `json:"expires,omitempty"`
}

// BrowserCookies exports the cookies from this login for an existing browser
// context. An empty domain preserves the scope selected by the auth instance.
func (r LoginResult) BrowserCookies(domain string) ([]BrowserCookie, error) {
	if err := validateCookieDomain(domain); err != nil {
		return nil, err
	}
	cookies := make([]BrowserCookie, 0, len(r.Cookies))
	for _, cookie := range r.Cookies {
		if cookie == nil {
			return nil, errors.New("authtest: missing session cookie")
		}
		if err := cookie.Valid(); err != nil {
			return nil, err
		}
		wire := BrowserCookie{
			Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain,
			Path: cookie.Path, HTTPOnly: cookie.HttpOnly, Secure: cookie.Secure, SameSite: "Lax",
		}
		if domain != "" {
			wire.Domain = domain
		}
		switch cookie.SameSite {
		case http.SameSiteNoneMode:
			wire.SameSite = "None"
		case http.SameSiteStrictMode:
			wire.SameSite = "Strict"
		}
		switch {
		case cookie.MaxAge > 0:
			seconds := r.Session.CreatedAt.Unix() + int64(cookie.MaxAge)
			wire.Expires = &seconds
		case cookie.MaxAge < 0:
			seconds := int64(1)
			wire.Expires = &seconds
		case !cookie.Expires.IsZero():
			seconds := cookie.Expires.Unix()
			wire.Expires = &seconds
		}
		cookies = append(cookies, wire)
	}
	return cookies, nil
}

func validateCookieDomain(domain string) error {
	if domain == "" {
		return nil
	}
	return (&http.Cookie{Name: "test", Value: "test", Domain: domain}).Valid()
}
