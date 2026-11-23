package plainauth

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
)

var errorCodeFormat = regexp.MustCompile("^[A-Za-z0-9_'-]+$")

// ErrorPageURL is the host-controlled destination for browser protocol errors.
func (a *Auth) ErrorPageURL() string {
	if a.opts.ErrorRedirectURL != "" {
		target, _ := a.CallbackURL(a.opts.ErrorRedirectURL) // validated during New
		return target
	}
	return a.PublicURL() + "/error"
}

// errorPage returns the browser error page, or a redirect to ErrorRedirectURL.
func (a *Auth) errorPage(h http.Header, r *http.Request) any {
	q := r.URL.Query()
	code := q.Get("error")
	if !errorCodeFormat.MatchString(code) {
		code = "UNKNOWN"
	}
	description := q.Get("error_description")
	if a.opts.ErrorRedirectURL != "" {
		target, _ := url.Parse(a.opts.ErrorRedirectURL)
		params := target.Query()
		params.Set("error", code)
		if description != "" {
			params.Set("error_description", description)
		}
		target.RawQuery = params.Encode()
		return Redirect(target.String())
	}
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	page := `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication error</title><main><h1>Authentication error</h1><p>` + html.EscapeString(code) + `</p>`
	if description != "" {
		page += "<p>" + html.EscapeString(description) + "</p>"
	}
	return HTMLPage(page + "</main></html>")
}
