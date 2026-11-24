package plainauth

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

var errorCodeFormat = regexp.MustCompile("^[A-Za-z0-9_'-]+$")

// ErrorPageURL is the host-controlled destination for browser protocol
// errors. With DynamicBaseURL it uses the fallback, and plugin endpoints use
// EndpointContext.ErrorPageURL for the request's own host.
func (a *Auth) ErrorPageURL() string {
	target, _ := a.errorPageURL(context.Background())
	return target
}

func (a *Auth) errorPageURL(ctx context.Context) (string, error) {
	if a.opts.ErrorRedirectURL != "" {
		return a.callbackURL(ctx, a.opts.ErrorRedirectURL) // validated during New
	}
	base, err := a.publicURL(ctx)
	if err != nil {
		return "", err
	}
	return base + "/error", nil
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
		set := url.Values{"error": {code}}
		if description != "" {
			set.Set("error_description", description)
		}
		return Redirect(httporigin.SetQuery(a.opts.ErrorRedirectURL, set))
	}
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	page := `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication error</title><main><h1>Authentication error</h1><p>` + html.EscapeString(code) + `</p>`
	if description != "" {
		page += "<p>" + html.EscapeString(description) + "</p>"
	}
	return HTMLPage(page + "</main></html>")
}
