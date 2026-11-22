package plainauth

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
)

var errorCodeFormat = regexp.MustCompile("^[A-Za-z0-9_'-]+$")

func (a *Auth) serveErrorPage(w http.ResponseWriter, r *http.Request) {
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
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	fmt.Fprintf(w, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication error</title><main><h1>Authentication error</h1><p>%s</p>`, html.EscapeString(code))
	if description != "" {
		fmt.Fprintf(w, "<p>%s</p>", html.EscapeString(description))
	}
	fmt.Fprint(w, "</main></html>")
}
