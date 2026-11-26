package plainauth

import (
	"context"
	_ "embed"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

var errorCodeFormat = regexp.MustCompile("^[A-Za-z0-9_'-]+$")

// ErrorPageOptions styles the error page at <mount>/error. Each string is
// one CSS value, such as "#0070f3", "oklch(0.55 0.15 25.7)", "1.25rem" or
// "'Inter', sans-serif"; an empty string keeps the default shown as light /
// dark. A color replaces its light and its dark default alike. Screens up to
// 640px wide use fixed smaller TextSm, Text2xl and Text6xl sizes. New refuses
// a value with a control character, a CSS comment, any of ; { } [ ] < > \
// or an unbalanced parenthesis or quote.
type ErrorPageOptions struct {
	Background        string // page and grid fade; white / oklch(0.15 0 0)
	Foreground        string // headings, code and text; oklch(0.271 0 0) / oklch(0.98 0 0)
	Primary           string // Go Home button; black / white
	PrimaryForeground string // Go Home label; white / black
	MutedForeground   string // CODE label and description; oklch(0.545 0 0) / oklch(0.65 0 0)
	Border            string // card, divider, code box, button and grid lines; oklch(0.89 0 0) / oklch(0.27 0 0)
	Destructive       string // title border unless TitleBorder is set; oklch(0.55 0.15 25.723) / oklch(0.65 0.15 25.723)
	TitleBorder       string // border around the ERROR title; defaults to Destructive
	TitleColor        string // ERROR title; defaults to Foreground
	GridColor         string // background grid lines; defaults to Border
	CardBackground    string // card; defaults to Background
	CornerBorder      string // card corner marks; #404040 / #a0a0a0

	RadiusSm string // sets --radius (0.625rem), which no element uses: the page has square corners
	TextSm   string // code and description; 0.875rem
	Text2xl  string // "Something went wrong"; 1.5rem
	Text4xl  string // sets --text-4xl (2.25rem), which no element uses
	Text6xl  string // ERROR title; 3rem

	// The page loads no web fonts, so name fonts installed on the viewer's
	// device.
	FontFamily     string // page text; -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif
	MonoFontFamily string // the error code; monospace

	DisableTitleBorder       bool // draws the title border transparent and keeps its width
	DisableCornerDecorations bool // removes the card's four corner marks
	DisableBackgroundGrid    bool // removes the background grid and its fade
}

//go:embed error_page.html
var errorPageHTML string

// errorPageTemplate is the styled page. css emits a theme value that New
// checked, or the built-in default, as trusted CSS; html/template still
// escapes the code, the description and every style attribute.
var errorPageTemplate = template.Must(template.New("error").Funcs(template.FuncMap{
	"css": func(value, fallback string) template.CSS {
		if value == "" {
			value = fallback
		}
		return template.CSS(value)
	},
}).Parse(errorPageHTML))

// prepareErrorPage keeps a private copy of the error page theme and refuses
// a value that could leave its CSS declaration.
func prepareErrorPage(o *Options) error {
	if o.ErrorPage == nil {
		return nil
	}
	page := *o.ErrorPage
	v := reflect.ValueOf(page)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && !cssValue(f.String()) {
			return fmt.Errorf("auth: ErrorPage.%s must be a single CSS value", v.Type().Field(i).Name)
		}
	}
	o.ErrorPage = &page
	return nil
}

// cssValue reports whether v stays inside the one CSS declaration it fills:
// it cannot end the declaration, rule or style element, escape the next
// character, open a comment, or leave a bracket or string open.
func cssValue(v string) bool {
	depth, quote := 0, rune(0)
	for i, r := range v {
		switch {
		case unicode.IsControl(r) || strings.ContainsRune(`;{}[]<>\`, r):
			return false
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '(':
			depth++
		case r == ')':
			depth--
			if depth < 0 {
				return false
			}
		case r == '/' && strings.HasPrefix(v[i+1:], "*"):
			return false
		}
	}
	return depth == 0 && quote == 0
}

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
// With Options.ErrorPage it is the styled page instead of the plain one.
func (a *Auth) errorPage(h http.Header, r *http.Request) (any, error) {
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
		return Redirect(httporigin.SetQuery(a.opts.ErrorRedirectURL, set)), nil
	}
	h.Set("Referrer-Policy", "no-referrer")
	if a.opts.ErrorPage != nil {
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		var page strings.Builder
		if err := errorPageTemplate.Execute(&page, struct {
			ErrorPageOptions
			Code, Description string
		}{*a.opts.ErrorPage, code, description}); err != nil {
			return nil, err
		}
		return HTMLPage(page.String()), nil
	}
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	page := `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication error</title><main><h1>Authentication error</h1><p>` + html.EscapeString(code) + `</p>`
	if description != "" {
		page += "<p>" + html.EscapeString(description) + "</p>"
	}
	return HTMLPage(page + "</main></html>"), nil
}
