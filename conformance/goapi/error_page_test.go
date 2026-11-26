package goapi_test

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
)

// errorPage serves <mount>/error with query and returns its headers and body.
func errorPage(t *testing.T, auth http.Handler, query string, status int) (http.Header, string) {
	t.Helper()
	response := serve(t, auth, "GET", "/api/auth/error"+query, "", nil, status)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.Header, string(body)
}

// Options.ErrorPage serves the styled page in place of the plain one, under a
// Content-Security-Policy that allows only its own inline styles; the plain
// page stays without it, and ErrorRedirectURL still wins.
func TestErrorPageOptIn(t *testing.T) {
	t.Setenv("AUTH_ENV", "")
	const query = "?error=login_failed&error_description=Alice+%26+Bob%27s+%3Cb%3E"
	plain := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example"})
	h, body := errorPage(t, plain, query, 200)
	if !strings.Contains(body, "<title>Authentication error</title>") || h.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
		t.Fatal("the plain page changed:", h.Get("Content-Security-Policy"), body)
	}
	styled := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", ErrorPage: &authn.ErrorPageOptions{}})
	h, body = errorPage(t, styled, query, 200)
	for name, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
		"Content-Type":            "text/html; charset=utf-8",
	} {
		if h.Get(name) != want {
			t.Fatalf("%s is %q, want %q", name, h.Get(name), want)
		}
	}
	for _, want := range []string{"<title>Error</title>", "--background: white;", "--background: oklch(0.15 0 0);", "background-size: 40px 40px", "border-top: 4px solid var(--corner-border);",
		"border: 2px solid var(--destructive);", "login_failed", "Alice &amp; Bob&#39;s &lt;b&gt;", `href="/"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("the styled page lacks %q", want)
		}
	}
	if strings.Count(body, "href=") != 1 || strings.Contains(body, "https://") || strings.Contains(body, "<!--") {
		t.Fatal("the styled page links elsewhere or keeps a comment")
	}
	// A code alone gets the default sentence; markup is escaped.
	_, body = errorPage(t, styled, "?error=it's", 200)
	if !strings.Contains(body, "it&#39;s") || !strings.Contains(body, "We encountered an unexpected error. Please try again or return to the home page.") || strings.Count(body, "href=") != 1 {
		t.Fatal("the default description or code escaping changed:", body)
	}
	_, body = errorPage(t, styled, "?error=%3Cscript%3E&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E", 200)
	if !strings.Contains(body, "UNKNOWN") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") || strings.Contains(body, "<script") {
		t.Fatal("markup reached the styled page")
	}
	// An entity in the description is shown as sent, not decoded.
	if _, body = errorPage(t, styled, "?error=x&error_description=Tom+%26amp%3B+Jerry", 200); !strings.Contains(body, "Tom &amp;amp; Jerry") {
		t.Fatal("the description's entity was decoded")
	}
	// ErrorRedirectURL takes precedence.
	redirected := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", ErrorPage: &authn.ErrorPageOptions{}, ErrorRedirectURL: "/auth-problem?source=signin"})
	h, _ = errorPage(t, redirected, query, 302)
	if u, err := url.Parse(h.Get("Location")); err != nil || u.Path != "/auth-problem" || u.Query().Get("source") != "signin" || u.Query().Get("error") != "login_failed" {
		t.Fatal("the redirect was", h.Get("Location"))
	}
	// In production the styled page stays at the mount's /error, while the
	// plain page redirects to the site root.
	t.Setenv("AUTH_ENV", "production")
	styled = newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", ErrorPage: &authn.ErrorPageOptions{}})
	if _, body = errorPage(t, styled, query, 200); !strings.Contains(body, "<title>Error</title>") || styled.ErrorPageURL() != "https://auth.example/api/auth/error" {
		t.Fatal("production lost the styled page:", styled.ErrorPageURL())
	}
	plain = newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example"})
	if h, _ = errorPage(t, plain, query, 302); !strings.HasPrefix(h.Get("Location"), "/?") {
		t.Fatal("production's plain page redirected to", h.Get("Location"))
	}
}

// Each theme value reaches every place the page styles with it, and the
// switches remove what they name.
func TestErrorPageThemeValues(t *testing.T) {
	t.Setenv("AUTH_ENV", "")
	theme := authn.ErrorPageOptions{
		Background: "rgb(9 0 1)", Foreground: "rgb(9 0 2)", Primary: "rgb(9 0 3)", PrimaryForeground: "rgb(9 0 4)", MutedForeground: "rgb(9 0 5)", Border: "rgb(9 0 6)",
		Destructive: "rgb(9 0 7)", TitleBorder: "rgb(9 0 8)", TitleColor: "rgb(9 0 9)", GridColor: "rgb(9 0 10)", CardBackground: "rgb(9 0 11)", CornerBorder: "rgb(9 0 12)",
		RadiusSm: "0.91rem", TextSm: "0.92rem", Text2xl: "0.93rem", Text4xl: "0.94rem", Text6xl: "0.95rem",
		FontFamily: "'Probe Sans', serif", MonoFontFamily: `"Probe Mono", monospace`,
	}
	render := func(o authn.ErrorPageOptions) string {
		t.Helper()
		_, body := errorPage(t, newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", ErrorPage: &o}), "?error=login_failed", 200)
		return body
	}
	page := render(theme)
	switched := theme
	switched.DisableTitleBorder, switched.DisableCornerDecorations, switched.DisableBackgroundGrid = true, true, true
	off := render(switched)
	for _, tc := range []struct {
		value     string
		on, unset int
	}{
		{theme.Background, 4, 3}, {theme.Foreground, 2, 2}, {theme.Primary, 2, 2}, {theme.PrimaryForeground, 2, 2}, {theme.MutedForeground, 2, 2}, {theme.Border, 2, 2},
		{theme.Destructive, 2, 2}, {theme.CornerBorder, 2, 2}, {theme.TitleBorder, 1, 0}, {theme.TitleColor, 1, 1}, {theme.GridColor, 2, 0}, {theme.CardBackground, 1, 1},
		{theme.RadiusSm, 1, 1}, {theme.TextSm, 1, 1}, {theme.Text2xl, 1, 1}, {theme.Text4xl, 1, 1}, {theme.Text6xl, 1, 1}, {theme.FontFamily, 1, 1}, {theme.MonoFontFamily, 1, 1},
	} {
		if strings.Count(page, tc.value) != tc.on || strings.Count(off, tc.value) != tc.unset {
			t.Fatalf("%s appears %d and %d times, want %d and %d", tc.value, strings.Count(page, tc.value), strings.Count(off, tc.value), tc.on, tc.unset)
		}
	}
	if strings.Count(page, "4px solid var(--corner-border)") != 8 || !strings.Contains(off, "border: 2px solid transparent;") {
		t.Fatal("the corner marks or the title border are wrong")
	}
	for _, gone := range []string{"4px solid var(--corner-border)", "background-size: 40px 40px", "mask-image"} {
		if strings.Contains(off, gone) {
			t.Fatal("a switch kept", gone)
		}
	}
}

// New refuses a theme value that could leave its CSS declaration and names
// the field; a quoted value cannot leave its style attribute, and New keeps
// its own copy of the theme.
func TestErrorPageRefusesUnsafeValues(t *testing.T) {
	t.Setenv("AUTH_ENV", "")
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	build := func(page *authn.ErrorPageOptions) (*authn.Auth, error) {
		return authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), ErrorPage: page})
	}
	kind := reflect.TypeFor[authn.ErrorPageOptions]()
	for i := range kind.NumField() {
		field := kind.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}
		var page authn.ErrorPageOptions
		reflect.ValueOf(&page).Elem().Field(i).SetString("red; color: blue")
		if _, err := build(&page); err == nil || !strings.Contains(err.Error(), "ErrorPage."+field.Name) {
			t.Fatal("New accepted a declaration in", field.Name, err)
		}
	}
	for _, bad := range []string{`red}body{display:none`, `red</style><script>alert(1)</script>`, `rgb(0 0 0`, `a)b(`, `'Segoe UI`, `"Segoe UI`, `red /* x */`, `\3b`, "1rem\n", "red\u0085", `[a]`,
		`url(x')/*')`, `URL(x')')`, `(url(a')'))`, `url( x')`, `url("x")`, `red */ blue`} {
		if _, err := build(&authn.ErrorPageOptions{Background: bad}); err == nil {
			t.Fatalf("New accepted %q", bad)
		}
	}
	for _, good := range []string{`oklch(0.55 0.15 25.723)`, `var(--primary)`, `rgb(0 0 0 / 50%)`, `calc(1rem + 2px)`, `system-ui, 'Segoe UI', 'Noto Sans (JP)', sans-serif`, `"Inter", sans-serif`, `red !important`} {
		if _, err := build(&authn.ErrorPageOptions{Background: good, FontFamily: good}); err != nil {
			t.Fatalf("New refused %q: %v", good, err)
		}
	}
	a, err := build(&authn.ErrorPageOptions{TitleColor: `red" onmouseover="alert(1)`})
	if err != nil {
		t.Fatal(err)
	}
	if _, body := errorPage(t, a, "?error=x", 200); strings.Contains(body, `" onmouseover="`) || !strings.Contains(body, "onmouseover") {
		t.Fatal("a quoted value left its style attribute")
	}
	page := &authn.ErrorPageOptions{Background: "#123456"}
	if a, err = build(page); err != nil {
		t.Fatal(err)
	}
	page.Background = "</style><script>alert(2)</script>"
	if _, body := errorPage(t, a, "?error=x", 200); !strings.Contains(body, "#123456") || strings.Contains(body, "<script") {
		t.Fatal("New kept the caller's theme")
	}
}
