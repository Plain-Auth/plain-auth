package goapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

func TestWildcardOriginCallbacks(t *testing.T) {
	t.Setenv("AUTH_TRUSTED_ORIGINS", "*.store.example,https://preview-?.example:84??")
	a, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example/login",
		Secret: strings.Repeat("x", 32), TrustedOrigins: []string{
			"https://*.apps.example", "http://192.168.*.*:*", "https://[::1]:8???",
			"https://branch.**.example", "https://portal*", "*://common.example:443", "https://media.example:*",
		}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		callback string
		trusted  bool
	}{
		{"/dashboard", true},
		{"https://auth.example/home", true},
		{"https://eu.web.apps.example/user?tab=profile#name", true},
		{"https://app.apps.example:443", true}, {"https://app.apps.example:8443", false},
		{"https://apps.example", false}, {"http://app.apps.example", false},
		{"https://app.apps.example.other.test", false},
		{"http://web.store.example", true}, {"https://web.store.example", true},
		{"https://preview-a.example:8443", true}, {"https://preview-ab.example:8443", false},
		{"https://preview-a.example:8843", false}, {"https://preview-a.example", false},
		{"http://192.168.1.2:8080", true}, {"http://192.168.dev.example:8080", false},
		{"https://[::1]:8123", true}, {"https://[::2]:8123", false},
		{"https://branch.one.two.example", true},
		{"https://portal-preview", true}, {"https://portal-preview:8443", false},
		{"https://common.example", true}, {"http://common.example:443", true},
		{"https://media.example:12345", true}, {"https://media.example", false},
		{"https://media.example:65536", false}, {"https://bad_label.apps.example", false},
		{"https://*.apps.example", false}, {"https://[web.apps.example]", false}, {"https://person@web.apps.example", false},
		{"ftp://web.store.example", false},
	} {
		t.Run(tc.callback, func(t *testing.T) {
			got, err := a.CallbackURL(tc.callback)
			if (err == nil) != tc.trusted || (tc.trusted && got == "") {
				t.Fatalf("CallbackURL(%q) returned %q, %v", tc.callback, got, err)
			}
		})
	}
}

func TestInvalidWildcardOriginConfiguration(t *testing.T) {
	t.Setenv("AUTH_TRUSTED_ORIGINS", "")
	for _, value := range []string{"*.shop.example/products", "https://user@*.shop.example", "https://*.shop.example#fragment",
		"https://*.shop.example:65536", "https://*.shop.example:", "https://*.shop.example:8x", "ftp://*.shop.example",
		"https://*.shop..example", "https://[::1]oops:*", "https://a.example?param=value"} {
		t.Run(value, func(t *testing.T) {
			_, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example",
				Secret: strings.Repeat("x", 32), TrustedOrigins: []string{value}})
			if err == nil {
				t.Fatal("invalid wildcard origin accepted at startup")
			}
		})
	}
}

// Custom-scheme origins trust app deep links and extensions: an exact
// authority and path prefix, a host-less scheme, or wildcards in the
// authority and in path segments. They need an explicit scheme, and schemes
// that can run code are never trusted.
func TestCustomSchemeOrigins(t *testing.T) {
	t.Setenv("AUTH_TRUSTED_ORIGINS", "")
	a, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example", Secret: strings.Repeat("x", 32),
		TrustedOrigins: []string{"myapp://", "chrome-extension://abcdefghijklmnop", "exp://192.168.*.*:*/**", "acme://app/auth", "*.example.com", "dev://**", "expo://10.0.0.*:*/**"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		callback string
		trusted  bool
	}{
		{"myapp://home/dashboard?tab=1", true}, {"myapp://", true}, {"MYAPP://Home", true},
		{"myapp:callback", false}, {"otherapp://home", false}, {"myapp://user@home", false},
		{"chrome-extension://abcdefghijklmnop/popup.html", true}, {"chrome-extension://otherextension/popup.html", false},
		{"exp://192.168.1.20:8081/--/auth", true}, {"exp://192.168.1.20:8081", true}, {"exp://evil.example:8081/--/auth", false},
		{"acme://app/auth", true}, {"acme://app/auth/done", true}, {"acme://app/authx", false}, {"acme://app/other", false}, {"acme://other/auth", false},
		{"acme://app/auth/../other", false},
		{"javascript://x.example.com/%0aalert(1)", false}, {"myother://x.example.com", false},
		{"https://x.example.com", true},
		{"dev://192.168.1.2:8081/--/auth/callback", true}, {"dev://any.host", true},
		{"expo://10.0.0.29:8081/path", true}, {"expo://10.0.1.29:8081/path", false},
	} {
		t.Run(tc.callback, func(t *testing.T) {
			got, err := a.CallbackURL(tc.callback)
			if (err == nil) != tc.trusted || (tc.trusted && got != tc.callback) {
				t.Fatalf("CallbackURL(%q) returned %q, %v", tc.callback, got, err)
			}
		})
	}
	for _, value := range []string{"javascript://", "data:", "file:///", "vbscript://x", "myapp://user@app", "myapp://app/%2e%2e", "myapp://app/[a]", "myapp://app#x"} {
		if _, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example", Secret: strings.Repeat("x", 32), TrustedOrigins: []string{value}}); err == nil {
			t.Errorf("accepted the trusted origin %q", value)
		}
	}
	// DisableOriginCheck still refuses schemes that can run code.
	open, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example", Secret: strings.Repeat("x", 32), DisableOriginCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, callback := range []string{"javascript:alert(1)", "data:text/html,<script>alert(1)</script>"} {
		if _, err := open.CallbackURL(callback); err == nil {
			t.Errorf("DisableOriginCheck accepted %q", callback)
		}
	}
	if _, err := open.CallbackURL("https://anywhere.example/done"); err != nil {
		t.Fatal("DisableOriginCheck refused an HTTPS target", err)
	}
}

// A trusted extension origin passes the browser origin check of a
// state-changing request, but One Tap only binds a web page origin.
func TestCustomSchemeRequestOrigin(t *testing.T) {
	t.Setenv("AUTH_TRUSTED_ORIGINS", "")
	off := false
	a, err := plainauth.New(plainauth.Options{Store: memory.New(), BaseURL: "https://auth.example", Secret: strings.Repeat("x", 32), EmailAndPassword: true, RateLimit: &off,
		TrustedOrigins: []string{"chrome-extension://abcdefghijklmnop"}})
	if err != nil {
		t.Fatal(err)
	}
	signUp := func(origin string) int {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"email":"ext`+strings.ToLower(origin[:3])+`@example.com","password":"correct horse battery","name":"Ext"}`))
		r.Header = http.Header{"Origin": {origin}, "Content-Type": {"application/json"}}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Code
	}
	if code := signUp("chrome-extension://abcdefghijklmnop"); code != 200 {
		t.Fatal("a trusted extension origin was refused", code)
	}
	if code := signUp("moz-extension://abcdefghijklmnop"); code != 403 {
		t.Fatal("an untrusted extension origin was accepted", code)
	}
	if err := a.BindOneTapNonce(httptest.NewRecorder(), "chrome-extension://abcdefghijklmnop", "client", strings.Repeat("n", 24)); err == nil {
		t.Fatal("One Tap bound an extension origin")
	}
}
