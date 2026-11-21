package onetap_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/FineStack/finestack-auth/plugins/onetap"
)

func TestRedirectFormRequiresGoogleProof(t *testing.T) {
	for _, p := range []string{"//outside.example/path", "https://outside.example", "/%2foutside.example", "/\\outside.example"} {
		if _, err := onetap.RedirectHandler("/api/auth", p); err == nil {
			t.Fatalf("accepted foreign redirect path %s", p)
		}
	}
	h, err := onetap.RedirectHandler("/api/auth", "/complete")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		from, body, cookie string
		want               int
	}{
		{"https://accounts.google.com", "g_csrf_token=bound&credential=token", "g_csrf_token=bound", 200},
		{"https://foreign.example", "g_csrf_token=bound&credential=token", "g_csrf_token=bound", 403},
		{"null", "g_csrf_token=bound&credential=token", "", 403},
		{"", "g_csrf_token=bound&credential=token", "g_csrf_token=other", 403},
		{"", "g_csrf_token=bound&credential=token", "g_csrf_token=bound; g_csrf_token=other", 403},
		{"", "g_csrf_token=bound&g_csrf_token=extra&credential=token", "g_csrf_token=bound", 403},
		{"", "g_csrf_token=bound&credential=token&credential=other", "g_csrf_token=bound", 400},
	} {
		r := httptest.NewRequest("POST", "https://app.test/return", strings.NewReader(test.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", test.cookie)
		r.Header.Set("Origin", test.from)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatalf("redirect form returned %d, want %d", w.Code, test.want)
		}
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
			t.Fatal("redirect receiver prematurely issued a credential or redirect")
		}
	}
	r := httptest.NewRequest("POST", "https://app.test/return", strings.NewReader(url.Values{"g_csrf_token": {"bound"}, "credential": {"</script><script>alert(1)</script>"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", "g_csrf_token=bound")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "</script><script>") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'nonce-") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("Google credential was not confined to a non-cacheable, escaped relay")
	}
}

func TestChromeOneTapRedirect(t *testing.T) {
	binary := os.Getenv("CHROME_BIN")
	if binary == "" {
		t.Skip("set CHROME_BIN to a local Chrome executable")
	}
	h, err := onetap.RedirectHandler("/auth", "/complete")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/return", h)
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "g_csrf_token", Value: "bound", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "browser", Value: "strict-proof", HttpOnly: true, Path: "/", SameSite: http.SameSiteStrictMode})
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fmt.Fprint(w, `<!doctype html><form method="POST" action="/return"><input name="g_csrf_token" value="bound"><input name="credential" value="local-google-token"></form><script>document.forms[0].submit()</script>`)
	})
	mux.HandleFunc("/auth/one-tap/callback", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("browser")
		var in map[string]string
		if err != nil || c.Value != "strict-proof" || json.NewDecoder(r.Body).Decode(&in) != nil || in["callbackURL"] != "/complete" || in["idToken"] != "local-google-token" || r.Header.Get("Origin") != "http://"+r.Host {
			http.Error(w, "failed to bind", 400)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "signed_in", Value: "yes", HttpOnly: true, Path: "/"})
		fmt.Fprint(w, "{}")
	})
	mux.HandleFunc("/complete", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("signed_in"); err != nil {
			http.Error(w, "unknown", 401)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<output>Browser credential verified</output>")
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--headless=new", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-gpu", "--no-first-run", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--user-data-dir="+t.TempDir(), "--virtual-time-budget=4000", "--dump-dom", s.URL+"/start")
	output, err := cmd.Output()
	if err != nil || !strings.Contains(string(output), "<output>Browser credential verified</output>") {
		t.Fatalf("browser did not complete the form redirect: %v %s", err, output)
	}
}
