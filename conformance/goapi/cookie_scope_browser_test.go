package goapi_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/lastlogin"
)

func TestChromeSharedCookieLogout(t *testing.T) {
	chrome := os.Getenv("CHROME_BIN")
	if chrome == "" {
		t.Skip("set CHROME_BIN to exercise Chromium's browser cookie store")
	}
	server := httptest.NewUnstartedServer(nil)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://auth.example.test:" + port
	sibling := "https://app.example.test:" + port
	instance, err := plainauth.New(plainauth.Options{
		BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true,
		Store: memory.New(), CrossSubDomainCookies: &plainauth.CrossSubDomainCookiesOptions{Domain: "example.test"},
		Plugins: []plainauth.Plugin{lastlogin.New(lastlogin.Options{CookieName: "__Secure-staff.preference"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", instance)
	mux.HandleFunc("/login-preference.mjs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, "../../plugins/lastlogin/browser.mjs")
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.example.test:"+port {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.URL.Query().Has("preference") {
			c, err := r.Cookie("__Secure-staff.preference")
			if err == nil {
				fmt.Fprint(w, c.Value)
			}
			return
		}
		session, err := instance.GetSession(r.Context(), r.Header)
		if err != nil {
			http.Error(w, "session lookup failed", 500)
			return
		}
		fmt.Fprint(w, session != nil)
	})
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<!doctype html><body><script type="module">
const post = (route, body) => fetch("/api/auth/" + route, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
const probe = async (query = "") => (await fetch("`+sibling+`/probe"+query,{credentials:"include",cache:"no-store"})).text();
let result;
try {
  const {loginPreference} = await import("/login-preference.mjs");
  const login = await post("sign-up/email",{name:"Local",email:"user@example.test",password:"fixture-password"});
  const preference = loginPreference({cookieName:"__Secure-staff.preference",domain:"example.test"});
  document.cookie = "another_preference=email-only; Path=/; Secure";
  if (!preference.is("email") || await probe("?preference") !== "email") throw Error("custom preference was not shared");
  preference.clear();
  if (preference.read() !== null || await probe("?preference") !== "") throw Error("domain preference survived clear");
  if (!document.cookie.includes("another_preference=email-only")) throw Error("clearing removed an unrelated preference");
  const shared = await probe();
  const hidden = !document.cookie.includes("session_token");
  const logout = await post("sign-out",{});
  const cleared = await probe();
  result = [login.status,shared,hidden,logout.status,cleared].join(",");
} catch (error) {result = String(error);}
await fetch("/result", {method:"POST", body:result});
</script></body>`)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	result := make(chan string, 1)
	mux.HandleFunc("POST /result", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			http.Error(w, "invalid browser result", http.StatusBadRequest)
			return
		}
		select {
		case result <- string(body):
		default:
		}
		w.WriteHeader(http.StatusNoContent)
		cancel()
	})
	server.Config.Handler = mux
	server.StartTLS()
	defer server.Close()
	cmd := exec.CommandContext(ctx, chrome, "--headless", "--disable-gpu", "--disable-background-networking", "--no-first-run", "--no-proxy-server", "--ignore-certificate-errors", "--user-data-dir="+t.TempDir(), "--host-resolver-rules=MAP auth.example.test 127.0.0.1, MAP app.example.test 127.0.0.1", origin+"/start")
	cmd.Cancel = func() error {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second
	diagnostic, browserErr := cmd.CombinedOutput()
	select {
	case got := <-result:
		if got != "200,true,true,200,false" {
			t.Fatalf("unexpected browser result: %q", got)
		}
	default:
		t.Fatalf("Chrome exited before reporting the cookie checks (context %v): %v\n%s", ctx.Err(), browserErr, diagnostic)
	}
}
