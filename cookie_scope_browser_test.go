package stonewrit_test

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

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
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
	instance, err := stonewrit.New(stonewrit.Options{
		BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true,
		Store: memory.New(), CrossSubDomainCookies: &stonewrit.CrossSubDomainCookiesOptions{Domain: "example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", instance)
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.example.test:"+port {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		session, err := instance.GetSession(r.Context(), r.Header)
		if err != nil {
			http.Error(w, "session lookup failed", 500)
			return
		}
		fmt.Fprint(w, session != nil)
	})
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<!doctype html><body><output>pending</output><script type="module">
const post = (route, body) => fetch("/api/auth/" + route, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
const probe = async () => (await fetch("`+sibling+`/probe",{credentials:"include",cache:"no-store"})).text();
try {
  const login = await post("sign-up/email",{name:"Local",email:"user@example.test",password:"fixture-password"});
  const shared = await probe();
  const hidden = !document.cookie.includes("session_token");
  const logout = await post("sign-out",{});
  const cleared = await probe();
  document.querySelector("output").textContent = [login.status,shared,hidden,logout.status,cleared].join(",");
} catch (error) {document.querySelector("output").textContent = error.message;}
</script></body>`)
	})
	server.Config.Handler = mux
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	profile := t.TempDir()
	cmd := exec.CommandContext(ctx, chrome, "--headless", "--disable-gpu", "--disable-background-networking", "--no-first-run", "--no-proxy-server", "--ignore-certificate-errors", "--user-data-dir="+profile, "--host-resolver-rules=MAP auth.example.test 127.0.0.1, MAP app.example.test 127.0.0.1", "--virtual-time-budget=10000", "--dump-dom", origin+"/start")
	dom, err := cmd.Output()
	if err != nil {
		t.Fatal("Chrome did not finish the loopback fixture", err)
	}
	if !strings.Contains(string(dom), "<output>200,true,true,200,false</output>") {
		t.Fatalf("unexpected browser result: %s", dom)
	}
}
