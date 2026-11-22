package oauthpopup_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlite"
	"github.com/Stonewrit/stonewrit-auth/plugins/oauthpopup"
	"github.com/Stonewrit/stonewrit-auth/plugins/openapi"
	"golang.org/x/oauth2"
)

const authBase = "https://identity.example"
const opener = "https://app.example"

func service(t *testing.T, enabled bool, configured ...oauthpopup.Options) *stonewrit.Auth {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	opts := stonewrit.Options{BaseURL: authBase, BasePath: "/identity", TrustedOrigins: []string{opener},
		Store: store, Secret: strings.Repeat("k", 32),
		SocialProviders: map[string]stonewrit.OAuthProvider{"work": {Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
			ExchangeCode: func(_ context.Context, _ oauth2.Config, _ string, _ string, _ url.Values) (*oauth2.Token, error) {
				return &oauth2.Token{AccessToken: "local"}, nil
			},
			Resolve: func(_ context.Context, _ *oauth2.Token, _ string) (stonewrit.OAuthProfile, error) {
				return stonewrit.OAuthProfile{Subject: "local", Email: "local@example.test", Name: "Local", EmailVerified: true}, nil
			},
		}}}
	if enabled {
		popup := oauthpopup.New()
		if len(configured) != 0 {
			popup, err = oauthpopup.NewWithOptions(configured[0])
			if err != nil {
				t.Fatal(err)
			}
		}
		opts.Plugins = []stonewrit.Plugin{popup, {ID: "host-cookie", OnSessionCookie: func(e stonewrit.SessionCookieEvent) {
			e.Header.Add("Set-Cookie", "host_marker=1; Path=/; HttpOnly")
		}}}
	}
	a, err := stonewrit.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func get(a http.Handler, path string, cs ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", authBase+"/identity"+path, nil)
	for _, c := range cs {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

var pageParts = regexp.MustCompile(`(?s)<script type="application/json" id="oauth-popup-data">(.+?)</script><script>(.+?)</script>`)

func message(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	pieces := pageParts.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || len(pieces) != 3 {
		t.Fatalf("expected popup page: HTTP %d", w.Code)
	}
	if pieces[2] != oauthpopup.CompletionScript || !strings.Contains(w.Body.String(), `id="`+oauthpopup.DataElementID+`"`) {
		t.Fatal("public completion script or data element differs from the served page")
	}
	sum := sha256.Sum256([]byte(pieces[2]))
	if oauthpopup.ScriptCSPHash != "sha256-"+base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatal("declared script hash differs from the executed script")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("completion policy does not match the executed script")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(pieces[1]), &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func start(nonce string) string {
	return "/oauth-popup/start?" + url.Values{"popupOrigin": {opener}, "popupNonce": {nonce}, "provider": {"work"}}.Encode()
}

func TestPopupOriginAndFailurePages(t *testing.T) {
	a := service(t, true)
	if w := get(a, "/oauth-popup/start?popupOrigin="+url.QueryEscape(opener)); w.Code != 400 {
		t.Fatal("missing provider should fail before a flow starts")
	}
	if w := get(service(t, false), start("n")); w.Code != 404 {
		t.Fatalf("plugin is opt-in: %d", w.Code)
	}
	for _, bad := range []string{"https://untrusted.test", "//app.example", "https://app.example@untrusted.test", "https://app.example/path", "https://app.example?app", "null", "*"} {
		w := get(a, "/oauth-popup/start?provider=work&popupOrigin="+url.QueryEscape(bad))
		if w.Code != 403 || len(w.Result().Cookies()) != 0 || pageParts.Match(w.Body.Bytes()) {
			t.Fatalf("invalid opener %q was trusted", bad)
		}
	}
	for field, code := range map[string]string{"callbackURL": "invalid_callback_url", "errorCallbackURL": "invalid_error_callback_url", "newUserCallbackURL": "invalid_new_user_callback_url"} {
		m := message(t, get(a, start("n")+"&"+field+"="+url.QueryEscape("https://untrusted.test/x")))
		if m["error"].(map[string]any)["code"] != code || m["token"] != nil || m["targetOrigin"] != opener {
			t.Fatal("unsafe redirect outcome", field, m)
		}
	}
	attack := "</script><p>marker</p>"
	w := get(a, strings.Replace(start(attack), "provider=work", "provider=missing", 1))
	m := message(t, w)
	if strings.Contains(w.Body.String(), attack) || m["nonce"] != attack || m["type"] != oauthpopup.MessageType || m["error"].(map[string]any)["code"] != "provider_not_found" {
		t.Fatal("escaped failure page lost its wire contract")
	}
}

func TestPopupMarkerAndSingleUseOAuthState(t *testing.T) {
	a := service(t, true)
	type grant struct {
		state               string
		stateCookie, marker *http.Cookie
	}
	begin := func(n string) grant {
		w := get(a, start(n))
		if w.Code != 302 {
			t.Fatal("expected provider navigation", w.Code)
		}
		dest, _ := url.Parse(w.Header().Get("Location"))
		g := grant{state: dest.Query().Get("state")}
		for _, c := range w.Result().Cookies() {
			if strings.HasSuffix(c.Name, ".oauth_popup") {
				g.marker = c
			}
			if strings.HasSuffix(c.Name, ".oauth_state") {
				g.stateCookie = c
			}
		}
		if g.state == "" || g.marker == nil || !g.marker.HttpOnly || g.marker.MaxAge != 600 || g.stateCookie == nil {
			t.Fatal("missing bound browser grant")
		}
		return g
	}
	callback := func(g grant, marker *http.Cookie) *httptest.ResponseRecorder {
		return get(a, "/callback/work?code=fixture&state="+g.state, g.stateCookie, marker)
	}
	first, other := begin("first"), begin("other")
	ordinary := callback(first, other.marker)
	if ordinary.Code != 302 || ordinary.Header().Get("Location") != authBase+"/identity" || pageParts.Match(ordinary.Body.Bytes()) {
		t.Fatal("foreign marker replaced a redirect")
	}
	other.marker.Value += "x"
	if damaged := callback(other, other.marker); damaged.Code != 302 {
		t.Fatal("tampered opener marker relayed a session")
	}
	g := begin("valid")
	w := callback(g, g.marker)
	m := message(t, w)
	if m["nonce"] != "valid" || m["targetOrigin"] != opener || m["redirectTo"] != authBase+"/identity" {
		t.Fatal("incorrect handoff target")
	}
	var token string
	expired, hostCookie := false, false
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, ".session_token") {
			token = c.Value
		}
		if c.Name == "host_marker" && c.Value == "1" {
			hostCookie = true
		}
		if c.Name == g.marker.Name && c.MaxAge < 0 {
			expired = true
		}
	}
	if !hostCookie || !expired || token == "" || token != m["token"] || a.VerifySignedSessionToken(token) == "" {
		t.Fatal("handoff must match the issued signed cookie and consume marker")
	}
	replayed := message(t, callback(g, g.marker))
	if replayed["token"] != nil || replayed["error"] == nil {
		t.Fatal("replayed grant issued a token")
	}
}

func TestPopupDescribesNavigationAndCompletion(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		doc, err := openapi.Generate(service(t, enabled))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		type operation struct {
			Parameters []struct {
				Name     string
				Required bool
			}
			Responses map[string]struct{ Content map[string]any }
		}
		var spec struct {
			Paths map[string]map[string]operation
		}
		if err := json.Unmarshal(encoded, &spec); err != nil {
			t.Fatal(err)
		}
		start, found := spec.Paths["/oauth-popup/start"]["get"]
		if found != enabled {
			t.Fatal("popup metadata does not follow activation")
		}
		if enabled {
			if start.Responses["200"].Content["text/html"] == nil || len(start.Parameters) != 9 {
				t.Fatal("missing popup start contract")
			}
			if _, ok := start.Responses["302"]; !ok {
				t.Fatal("missing provider navigation")
			}
		}
		for _, method := range []string{"get", "post"} {
			op := spec.Paths["/callback/{id}"][method]
			if _, ok := op.Responses["302"]; !ok {
				t.Fatal("missing ordinary OAuth redirect")
			}
			if html := op.Responses["200"].Content["text/html"] != nil; html != (enabled && method == "get") {
				t.Fatal("callback completion metadata does not match the handler", method)
			}
		}
	}
}

func TestPopupBrowserModule(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST"} {
		w := httptest.NewRecorder()
		oauthpopup.BrowserModule(w, httptest.NewRequest(method, "https://app.example/popup.mjs", nil))
		if method == "POST" {
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("unexpected module method response")
			}
			continue
		}
		if w.Code != 200 || w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
			t.Fatal("module MIME type")
		}
		if method == "GET" && !strings.Contains(w.Body.String(), "export function createPopupClient(") {
			t.Fatal("browser host did not receive the client ES module")
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD returned script content")
		}
	}
}

func TestHostSelectsPopupMessageProtocol(t *testing.T) {
	const custom = "work.auth:oauth.popup"
	for _, input := range []string{"*", "oauth", "a:b:c", "app:popup\n", "space here:popup", strings.Repeat("x", 65) + ":popup"} {
		if _, err := oauthpopup.NewWithOptions(oauthpopup.Options{MessageType: input}); err == nil {
			t.Fatalf("invalid message type %q", input)
		}
	}
	for _, kind := range []string{"", custom} {
		a := service(t, true, oauthpopup.Options{MessageType: kind})
		expected := kind
		if expected == "" {
			expected = oauthpopup.MessageType
		}
		attempt := start("nonce") + "&messageType=untrusted%3Aprotocol"
		w := get(a, strings.Replace(attempt, "provider=work", "provider=unknown", 1))
		if m := message(t, w); m["type"] != expected || m["token"] != nil {
			t.Fatal("query overrode host error protocol")
		}
		w = get(a, attempt)
		if w.Code != 302 {
			t.Fatal("popup did not start")
		}
		provider, _ := url.Parse(w.Header().Get("Location"))
		done := get(a, "/callback/work?state="+provider.Query().Get("state")+"&code=fixture&messageType=untrusted%3Aprotocol", w.Result().Cookies()...)
		if m := message(t, done); m["type"] != expected || m["nonce"] != "nonce" || m["targetOrigin"] != opener || m["token"] == nil {
			t.Fatal("popup message type lost its marker binding")
		}
	}
}
