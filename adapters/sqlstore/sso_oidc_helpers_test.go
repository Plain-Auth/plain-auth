package sqlstore

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

// ssoHost serves enterprise sign-in at https://service.test/identity and
// trusts the local issuer's origin.
type ssoHost struct {
	t   *testing.T
	a   *auth.Auth
	idp *ssoIssuer
}

func newSSOHost(t *testing.T, store *Store, idp *ssoIssuer, opts sso.Options) *ssoHost {
	t.Helper()
	p, err := sso.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, EmailAndPassword: true, Secret: strings.Repeat("k", 32), TrustedOrigins: []string{idp.URL}, Plugins: []auth.Plugin{p}})
	if err != nil {
		t.Fatal(err)
	}
	return &ssoHost{t, a, idp}
}

func (h *ssoHost) call(method, path, cookie string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://service.test")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.a.ServeHTTP(w, req)
	return w
}

// signUp creates a password account and returns its session cookie.
func (h *ssoHost) signUp(email string) string {
	h.t.Helper()
	w := h.call("POST", "sign-up/email", "", map[string]any{"name": "Owner", "email": email, "password": "correct-horse-staple"})
	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Name, "session_token") {
			return c.Name + "=" + c.Value
		}
	}
	h.t.Fatal("sign-up returned no session", w.Code, w.Body.String())
	return ""
}

func (h *ssoHost) register(cookie string, body map[string]any) *httptest.ResponseRecorder {
	return h.call("POST", "sso/register", cookie, body)
}

// ssoPending is a started sign-in whose code the issuer will exchange.
type ssoPending struct{ cookie, path string }

// start posts /sign-in/sso with callbackURL /home and errorCallbackURL
// /retry, and has the issuer grant a code for the returned authorization
// request. A refused start returns its response and no pending sign-in.
func (h *ssoHost) start(selector map[string]any, email, subject, style, mode string) (ssoPending, *httptest.ResponseRecorder) {
	h.t.Helper()
	body := map[string]any{"callbackURL": "/home", "errorCallbackURL": "/retry"}
	for k, v := range selector {
		body[k] = v
	}
	w := h.call("POST", "sign-in/sso", "", body)
	if w.Code != 200 {
		return ssoPending{}, w
	}
	var result struct{ URL string }
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		h.t.Fatal(err)
	}
	u, err := url.Parse(result.URL)
	if err != nil {
		h.t.Fatal(err)
	}
	q := u.Query()
	cb, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		h.t.Fatal(err)
	}
	code := rand.Text()
	h.idp.mu.Lock()
	h.idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), cb.String(), email, subject, style, mode}
	h.idp.mu.Unlock()
	state := w.Result().Cookies()[0]
	return ssoPending{state.Name + "=" + state.Value, strings.TrimPrefix(cb.Path, "/identity/") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()}, w
}

// finish returns the browser to the callback with its state cookie.
func (h *ssoHost) finish(p ssoPending) *httptest.ResponseRecorder {
	return h.call("GET", p.path, p.cookie, nil)
}

// signIn starts and finishes a sign-in; a refused start returns its response.
func (h *ssoHost) signIn(selector map[string]any, email, subject, style, mode string) *httptest.ResponseRecorder {
	h.t.Helper()
	p, w := h.start(selector, email, subject, style, mode)
	if p.path == "" {
		return w
	}
	return h.finish(p)
}
