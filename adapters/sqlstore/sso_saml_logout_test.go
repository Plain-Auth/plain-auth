package sqlstore

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/crewjam/saml"
)

func mustTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	return u
}

func testSAMLLogout(t *testing.T, first, second *Store, idp *saml.IdentityProvider, api, origin string, newBrowser func() *http.Client, sdk func(*http.Client) *client.Client, login func(*testing.T, *http.Client, string, func(*saml.Assertion)), owner *client.Client, node, peer http.Handler) {
	ctx := t.Context()
	application := strings.TrimSuffix(api, "/identity")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	code := func(h *http.Client, target string) (int, string) {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		must(e)
		res, e := h.Do(r)
		must(e)
		res.Body.Close()
		return res.StatusCode, res.Header.Get("Location")
	}
	start := func(h *http.Client) (*saml.IdpLogoutRequest, string) {
		t.Helper()
		target, e := sdk(h).StartSAMLLogout(ctx, "work", "/signed-out")
		must(e)
		r, e := http.NewRequest("GET", target, nil)
		must(e)
		if r.URL.Scheme+"://"+r.URL.Host+r.URL.Path != origin+"/logout" || r.URL.Query().Get("Signature") == "" || r.URL.Query().Get("SigAlg") != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
			t.Fatal("wrong signed logout destination")
		}
		req, e := saml.NewIdpLogoutRequest(idp, r)
		must(e)
		must(req.Validate())
		indices := req.Request.AllSessionIndexes()
		if req.Request.NameID == nil || req.Request.NameID.Value != "employee" || len(indices) != 1 || indices[0].Value != "idp-index" {
			t.Fatal("incorrect signed logout identity")
		}
		return req, r.URL.Query().Get("RelayState")
	}
	reply := func(req *saml.IdpLogoutRequest, status string, update func(*saml.LogoutResponse)) string {
		t.Helper()
		r := req.MakeLogoutResponse(status)
		if update != nil {
			update(r)
		}
		w := httptest.NewRecorder()
		must(req.WriteLogoutResponse(w, r))
		target := w.Header().Get("Location")
		if update != nil {
			target = api + "/sso/saml2/sp/slo/work?" + mustTestURL(t, target).RawQuery
		}
		if !strings.HasPrefix(target, api+"/sso/saml2/sp/slo/work?") {
			t.Fatal("wrong logout response destination")
		}
		return target
	}
	// Inline IdP metadata can add the Redirect logout service independently of
	// AuthnRequest signing. Ambiguous optional services leave sign-in available.
	for _, tc := range []struct {
		name       string
		services   []saml.Endpoint
		advertised bool
	}{
		{"xml-logout", []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: origin + "/logout"}}, true},
		{"xml-ambiguous", []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: origin + "/logout"}, {Binding: saml.HTTPRedirectBinding, Location: origin + "/other"}}, false},
		{"xml-split-origin", []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: "https://other.example.test/logout"}}, false},
	} {
		var imported saml.EntityDescriptor
		must(xml.Unmarshal([]byte(idpDocument(t, idp.MetadataURL.String(), idp.SSOURL.String(), idp.Certificate)), &imported))
		imported.IDPSSODescriptors[0].SingleLogoutServices = tc.services
		raw, e := xml.Marshal(imported)
		must(e)
		cfg := sso.SAMLConfig{EntryPoint: idp.SSOURL.String(), IDPMetadata: sso.SAMLIDPMetadata{Metadata: string(raw)}, SPMetadata: &sso.SAMLSPMetadata{EntityID: application + "/" + tc.name}}
		_, e = owner.RegisterSAMLProvider(ctx, client.RegisterSAMLProviderRequest{ProviderID: tc.name, Domain: tc.name + ".example", Issuer: idp.MetadataURL.String(), SAML: cfg})
		must(e)
		response, e := newBrowser().Get(api + "/sso/saml2/sp/metadata?providerId=" + tc.name)
		must(e)
		var metadata saml.EntityDescriptor
		err := xml.NewDecoder(response.Body).Decode(&metadata)
		response.Body.Close()
		must(err)
		if len(metadata.SPSSODescriptors) != 1 {
			t.Fatal("missing SP metadata", tc.name)
		}
		desc := metadata.SPSSODescriptors[0]
		if (len(desc.SingleLogoutServices) == 1) != tc.advertised || desc.AuthnRequestsSigned != nil && *desc.AuthnRequestsSigned {
			t.Fatal("incorrect optional logout metadata", tc.name)
		}
	}
	// A registered account's own ordinary password session cannot request logout at the IdP.
	if _, e := owner.StartSAMLLogout(ctx, "work", "/signed-out"); e == nil {
		t.Fatal("password session initiated SAML logout")
	}
	h := newBrowser()
	login(t, h, "employee", nil)
	// An unknown provider answers with another runtime's code.
	var notFound *auth.APIError
	if _, e := sdk(h).StartSAMLLogout(ctx, "absent", "/signed-out"); !errors.As(e, &notFound) || notFound.Status != 404 || notFound.Code != "SAML_PROVIDER_NOT_FOUND" || notFound.Message != "SAML provider not found" {
		t.Fatal("a logout for an unknown provider did not answer SAML_PROVIDER_NOT_FOUND", e)
	}
	// The SLO route answers an IdP request for an unknown provider with the
	// same code. A response without this browser's logout cookie is invalid
	// before any provider lookup.
	sigAlg := url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	for _, query := range []string{"SAMLRequest=x&SigAlg=" + sigAlg + "&Signature=y"} {
		res, e := newBrowser().Get(api + "/sso/saml2/sp/slo/absent?" + query)
		must(e)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 404 || !strings.Contains(string(body), `"code":"SAML_PROVIDER_NOT_FOUND"`) {
			t.Fatal("the SLO route did not answer an unknown provider with SAML_PROVIDER_NOT_FOUND", query, res.StatusCode, string(body))
		}
	}
	another := newBrowser()
	login(t, another, "employee", nil)
	a, e := sdk(h).GetSession(ctx)
	must(e)
	other, e := sdk(another).GetSession(ctx)
	must(e)
	p, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: "work", Protocol: "saml"})
	must(e)
	if _, e = second.SAMLSessionForLogout(ctx, sso.Actor{UserID: a.User.ID, SessionID: other.Session.ID, SessionToken: a.Session.Token}, "work", p.Reference, time.Now()); !errors.Is(e, sso.ErrSAMLLogoutSession) {
		t.Fatal("cross-session record returned", e)
	}
	req, _ := start(h)
	if _, _, e = second.Session(ctx, a.Session.Token); !errors.Is(e, auth.ErrNotFound) {
		t.Fatal("local session survived logout", e)
	}
	if _, _, e = second.Session(ctx, other.Session.Token); e != nil {
		t.Fatal("other SAML session was revoked", e)
	}
	if state, e := sdk(h).GetSession(ctx); e != nil || state != nil {
		t.Fatal("logout cookie did not clear local browser")
	}
	if status, _ := code(h, reply(req, saml.StatusResponder, nil)); status != 400 {
		t.Fatal("non-success logout accepted", status)
	}
	if status, _ := code(h, reply(req, saml.StatusSuccess, func(r *saml.LogoutResponse) { r.Issuer.Value = "urn:other-idp" })); status != 400 {
		t.Fatal("unexpected response issuer accepted", status)
	}
	if status, _ := code(h, reply(req, saml.StatusSuccess, func(r *saml.LogoutResponse) { r.Destination = api + "/wrong-path" })); status != 400 {
		t.Fatal("other SP response destination accepted", status)
	}
	if status, _ := code(h, reply(req, saml.StatusSuccess, func(r *saml.LogoutResponse) { r.InResponseTo = "id-other" })); status != 400 {
		t.Fatal("unrelated logout acknowledgement", status)
	}
	target := reply(req, saml.StatusSuccess, nil)
	unsigned := mustTestURL(t, target)
	q := unsigned.Query()
	q.Del("SigAlg")
	q.Del("Signature")
	unsigned.RawQuery = q.Encode()
	if status, _ := code(h, unsigned.String()); status != 400 {
		t.Fatal("unsigned logout acknowledgement accepted")
	}
	var raw string
	must(first.db.QueryRowContext(ctx, first.bind(`SELECT "samlConfig" FROM "ssoProvider" WHERE "id"=?`), p.ID).Scan(&raw))
	var changed sso.SAMLConfig
	must(json.Unmarshal([]byte(raw), &changed))
	changed.Audience = "urn:changed:logout"
	modified, e := json.Marshal(changed)
	must(e)
	replace := func(v string) {
		_, e := second.db.ExecContext(ctx, second.bind(`UPDATE "ssoProvider" SET "samlConfig"=? WHERE "id"=?`), v, p.ID)
		must(e)
	}
	replace(string(modified))
	if status, _ := code(h, target); status != 400 {
		t.Fatal("changed directory completed an older logout", status)
	}
	if _, e := sdk(another).StartSAMLLogout(ctx, "work", "/signed-out"); e == nil {
		t.Fatal("changed directory inherited an older login session")
	}
	replace(raw)
	if status, _ := code(newBrowser(), target); status != 400 {
		t.Fatal("foreign browser completed logout", status)
	}
	// A subsequent password login remains active when the old IdP round trip finishes.
	next, e := sdk(h).SignUpEmail(ctx, client.SignUpRequest{Name: "New local login", Email: "later@staff.example", Password: "local-test-password-0123"})
	must(e)
	status, location := code(h, target)
	if status != 302 || location != application+"/signed-out" {
		t.Fatal("logout acknowledgement", status, location)
	}
	current, e := sdk(h).GetSession(ctx)
	must(e)
	if current == nil || current.User.ID != next.User.ID {
		t.Fatal("callback displaced newer local session")
	}
	if status, _ = code(h, target); status != 400 {
		t.Fatal("replayed browser return accepted", status)
	}
	// Both replicas hold the same pending return; only one may consume it.
	req, _ = start(another)
	target = reply(req, saml.StatusSuccess, nil)
	rURL := mustTestURL(t, target)
	cookies := another.Jar.Cookies(rURL)
	results := make(chan int, 2)
	gate := make(chan struct{})
	for _, handler := range []http.Handler{node, peer} {
		go func() {
			<-gate
			r := httptest.NewRequest("GET", target, nil)
			for _, cookie := range cookies {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			results <- w.Code
		}()
	}
	close(gate)
	statuses := []int{<-results, <-results}
	slices.Sort(statuses)
	if !slices.Equal(statuses, []int{302, 400}) {
		t.Fatal("non-atomic logout acknowledgement", statuses)
	}
	h = newBrowser()
	login(t, h, "employee", nil)
	req, state := start(h)
	_, e = first.db.ExecContext(ctx, first.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "id"=?`), first.date(time.Now().Add(-time.Second)), originDigest("slr-", state))
	must(e)
	if status, _ = code(h, reply(req, saml.StatusSuccess, nil)); status != 400 {
		t.Fatal("expired logout accepted", status)
	}
	h = newBrowser()
	login(t, h, "no-index", func(a *saml.Assertion) { a.AuthnStatements[0].SessionIndex = "" })
	if _, e = sdk(h).StartSAMLLogout(ctx, "work", "/signed-out"); e == nil {
		t.Fatal("missing IdP session index accepted")
	}
	current, e = sdk(h).GetSession(ctx)
	must(e)
	if current == nil {
		t.Fatal("unavailable IdP logout revoked a local-only session")
	}
	h = newBrowser()
	login(t, h, "employee", nil)
	startURL := mustTestURL(t, api+"/sso/saml2/logout/work")
	launchCookies := h.Jar.Cookies(startURL)
	replies := make(chan int, 2)
	launch := make(chan struct{})
	for _, handler := range []http.Handler{node, peer} {
		go func() {
			<-launch
			r := httptest.NewRequest("POST", startURL.String(), strings.NewReader(`{"callbackURL":"/done"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", application)
			for _, cookie := range launchCookies {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			replies <- w.Code
		}()
	}
	close(launch)
	statuses = []int{<-replies, <-replies}
	slices.Sort(statuses)
	if statuses[0] != 302 || statuses[1] < 400 || statuses[1] >= 500 {
		t.Fatal("concurrent sign-out starts", statuses)
	}

}
