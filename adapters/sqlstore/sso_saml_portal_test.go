package sqlstore

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/crewjam/saml"
)

type portalResponse struct {
	status   int
	location string
	session  *http.Cookie
}

func checkSAMLPortal(t *testing.T, idp *saml.IdentityProvider, spEntity, acs, origin string, form func(*saml.IdpAuthnRequest, string, string, func(*saml.Assertion)) url.Values, reviewed *atomic.Pointer[sso.SAMLDirectory], directory sso.SAMLDirectory, node, peer, disabled, existingOnly http.Handler) {
	t.Helper()
	// The directory is registered under the same host and auth mount as the SP flows.
	target, _ := url.Parse(acs)
	home := target.Scheme + "://" + target.Host
	issue := func(adjust func(*saml.Assertion)) url.Values {
		t.Helper()
		req, e := idp.NewIdpInitiatedRequest(httptest.NewRequest("GET", origin+"/portal", nil), spEntity, "")
		if e != nil {
			t.Fatal(e)
		}
		fields := form(req, "portal-user", "portal@staff.example", adjust)
		fields.Del("RelayState")
		return fields
	}
	send := func(handler http.Handler, fields url.Values, source, host, dest string) portalResponse {
		r := httptest.NewRequest("POST", acs, strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if source != "" {
			r.Header.Set("Origin", source)
		}
		if host != "" {
			r.Host = host
		}
		if dest != "" {
			r.Header.Set("Sec-Fetch-Dest", dest)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		result := portalResponse{status: w.Code, location: w.Header().Get("Location")}
		for _, cookie := range w.Result().Cookies() {
			if strings.HasSuffix(cookie.Name, ".session_token") && cookie.Value != "" {
				result.session = cookie
			}
		}
		return result
	}
	rejected := func(res portalResponse, code string) {
		t.Helper()
		u, _ := url.Parse(res.location)
		if res.session != nil || res.status != 302 || u.Query().Get("error") != code {
			t.Fatalf("expected %s, received status %d and URL %q", code, res.status, res.location)
		}
	}
	proof := issue(nil)
	rejected(send(disabled, proof, origin, "", "document"), "unsolicited_response")
	rejected(send(node, proof, origin, "", "document"), "unsolicited_response")
	reviewed.Store(&directory)
	rejected(send(existingOnly, proof, origin, "", "document"), "signup_disabled")
	for _, orig := range []string{"", "null", "https://other.example.test", "https://identity.example.test:9999"} {
		rejected(send(node, proof, orig, "", "document"), "invalid_origin")
	}
	rejected(send(node, proof, origin, "", "iframe"), "invalid_origin")
	if got := send(node, proof, origin, "different.example.test", "document"); got.status != 400 || got.session != nil {
		t.Fatal("unconfigured auth host accepted portal form")
	}
	bad := issue(nil)
	bad.Set("RelayState", "unknown-browser-state")
	if got := send(node, bad, origin, "", "document"); got.status != 400 || got.session != nil {
		t.Fatal("unrecognized RelayState fell through to a portal login")
	}
	for name, adjust := range map[string]func(*saml.Assertion){
		"subject request": func(a *saml.Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "_requested-elsewhere"
		},
		"recipient": func(a *saml.Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = acs + "-other"
		},
		"issuer":   func(a *saml.Assertion) { a.Issuer.Value = "urn:unrelated:idp" },
		"audience": func(a *saml.Assertion) { a.Conditions.AudienceRestrictions[0].Audience.Value = "urn:unrelated:sp" },
		"expiry":   func(a *saml.Assertion) { a.Conditions.NotOnOrAfter = time.Now().Add(-time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			rejected(send(peer, issue(adjust), origin, "", "document"), "invalid_saml_response")
		})
	}
	results := make(chan portalResponse, 2)
	gate := make(chan struct{})
	for _, handler := range []http.Handler{node, peer} {
		go func() { <-gate; results <- send(handler, proof, origin, "", "document") }()
	}
	close(gate)
	one, two := <-results, <-results
	if one.session == nil {
		one, two = two, one
	}
	if one.session == nil || one.status != 302 || one.location != home+"/company-portal" {
		t.Fatalf("no authorized session redirect: %d %s", one.status, one.location)
	}
	rejected(two, "replay_detected")
	if returned := send(existingOnly, issue(nil), origin, "", "document"); returned.session == nil || returned.location != home+"/company-portal" {
		t.Fatal("existing enterprise account could not return with implicit signup disabled", returned.status)
	}

	view := httptest.NewRequest("GET", home+"/identity/get-session", nil)
	view.AddCookie(one.session)
	w := httptest.NewRecorder()
	peer.ServeHTTP(w, view)
	var who struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if w.Code != 200 || json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&who) != nil || who.User.Email != "portal@staff.example" {
		t.Fatal("portal session is not visible on the second replica")
	}
}
