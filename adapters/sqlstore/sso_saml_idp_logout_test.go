package sqlstore

import (
	"crypto"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/crewjam/saml"
)

func testSAMLIDPLogout(t *testing.T, first, peerStore *Store, idp *saml.IdentityProvider, api string, browser func() *http.Client, sdk func(*http.Client) *client.Client, login func(*testing.T, *http.Client, string, func(*saml.Assertion)), owner *client.Client, node, peer http.Handler, dns *dnsAnswers) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	name := saml.NameID{Value: "logout-user", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: "qualifier-one", SPNameQualifier: "qualifier-two", SPProvidedID: "opaque-id"}
	signin := func(name saml.NameID, index string) (*http.Client, string) {
		t.Helper()
		h := browser()
		login(t, h, name.Value, func(a *saml.Assertion) { *a.Subject.NameID = name; a.AuthnStatements[0].SessionIndex = index })
		out, e := sdk(h).GetSession(ctx)
		must(e)
		return h, out.Session.Token
	}
	alive := func(token string, want bool) {
		t.Helper()
		_, _, e := peerStore.Session(ctx, token)
		if want && e != nil || !want && !errors.Is(e, auth.ErrNotFound) {
			t.Fatal("incorrect local session state", want, e)
		}
	}
	path := api + "/sso/saml2/sp/slo/work"
	const alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	signer := &saml.ServiceProvider{Key: idp.Key.(crypto.Signer), Certificate: idp.Certificate, SignatureMethod: alg}
	newRequest := func() *saml.LogoutRequest {
		n := name
		return &saml.LogoutRequest{ID: "_" + rand.Text(), Version: "2.0", IssueInstant: time.Now().UTC(), Destination: path, Issuer: &saml.Issuer{Value: idp.MetadataURL.String()}, NameID: &n, SessionIndex: &saml.SessionIndex{Value: "index-one"}}
	}
	urlFor := func(r *saml.LogoutRequest, relay string) string {
		t.Helper()
		u, e := signer.RedirectLogoutRequestURL(r, relay)
		must(e)
		return path + "?" + u.RawQuery
	}
	send := func(h *http.Client, target string) (int, http.Header) {
		t.Helper()
		r, e := h.Get(target)
		must(e)
		r.Body.Close()
		return r.StatusCode, r.Header
	}
	_, a := signin(name, "index-one")
	targetBrowser, b := signin(name, "index-one")
	unrelated, c := signin(name, "index-two")
	qualified := name
	qualified.SPProvidedID = "OTHER"
	_, d := signin(qualified, "index-one")
	otherName := name
	otherName.Value = "logout-neighbor"
	_, otherUser := signin(otherName, "index-one")
	unchanged := func() {
		for _, token := range []string{a, b, c, d, otherUser} {
			alive(token, true)
		}
	}
	for _, adjust := range []func(*saml.LogoutRequest){
		func(r *saml.LogoutRequest) { r.SessionIndex = nil },
		func(r *saml.LogoutRequest) { r.AdditionalSessionIndexes = []saml.SessionIndex{{Value: "index-two"}} },
		func(r *saml.LogoutRequest) { r.Issuer.Value = "urn:unrelated-directory" },
		func(r *saml.LogoutRequest) { r.Destination = api + "/other" },
		func(r *saml.LogoutRequest) { r.IssueInstant = time.Now().Add(-time.Hour) },
		func(r *saml.LogoutRequest) { v := time.Now().Add(-time.Second); r.NotOnOrAfter = &v },
	} {
		r := newRequest()
		adjust(r)
		if status, _ := send(unrelated, urlFor(r, "")); status != 400 {
			t.Fatal("unexpected invalid request status", status)
		}
		unchanged()
	}
	plain := newRequest().Redirect("opaque")
	if status, _ := send(targetBrowser, plain.String()); status != 400 {
		t.Fatal("unsigned IdP request accepted")
	}
	unchanged()
	// Authorized no-match results do not reveal whether a particular identity is local.
	r := newRequest()
	r.NameID.SPNameQualifier = "another"
	if status, head := send(unrelated, urlFor(r, "")); status != 302 || len(head.Values("Set-Cookie")) != 0 {
		t.Fatal("no-match logout altered the caller", status)
	}
	unchanged()
	p, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: "work", Protocol: "saml"})
	must(e)
	// A second immutable registration uses the same issuer, certificate, NameID
	// and SessionIndex. Its login record still belongs to a distinct directory.
	const alternate = "parallel-logout"
	var alternateMetadata saml.EntityDescriptor
	must(xml.Unmarshal([]byte(idpDocument(t, idp.MetadataURL.String(), idp.SSOURL.String(), idp.Certificate)), &alternateMetadata))
	returnLocation := idp.LogoutURL.String() + "/reply"
	alternateMetadata.IDPSSODescriptors[0].SingleLogoutServices = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: idp.LogoutURL.String(), ResponseLocation: returnLocation}}
	metadata, e := xml.Marshal(alternateMetadata)
	must(e)
	alternateConfig := *p.SAML
	alternateConfig.IDPMetadata = sso.SAMLIDPMetadata{Metadata: string(metadata)}
	_, e = owner.RegisterSAMLProvider(ctx, client.RegisterSAMLProviderRequest{ProviderID: alternate, Domain: "other.example", Issuer: p.Issuer, SAML: alternateConfig})
	must(e)
	domainToken, e := owner.RequestSSODomainVerification(ctx, alternate)
	must(e)
	dns.put("_plain-auth-token-"+alternate+".other.example.", domainToken)
	must(owner.VerifySSODomain(ctx, alternate))
	alt, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: alternate, Protocol: "saml"})
	must(e)
	now := time.Now().UTC()
	altUser := auth.User{ID: rand.Text(), Name: "independent account", Email: "employee@other.example", CreatedAt: now, UpdatedAt: now}
	altSession := auth.StoredSession{Session: auth.Session{ID: rand.Text(), Token: rand.Text(), UserID: altUser.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	immutableIdentity := sso.SAMLLogoutIdentity{NameID: name, SessionIndex: "index-one"}
	_, _, e = first.CompleteSAMLLogin(ctx, alt.Reference, "", true, alternate, name.Value, sso.AssertionReceipt{Issuer: idp.MetadataURL.String(), ID: "_" + rand.Text(), Logout: &immutableIdentity}, altUser, altSession, auth.OAuthLoginOptions{})
	must(e)
	proof := sso.SAMLIDPLogout{ID: "_" + rand.Text(), ProviderID: "work", Reference: p.Reference, Issuer: idp.MetadataURL.String(), Identity: sso.SAMLLogoutIdentity{NameID: name, SessionIndex: "index-one"}, IssuedAt: time.Now()}
	// A node that only refreshes the application session must keep the SAML
	// binding live beyond the original sliding expiration.
	original, u, e := first.Session(ctx, a)
	must(e)
	short := time.Now().UTC().Truncate(time.Millisecond).Add(time.Hour)
	changed, e := peerStore.RefreshSession(ctx, a, original.ExpiresAt, time.Now(), short)
	must(e)
	if !changed {
		t.Fatal("session expiry not updated")
	}
	later := short.Add(2 * time.Hour)
	changed, e = peerStore.RefreshSession(ctx, a, short, short.Add(-time.Minute), later)
	must(e)
	if !changed {
		t.Fatal("sliding session not renewed")
	}
	if _, err := first.SAMLSessionForLogout(ctx, sso.Actor{UserID: u.ID, SessionID: original.ID, SessionToken: a}, "work", p.Reference, short.Add(time.Minute)); err != nil {
		t.Fatal("renewed SAML session lost its logout binding", err)
	}
	proofAtDeadline := proof
	deadline := time.Now().Add(180 * time.Millisecond)
	proofAtDeadline.NotOnOrAfter = &deadline
	holder, err := first.beginMembershipChange(ctx)
	must(err)
	if _, err = first.lockedLogoutProvider(ctx, holder, "work", p.Reference); err != nil {
		holder.Rollback()
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() {
		_, e := peerStore.RevokeSAMLIDPSessions(ctx, proofAtDeadline, c, false, time.Now())
		waiting <- e
	}()
	<-time.After(time.Until(deadline.Add(50 * time.Millisecond)))
	must(holder.Rollback())
	if e = <-waiting; !errors.Is(e, sso.ErrSAMLLogoutRequest) {
		t.Fatal("logout remained valid past its deadline while locked", e)
	}
	unchanged()
	wrong := proof
	wrong.Reference = "other-record"
	if _, e := peerStore.RevokeSAMLIDPSessions(ctx, wrong, c, false, time.Now()); !errors.Is(e, sso.ErrChanged) {
		t.Fatal("foreign directory accepted", e)
	}
	wrong = proof
	wrong.Issuer = "urn:old-authority"
	if _, e := peerStore.RevokeSAMLIDPSessions(ctx, wrong, c, false, time.Now()); !errors.Is(e, sso.ErrSAMLLogoutRequest) {
		t.Fatal("foreign issuer accepted", e)
	}
	flag := func(value bool) {
		_, e := first.db.ExecContext(ctx, first.bind(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`), value, p.ID)
		must(e)
	}
	flag(false)
	if _, e := peerStore.RevokeSAMLIDPSessions(ctx, proof, c, false, time.Now()); !errors.Is(e, sso.ErrDomainUnverified) {
		t.Fatal("unenrolled replica ignored the current domain proof", e)
	}
	flag(true)
	unchanged()
	r = newRequest()
	target := urlFor(r, "opaque return state")
	cookies := unrelated.Jar.Cookies(mustTestURL(t, target))
	type answer struct {
		status int
		head   http.Header
	}
	ch := make(chan answer, 2)
	gate := make(chan struct{})
	for _, handler := range []http.Handler{node, peer} {
		go func() {
			<-gate
			req := httptest.NewRequest("GET", target, nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			ch <- answer{w.Code, w.Header()}
		}()
	}
	close(gate)
	codes := []int{}
	for range 2 {
		out := <-ch
		codes = append(codes, out.status)
		if out.status == 302 {
			u := mustTestURL(t, out.head.Get("Location"))
			if u.Scheme+"://"+u.Host+u.Path != idp.LogoutURL.String() || u.Query().Get("SigAlg") != alg || u.Query().Get("Signature") == "" || u.Query().Get("RelayState") != "opaque return state" {
				t.Fatal("invalid signed acknowledgement")
			}
			if len(out.head.Values("Set-Cookie")) != 0 {
				t.Fatal("unrelated browser cookie was cleared")
			}
		}
	}
	slices.Sort(codes)
	if !slices.Equal(codes, []int{302, 400}) {
		t.Fatal("incoming logout replay race", codes)
	}
	alive(a, false)
	alive(b, false)
	alive(altSession.Token, true)
	for _, token := range []string{c, d, otherUser} {
		alive(token, true)
	}
	ret, e := owner.GetSession(ctx)
	must(e)
	if ret == nil {
		t.Fatal("directory owner's independent session was revoked")
	}
	local, latest := signin(name, "index-one")
	if status, _ := send(local, target); status != 400 {
		t.Fatal("replayed IdP request revoked a later login")
	}
	alive(latest, true)
	if status, head := send(local, urlFor(newRequest(), "")); status != 302 || !strings.Contains(strings.Join(head.Values("Set-Cookie"), ";"), "session_token=") {
		t.Fatal("revoked browser retained its cookie", status)
	}
	_, outOfBand := signin(name, "index-one")
	if status, head := send(browser(), urlFor(newRequest(), "")); status != 302 || len(head.Values("Set-Cookie")) != 0 {
		t.Fatal("cookie-free directory logout failed", status)
	}
	alive(outOfBand, false)
	alive(altSession.Token, true)
	// An imported directory may publish a separate same-origin ResponseLocation.
	r = newRequest()
	r.Destination = api + "/sso/saml2/sp/slo/" + alternate
	alternateTarget, e := signer.RedirectLogoutRequestURL(r, "opaque")
	must(e)
	status, head := send(browser(), alternateTarget.String())
	if status != 302 {
		t.Fatal("separate IdP response endpoint rejected", status)
	}
	next := mustTestURL(t, head.Get("Location"))
	if next.Scheme+"://"+next.Host+next.Path != returnLocation {
		t.Fatal("incorrect IdP ResponseLocation", next.Path)
	}
	alive(altSession.Token, false)
	alive(latest, false)
	alive(c, true)
}
