package sqlstore

import (
	"crypto"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/crewjam/saml"
)

// SAML single logout's records run the verification hooks on SQLite,
// PostgreSQL and MySQL, outside the store's transactions: a sign-in's logout
// binding is created after the session's before hooks and before its after
// hooks run, renewal runs its update after hooks, SP-initiated logout creates
// a logout request and removes the binding in one pass, the IdP's response
// spends the request, and an IdP-initiated logout removes every binding it
// ends. withHooks swaps in nodes that run hooks and returns them with a
// function that restores the earlier ones.
func testSAMLLogoutHooks(t *testing.T, first, second *Store, idp *saml.IdentityProvider, api string, newBrowser func() *http.Client, sdk func(*http.Client) *client.Client,
	login func(*testing.T, *http.Client, string, func(*saml.Assertion)), withHooks func(auth.DatabaseHooks) (http.Handler, http.Handler, func())) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	log := newHookLog(t, first, second)
	node, peer, restore := withHooks(log.hooks())
	defer restore()
	const (
		bindingCreate  = "v-create-before:saml-logout-session"
		bindingCreated = "v-create-after:saml-logout-session"
		bindingDelete  = "v-delete-before:saml-logout-session"
		bindingDeleted = "v-delete-after:saml-logout-session"
		requestCreate  = "v-create-before:saml-logout-request"
		requestCreated = "v-create-after:saml-logout-request"
		requestSpend   = "v-delete-before:saml-logout-request"
		requestSpent   = "v-delete-after:saml-logout-request"
	)
	bindings := func() int {
		t.Helper()
		var n int
		must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier"='saml-logout-session'`)).Scan(&n))
		return n
	}
	row := func(id string) (time.Time, bool) {
		t.Helper()
		var expires time.Time
		err := first.db.QueryRowContext(ctx, first.bind(`SELECT "expiresAt" FROM "verification" WHERE "id"=?`), id).Scan(&expires)
		return expires, err == nil
	}
	// only keeps the events of the records under test.
	only := func(got []string) []string {
		var out []string
		for _, e := range got {
			if strings.Contains(e, "saml-logout") || strings.HasPrefix(e, "session-") {
				out = append(out, e)
			}
		}
		return out
	}
	name := func(value string) saml.NameID {
		return saml.NameID{Value: value, Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: "hook-qualifier", SPNameQualifier: "hook-sp-qualifier"}
	}
	signin := func(id saml.NameID, index string) (*http.Client, *auth.SessionResult) {
		t.Helper()
		h := newBrowser()
		login(t, h, id.Value, func(a *saml.Assertion) { *a.Subject.NameID = id; a.AuthnStatements[0].SessionIndex = index })
		s, e := sdk(h).GetSession(ctx)
		must(e)
		return h, s
	}
	get := func(h *http.Client, target string) (int, string) {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		must(e)
		res, e := h.Do(r)
		must(e)
		res.Body.Close()
		return res.StatusCode, res.Header.Get("Location")
	}
	// logout starts SP-initiated logout and returns the IdP's signed reply.
	logout := func(h *http.Client) (string, string) {
		t.Helper()
		target, e := sdk(h).StartSAMLLogout(ctx, "work", "/signed-out")
		must(e)
		r, e := http.NewRequest("GET", target, nil)
		must(e)
		req, e := saml.NewIdpLogoutRequest(idp, r)
		must(e)
		must(req.Validate())
		w := httptest.NewRecorder()
		must(req.WriteLogoutResponse(w, req.MakeLogoutResponse(saml.StatusSuccess)))
		return w.Header().Get("Location"), r.URL.Query().Get("RelayState")
	}

	// The binding's hooks follow the user and session hooks once.
	before := bindings()
	var seen []int
	log.setProbe(func(event string) {
		if event == bindingCreate || event == bindingCreated {
			seen = append(seen, bindings())
		}
	})
	h, s := signin(name("hooked-logout"), "hook-index")
	log.setProbe(nil)
	got, recs := log.drain()
	log.same(only(got), "session-before", bindingCreate, "session-after", bindingCreated)
	id := originDigest("sls-", s.Session.ID)
	expires, stored := row(id)
	var binding auth.VerificationRecord
	for _, r := range recs {
		if r.Identifier == "saml-logout-session" {
			binding = r
		}
	}
	if !stored || binding.ID != id || binding.UserID != s.User.ID || !binding.ExpiresAt.Equal(expires) || !expires.Equal(s.Session.ExpiresAt) || len(seen) != 2 || seen[0] != before || seen[1] != before+1 {
		t.Fatal("the binding's hooks saw", binding, "for the row", id, expires, "while the binding rows were", seen)
	}
	log.clean(recs, "hooked-logout", "hook-index", "hook-qualifier", s.Session.ID, s.Session.Token)
	// Renewing the session runs the binding's update after hooks with the
	// new expiry.
	_, e := first.db.ExecContext(ctx, first.bind(`UPDATE "session" SET "expiresAt"=? WHERE "id"=?`), first.date(time.Now().Add(6*24*time.Hour-time.Hour)), s.Session.ID)
	must(e)
	_, e = first.db.ExecContext(ctx, first.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "id"=?`), first.date(time.Now().Add(6*24*time.Hour-time.Hour)), id)
	must(e)
	renewed, e := sdk(h).GetSession(ctx)
	must(e)
	got, recs = log.drain()
	log.same(only(got), "v-update-after:saml-logout-session")
	if expires, _ := row(id); len(recs) != 1 || recs[0].ID != id || !recs[0].ExpiresAt.Equal(expires) || !expires.Equal(renewed.Session.ExpiresAt) {
		t.Fatal("the renewal's update hook saw", recs, "for the renewed expiry", expires, renewed.Session.ExpiresAt)
	}

	// SP-initiated logout creates the request and removes the binding in one
	// pass; the IdP's response spends the request.
	reply, state := logout(h)
	got, recs = log.drain()
	log.same(only(got), requestCreate, bindingDelete, requestCreated, bindingDeleted)
	if _, stored := row(id); stored {
		t.Fatal("logout kept the binding")
	}
	log.clean(recs, state, "work", "hooked-logout")
	if status, location := get(h, reply); status != 302 || !strings.HasSuffix(location, "/signed-out") {
		t.Fatal("the logout response answered", status, location)
	}
	got, _ = log.drain()
	log.same(only(got), requestSpend, requestSpent)

	// A declined logout response keeps the request and its cookie.
	h, _ = signin(name("hooked-kept"), "hook-index")
	log.drain()
	reply, state = logout(h)
	log.drain()
	log.set(log.skip, requestSpend, true)
	status, _ := get(h, reply)
	log.set(log.skip, requestSpend, false)
	got, _ = log.drain()
	log.same(only(got), requestSpend)
	if _, stored := row(originDigest("slr-", state)); status != 400 || !stored {
		t.Fatal("a declined logout response answered", status, "and spent its request")
	}
	if status, _ := get(h, reply); status != 302 {
		t.Fatal("the kept request did not complete logout", status)
	}
	log.drain()

	// A declined logout request signs out, and its response answers 400.
	h, s = signin(name("hooked-unstored"), "hook-index")
	log.drain()
	log.set(log.skip, requestCreate, true)
	reply, state = logout(h)
	log.set(log.skip, requestCreate, false)
	got, _ = log.drain()
	log.same(only(got), requestCreate, bindingDelete, bindingDeleted)
	if _, stored := row(originDigest("slr-", state)); stored {
		t.Fatal("a declined logout request was stored")
	}
	if _, _, e := second.Session(ctx, s.Session.Token); e == nil {
		t.Fatal("a declined logout request kept the session")
	}
	if status, _ := get(h, reply); status != 400 {
		t.Fatal("the response to a declined logout request answered", status)
	}
	got, _ = log.drain()
	log.same(only(got))
	// A declined binding at logout stays stored, and the session still ends.
	h, s = signin(name("hooked-binding-kept"), "hook-index")
	log.drain()
	log.set(log.skip, bindingDelete, true)
	logout(h)
	log.set(log.skip, bindingDelete, false)
	log.drain()
	if _, stored := row(originDigest("sls-", s.Session.ID)); !stored {
		t.Fatal("a declined binding was removed")
	}
	if _, _, e := second.Session(ctx, s.Session.Token); e == nil {
		t.Fatal("a declined binding kept its session")
	}
	// A declined binding at sign-in signs in without single logout.
	log.set(log.skip, bindingCreate, true)
	h, s = signin(name("hooked-no-binding"), "hook-index")
	log.set(log.skip, bindingCreate, false)
	got, _ = log.drain()
	log.same(only(got), "session-before", bindingCreate, "session-after")
	if _, stored := row(originDigest("sls-", s.Session.ID)); stored {
		t.Fatal("a declined binding was stored")
	}
	if _, e := sdk(h).StartSAMLLogout(ctx, "work", "/signed-out"); e == nil {
		t.Fatal("a session without a binding started SAML logout")
	}
	log.drain()

	// Concurrent LogoutResponses for one request run one delete after hook.
	h, _ = signin(name("hooked-race"), "hook-index")
	reply, _ = logout(h)
	log.drain()
	cookies := h.Jar.Cookies(mustTestURL(t, reply))
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for _, handler := range []http.Handler{node, peer} {
		wg.Go(func() {
			r := httptest.NewRequest("GET", reply, nil)
			for _, c := range cookies {
				r.AddCookie(c)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			statuses <- w.Code
		})
	}
	wg.Wait()
	close(statuses)
	codes := map[int]int{}
	for status := range statuses {
		codes[status]++
	}
	spends := 0
	got, _ = log.drain()
	for _, e := range got {
		if e == requestSpent {
			spends++
		}
	}
	if codes[302] != 1 || codes[400] != 1 || spends != 1 {
		t.Fatal("two concurrent logout responses answered", codes, "with", spends, "spends")
	}

	// An IdP logout runs every binding's delete hooks in one pass.
	shared := name("hooked-idp")
	_, a := signin(shared, "idp-hook-index")
	_, b := signin(shared, "idp-hook-index")
	log.drain()
	path := api + "/sso/saml2/sp/slo/work"
	signer := &saml.ServiceProvider{Key: idp.Key.(crypto.Signer), Certificate: idp.Certificate, SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
	request := func() string {
		t.Helper()
		n := shared
		r := &saml.LogoutRequest{ID: "_" + rand.Text(), Version: "2.0", IssueInstant: time.Now().UTC(), Destination: path, Issuer: &saml.Issuer{Value: idp.MetadataURL.String()}, NameID: &n, SessionIndex: &saml.SessionIndex{Value: "idp-hook-index"}}
		u, e := signer.RedirectLogoutRequestURL(r, "")
		must(e)
		return path + "?" + u.RawQuery
	}
	target := request()
	if status, _ := get(newBrowser(), target); status != 302 {
		t.Fatal("the IdP logout answered", status)
	}
	got, recs = log.drain()
	log.same(only(got), bindingDelete, bindingDelete, bindingDeleted, bindingDeleted)
	for _, s := range []*auth.SessionResult{a, b} {
		if _, _, e := second.Session(ctx, s.Session.Token); e == nil {
			t.Fatal("the IdP logout kept a session")
		}
	}
	log.clean(recs, "hooked-idp", "idp-hook-index", "hook-qualifier")
	// A replayed LogoutRequest runs no hooks.
	if status, _ := get(newBrowser(), target); status != 400 {
		t.Fatal("a replayed IdP logout answered", status)
	}
	got, _ = log.drain()
	log.same(only(got))
	// A declined binding still has its session ended, and stays stored.
	_, c := signin(shared, "idp-hook-index")
	log.drain()
	log.set(log.skip, bindingDelete, true)
	if status, _ := get(newBrowser(), request()); status != 302 {
		t.Fatal("the IdP logout answered", status)
	}
	log.set(log.skip, bindingDelete, false)
	got, _ = log.drain()
	log.same(only(got), bindingDelete)
	if _, stored := row(originDigest("sls-", c.Session.ID)); !stored {
		t.Fatal("a declined binding was removed")
	}
	if _, _, e := second.Session(ctx, c.Session.Token); e == nil {
		t.Fatal("a declined binding kept its session")
	}
}
