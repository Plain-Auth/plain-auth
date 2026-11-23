package polar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/bearer"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/google/uuid"
	polargo "github.com/polarsource/polar-go"
)

const portalURL = "https://billing.example.test/fixture/portal"
const portalToken = "polar_cst_fixture_token"
const providerSecret = "merchant-internal-fixture"

func readPersonal(h http.Handler, method, path, body string, cookie *http.Cookie, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, host+"/api/auth"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for k, vs := range headers {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// This transport models Polar's versioned wire objects independently from the generated Go structs.
type portalProvider struct {
	t       *testing.T
	names   map[string]string
	mutate  func(map[string]any, map[string]any)
	during  func()
	missing bool
	failed  bool
	calls   int
}

func (p *portalProvider) Do(req *http.Request) (*http.Response, error) {
	p.t.Helper()
	p.calls++
	if req.Header.Get("Authorization") != "Bearer fixture" || req.Header.Get("Polar-Version") != "2026-10" {
		return nil, errors.New("invalid provider authorization or version")
	}
	owner := ""
	portal := req.Method == "POST" && req.URL.Path == "/v1/customer-sessions/"
	switch {
	case portal:
		var payload map[string]any
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			return nil, err
		}
		owner, _ = payload["external_customer_id"].(string)
		if len(payload) != 2 || payload["return_url"] != host+"/account" {
			return nil, errors.New("only the session external ID and configured return URL may be forwarded")
		}
	case req.Method == "GET" && strings.HasPrefix(req.URL.Path, "/v1/customers/external/") && strings.HasSuffix(req.URL.Path, "/state"):
		owner = strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/v1/customers/external/"), "/state")
	default:
		return nil, errors.New("unexpected provider endpoint")
	}
	name, ok := p.names[owner]
	if !ok || req.URL.RawQuery != "" {
		return nil, errors.New("unexpected customer selection")
	}
	now := time.Now().UTC()
	customerID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(owner)).String()
	token := portalToken + "-" + name
	person := map[string]any{
		"id": customerID, "external_id": owner, "email": name + "@example.test", "email_verified": true,
		"type": "individual", "organization_id": merchant, "created_at": now, "deleted_at": nil, "name": name,
		"metadata": map[string]string{"merchant_note": providerSecret}, "avatar_url": "https://avatars.example.test/1",
	}
	var response map[string]any
	status := 200
	if portal {
		status = 201
		target := url.Values{"customer_session_token": {token}, "email": {name + "@example.test"}}
		response = map[string]any{
			"id": "4ffb29e3-05df-4096-984a-ffdd76e534ea", "customer_id": customerID, "customer": person,
			"created_at": now, "expires_at": now.Add(time.Hour), "return_url": host + "/account", "token": token,
			"customer_portal_url": portalURL + "?" + target.Encode(),
		}
	} else {
		response = person
		person["active_subscriptions"] = []map[string]any{
			{"id": "73766bd0-60a3-4eac-94f4-dffb7a5c5aff", "created_at": now, "metadata": map[string]string{"merchant_note": providerSecret}, "status": "active", "amount": 1000,
				"currency": "usd", "recurring_interval": "month", "current_period_start": now, "current_period_end": now.Add(24 * time.Hour),
				"cancel_at_period_end": false, "product_id": otherProduct, "meters": []any{}},
		}
		person["granted_benefits"] = []map[string]any{
			{"id": "3027544d-9cc3-4f25-bff9-27478514f391", "created_at": now, "granted_at": now, "benefit_id": "41b2b61b-bec8-4a70-ba07-d4dbe85fd399", "benefit_type": "custom",
				"benefit_metadata": map[string]string{"merchant_note": providerSecret}, "properties": map[string]string{}},
		}
		person["active_meters"] = []map[string]any{
			{"id": "96783985-fca5-40fb-8367-91258e087615", "created_at": now, "meter_id": "60352a5a-2768-4016-97b8-315f585a9a6f", "consumed_units": 2.5, "credited_units": 4, "balance": 1.5},
		}
	}
	if p.mutate != nil {
		p.mutate(person, response)
	}
	if p.during != nil {
		p.during()
	}
	if p.missing {
		status = 404
		response = map[string]any{"error": "ResourceNotFound", "detail": providerSecret}
	}
	if p.failed {
		status = 422
		response = map[string]any{"error": "RequestValidationError", "detail": providerSecret}
	}
	out, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(out)), Request: req}, nil
}

func TestPersonalPortalAndCustomerState(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, dsn := database(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"anonymous", "admin"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := sqlstore.OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			ledger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			provider := &portalProvider{t: t, names: map[string]string{}}
			opts := Options{
				Client: polargo.New(polargo.WithSecurity("fixture"), polargo.WithClient(provider)),
				Ledger: ledger, OrganizationID: merchant, Products: map[string]string{"pro": product}, HostedOrigin: hosted, SuccessURL: "/success", WebhookSecret: dashboardSecret,
			}
			node := func(opts Options) *auth.Auth {
				t.Helper()
				plugin, err := New(opts)
				if err != nil {
					t.Fatal(err)
				}
				a, err := auth.New(auth.Options{Secret: strings.Repeat("p", 40), Store: store, EmailAndPassword: true, BaseURL: host, Plugins: []auth.Plugin{plugin, bearer.New(bearer.Options{RequireSignature: true})}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			disabled := node(opts)
			expect(t, readPersonal(disabled, "GET", "/customer/state", "", nil, nil), 404)
			expect(t, readPersonal(disabled, "POST", "/customer/portal", "{}", nil, nil), 404)
			for _, cfg := range []PortalOptions{{URL: "http://test/portal"}, {URL: portalURL + "?token=x"}, {URL: portalURL, Theme: "other"}} {
				opts.Portal = &cfg
				if _, err := NewService(opts); err == nil {
					t.Fatal("invalid portal configuration accepted")
				}
			}
			opts.Portal = &PortalOptions{URL: portalURL, ReturnURL: "/account", Theme: "dark"}
			a := node(opts)
			exec := func(q string, args ...any) {
				t.Helper()
				if dialect == "mysql" {
					q = strings.ReplaceAll(q, "\"", string(rune(96)))
				}
				if _, err := db.ExecContext(ctx, ledger.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			signup := func(name string) (string, *http.Cookie) {
				t.Helper()
				v, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "fixture-password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				provider.names[v.User.ID] = name
				return v.User.ID, a.SessionCookie(v.Token, true)
			}
			aliceID, alice := signup("alice")
			bobID, bob := signup("bob")
			same := http.Header{"Sec-Fetch-Site": {"same-origin"}}
			origin := http.Header{"Origin": {host}}
			for _, path := range []string{"/customer/portal", "/customer/state"} {
				expect(t, readPersonal(a, "GET", path, "", nil, same), 401)
				expect(t, readPersonal(a, "GET", path, "", alice, same), 403)
			}
			exec(`UPDATE "user" SET "emailVerified"=TRUE`)
			for _, path := range []string{"/customer/portal", "/customer/state"} {
				expect(t, readPersonal(a, "GET", path+"?organizationId="+bobID, "", alice, same), 400)
				expect(t, readPersonal(a, "GET", path+"?external_customer_id="+bobID, "", alice, same), 400)
				exec(`UPDATE "session" SET "impersonatedBy"=? WHERE "userId"=?`, bobID, aliceID)
				expect(t, readPersonal(a, "GET", path, "", alice, same), 403)
				exec(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "userId"=?`, aliceID)
				exec(`UPDATE "user" SET "isAnonymous"=TRUE WHERE "id"=?`, aliceID)
				expect(t, readPersonal(a, "GET", path, "", alice, same), 403)
				exec(`UPDATE "user" SET "isAnonymous"=FALSE WHERE "id"=?`, aliceID)
			}
			expect(t, readPersonal(a, "POST", "/customer/portal", `{"returnUrl":"https://elsewhere.test"}`, alice, origin), 400)
			expect(t, readPersonal(a, "GET", "/customer/portal", "", alice, http.Header{"Sec-Fetch-Site": {"cross-site"}, "Origin": {"https://elsewhere.test"}}), 403)
			if provider.calls != 0 {
				t.Fatal("untrusted personal billing request reached the provider")
			}
			for _, tc := range []struct {
				method, body string
				redirect     bool
			}{
				{"GET", "", true}, {"POST", `{"redirect":false}`, false},
			} {
				h := same
				if tc.method == "POST" {
					h = origin
				}
				rec := readPersonal(a, tc.method, "/customer/portal", tc.body, alice, h)
				var wire struct {
					URL      string `json:"url"`
					Redirect bool   `json:"redirect"`
				}
				got := expect(t, rec, 200)
				if err := json.Unmarshal([]byte(got), &wire); err != nil {
					t.Fatal(err)
				}
				u, err := url.Parse(wire.URL)
				if err != nil || u.Host != "billing.example.test" || u.Query().Get("theme") != "dark" || u.Query().Get("customer_session_token") != portalToken+"-alice" ||
					wire.Redirect != tc.redirect || strings.Contains(got, providerSecret) || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("invalid private portal handoff")
				}
			}
			signed, _ := url.PathUnescape(bob.Value)
			bearerResult := readPersonal(a, "GET", "/customer/portal", "", nil, http.Header{"Authorization": {"Bearer " + signed}})
			if got := expect(t, bearerResult, 200); !strings.Contains(got, portalToken+"-bob") || strings.Contains(got, portalToken+"-alice") {
				t.Fatal("signed bearer received another customer's portal")
			}
			for owner, cookie := range map[string]*http.Cookie{aliceID: alice, bobID: bob} {
				rec := readPersonal(a, "GET", "/customer/state", "", cookie, same)
				raw := expect(t, rec, 200)
				var state CustomerState
				if err := json.Unmarshal([]byte(raw), &state); err != nil {
					t.Fatal(err)
				}
				if state.ExternalID != owner || state.OrganizationID != merchant || len(state.ActiveSubscriptions) != 1 || state.ActiveSubscriptions[0].ProductID != otherProduct ||
					len(state.GrantedBenefits) != 1 || state.GrantedBenefits[0].BenefitID != "41b2b61b-bec8-4a70-ba07-d4dbe85fd399" || len(state.ActiveMeters) != 1 || state.ActiveMeters[0].Balance != 1.5 ||
					strings.Contains(raw, providerSecret) || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("owner-scoped subscription, benefit and meter summary leaked or lost data")
				}
			}
			provider.mutate = func(person, res map[string]any) {
				for _, field := range []string{"active_subscriptions", "granted_benefits", "active_meters"} {
					person[field] = []any{}
				}
			}
			emptyState := expect(t, readPersonal(a, "GET", "/customer/state", "", alice, same), 200)
			for _, field := range []string{"active_subscriptions", "granted_benefits", "active_meters"} {
				if !strings.Contains(emptyState, `"`+field+`":[]`) {
					t.Fatal("a fresh personal customer lost an empty billing collection")
				}
			}
			tests := []struct {
				name   string
				change func(map[string]any, map[string]any)
			}{
				{"external owner", func(person, res map[string]any) { person["external_id"] = bobID }},
				{"merchant", func(person, res map[string]any) { person["organization_id"] = otherProduct }},
				{"team", func(person, res map[string]any) { person["type"] = "team" }},
				{"deleted", func(person, res map[string]any) { person["deleted_at"] = time.Now().UTC() }},
			}
			for _, tc := range tests {
				provider.mutate = tc.change
				for _, path := range []string{"/customer/portal", "/customer/state"} {
					got := expect(t, readPersonal(a, "GET", path, "", alice, same), 502)
					if strings.Contains(got, portalToken) || strings.Contains(got, providerSecret) {
						t.Fatalf("%s exposed provider data", tc.name)
					}
				}
			}
			for key, value := range map[string]any{"customer_id": otherProduct, "return_url": host + "/wrong", "expires_at": time.Now().Add(-time.Minute), "customer_portal_url": portalURL + "?customer_session_token=another"} {
				provider.mutate = func(person, res map[string]any) { res[key] = value }
				expect(t, readPersonal(a, "GET", "/customer/portal", "", alice, same), 502)
			}
			provider.mutate = func(person, res map[string]any) {
				res["customer_portal_url"] = strings.Replace(res["customer_portal_url"].(string), "/fixture/", "/other-merchant/", 1)
			}
			expect(t, readPersonal(a, "GET", "/customer/portal", "", alice, same), 502)
			provider.mutate = nil
			provider.missing = true
			for _, path := range []string{"/customer/portal", "/customer/state"} {
				got := expect(t, readPersonal(a, "GET", path, "", alice, same), 404)
				if strings.Contains(got, providerSecret) {
					t.Fatal("provider response was returned verbatim")
				}
			}
			provider.missing = false
			provider.failed = true
			for _, path := range []string{"/customer/portal", "/customer/state"} {
				got := expect(t, readPersonal(a, "GET", path, "", alice, same), 502)
				if strings.Contains(got, providerSecret) {
					t.Fatal("provider validation details were leaked")
				}
			}
			provider.failed = false
			for i, path := range []string{"/customer/portal", "/customer/state"} {
				id, cookie := signup(fmt.Sprintf("revoked%d", i))
				exec(`UPDATE "user" SET "emailVerified"=TRUE WHERE "id"=?`, id)
				provider.during = func() { exec(`DELETE FROM "session" WHERE "userId"=?`, id) }
				got := expect(t, readPersonal(a, "GET", path, "", cookie, same), 401)
				if strings.Contains(got, portalToken) || strings.Contains(got, uuid.NewSHA1(uuid.NameSpaceOID, []byte(id)).String()) {
					t.Fatal("revoked session received portal credentials or state")
				}
			}
		})
	}
}
