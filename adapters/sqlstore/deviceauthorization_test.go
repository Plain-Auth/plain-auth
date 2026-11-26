package sqlstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/deviceauthorization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestDeviceAuthorizationFlow(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := organizationTestDSN(t, dialect)
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"device-authorization"})
			if err != nil {
				t.Fatal(err)
			}
			origin := "https://device.example"
			var requested []string // client|scope pairs given to OnDeviceAuthRequest
			opts := deviceauthorization.Options{VerificationURI: "/activate?from=tv", ValidateClient: func(_ context.Context, c string) (bool, error) { return c == "tv" || c == "cli", nil }, OnDeviceAuthRequest: func(_ context.Context, client, scope string) error {
				requested = append(requested, client+"|"+scope)
				return nil
			}}
			var stores []*Store
			open := func(opts deviceauthorization.Options, limit bool) *authn.Auth {
				t.Helper()
				store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				stores = append(stores, store)
				t.Cleanup(func() { store.Close() })
				p, err := deviceauthorization.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				a, err := authn.New(authn.Options{BaseURL: origin, Secret: strings.Repeat("d", 32), EmailAndPassword: true, Plugins: []authn.Plugin{p}, Store: store, RateLimit: &limit})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			first, second := open(opts, false), open(opts, false)
			signup := func(id string) (authn.User, *http.Cookie) {
				t.Helper()
				res, err := first.SignUpEmail(ctx, authn.SignUpInput{Name: id, Email: id + "@test.example", Password: "a local password"}, authn.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return res.User, first.SessionCookie(res.Token, true)
			}
			user, owner := signup("alice")
			_, other := signup("bob")
			type response struct {
				status int
				data   map[string]any
				header http.Header
			}
			send := func(a *authn.Auth, method, path, body, mt string, c *http.Cookie) response {
				r := httptest.NewRequest(method, origin+"/api/auth"+path, strings.NewReader(body))
				r.Header.Set("Content-Type", mt)
				r.Header.Set("Origin", origin)
				if c != nil {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var data map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &data)
				return response{w.Code, data, w.Header()}
			}
			check := func(r response, want int, code string) {
				t.Helper()
				if r.status != want || code != "" && (r.data["error"] != code || r.data["error_description"] == nil) {
					t.Fatalf("got %d %v, want %d %s", r.status, r.data, want, code)
				}
			}
			refuse := func(r response, want int, code, description string) {
				t.Helper()
				check(r, want, code)
				if r.data["error_description"] != description {
					t.Fatalf("got description %v, want %q", r.data["error_description"], description)
				}
			}
			const form = "application/x-www-form-urlencoded"
			issue := func(a *authn.Auth, suffix string) (device, user string) {
				t.Helper()
				r := send(a, "POST", "/device/code", "client_id=tv&scope=read+profile"+suffix, form, nil)
				check(r, 200, "")
				device, _ = r.data["device_code"].(string)
				user, _ = r.data["user_code"].(string)
				if device == "" || user == "" || r.data["verification_uri_complete"] != origin+"/activate?from=tv&user_code="+url.QueryEscape(user) || r.data["interval"] != float64(5) || r.data["expires_in"] != float64(1800) || r.header.Get("Cache-Control") != "no-store" {
					t.Fatalf("invalid device issue response %v", r.data)
				}
				if r.data["verification_uri"] != origin+"/activate?from=tv" || r.header.Get("Pragma") != "no-cache" {
					t.Fatalf("device code response lost its verification URI or Pragma header: %v %v", r.data, r.header)
				}
				return device, user
			}
			poll := func(a *authn.Auth, d, c string) response {
				return send(a, "POST", "/device/token", url.Values{"grant_type": {authn.DeviceGrantType}, "device_code": {d}, "client_id": {c}}.Encode(), form, nil)
			}
			verify := func(a *authn.Auth, code string, c *http.Cookie) response {
				return send(a, "GET", "/device?user_code="+url.QueryEscape(code), "", "", c)
			}
			decide := func(a *authn.Auth, action, code string, c *http.Cookie) response {
				b, _ := json.Marshal(map[string]string{"userCode": code})
				return send(a, "POST", "/device/"+action, string(b), "application/json", c)
			}
			check(send(first, "POST", "/device/code", "client_id=tv&client_id=cli", form, nil), 400, "invalid_request")
			check(send(first, "POST", "/device/code", "client_id=no", form, nil), 400, "invalid_client")
			// A code request needs a client ID; an omitted or empty one is refused before the callback.
			for _, body := range []string{"scope=read", "client_id=&scope=read"} {
				refuse(send(first, "POST", "/device/code", body, form, nil), 400, "invalid_request", "client_id is required")
			}
			refuse(send(first, "POST", "/device/code", `{"scope":"read"}`, "application/json", nil), 400, "invalid_request", "client_id is required")
			d, u := issue(first, "&user_id=&client_id=")
			if len(d) != 40 || len(u) != 8 || !slices.Equal(requested, []string{"tv|read profile"}) {
				t.Fatal("device generation defaults or request callback changed", requested)
			}
			check(send(first, "POST", "/device/code", `{"client_id":"cli"}`, "application/json", nil), 200, "")
			if !slices.Equal(requested, []string{"tv|read profile", "cli|"}) {
				t.Fatalf("OnDeviceAuthRequest got %q, want the accepted client and scope of each accepted code request", requested)
			}
			// Malformed token requests are refused before the client check and leave the polling timer alone.
			for _, body := range []url.Values{{"device_code": {d}, "client_id": {"tv"}}, {"grant_type": {"authorization_code"}, "device_code": {d}, "client_id": {"invalid"}}, {"grant_type": {authn.DeviceGrantType}, "client_id": {"tv"}}} {
				refuse(send(first, "POST", "/device/token", body.Encode(), form, nil), 400, "invalid_request", "A device code and device grant type are required")
			}
			refuse(send(first, "POST", "/device/token", url.Values{"grant_type": {authn.DeviceGrantType}, "device_code": {d}}.Encode(), form, nil), 400, "invalid_request", "client_id is required")
			check(poll(first, d, "invalid"), 400, "invalid_client")
			check(poll(first, d, "cli"), 400, "invalid_grant")
			check(poll(first, d, "tv"), 400, "authorization_pending")
			check(poll(second, d, "tv"), 400, "slow_down")
			check(decide(first, "approve", u, nil), 401, "unauthorized")
			check(decide(first, "approve", u, owner), 400, "invalid_request")
			refuse(decide(first, "deny", u, nil), 401, "unauthorized", "Authentication required")
			refuse(decide(first, "deny", u, owner), 400, "invalid_request", "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying")
			// 0 is outside the default alphabet, so this code can match no issued grant.
			refuse(decide(first, "approve", "0000-0000", owner), 400, "invalid_request", "Invalid user code")
			refuse(decide(first, "deny", "0000-0000", owner), 400, "invalid_request", "Invalid user code")
			anonymous := verify(first, u, nil)
			check(anonymous, 200, "")
			if len(anonymous.data) != 2 {
				t.Fatal("anonymous reviewer saw private grant metadata")
			}
			refuse(send(first, "GET", "/device", "", "", nil), 400, "invalid_request", "Invalid user code")
			display := strings.ToLower(u[:4] + "-" + u[4:])
			mine := verify(second, display, owner)
			check(mine, 200, "")
			if mine.data["scope"] != "read profile" || mine.data["client_id"] != "tv" {
				t.Fatal("owner did not see request context")
			}
			stranger := verify(first, u, other)
			check(stranger, 200, "")
			if len(stranger.data) != 2 {
				t.Fatal("non-owner saw private grant metadata")
			}
			check(decide(first, "deny", u, other), 403, "access_denied")
			check(decide(first, "approve", u, owner), 200, "")
			check(decide(second, "deny", u, owner), 400, "invalid_request")
			refuse(decide(second, "approve", u, owner), 400, "invalid_request", "Device code already processed")
			if _, err := stores[0].db.ExecContext(ctx, stores[0].bind(`UPDATE "deviceCode" SET "lastPolledAt"=? WHERE "deviceCode"=?`), stores[0].date(time.Now().Add(-time.Minute)), d); err != nil {
				t.Fatal(err)
			}
			out := make(chan response, 2)
			for _, a := range []*authn.Auth{first, second} {
				go func() { out <- poll(a, d, "tv") }()
			}
			a, b := <-out, <-out
			if b.status == 200 {
				a, b = b, a
			}
			check(a, 200, "")
			check(b, 400, "invalid_grant")
			token, _ := a.data["access_token"].(string)
			if token == "" || a.data["scope"] != "read profile" || a.data["token_type"] != "Bearer" || a.data["expires_in"].(float64) < 1 || a.header.Get("Set-Cookie") != "" || a.header.Get("Pragma") != "no-cache" {
				t.Fatal("invalid bearer response")
			}
			if a.header.Get("Cache-Control") != "no-store" {
				t.Fatal("device token response is cacheable")
			}
			ss, _, err := stores[1].Session(ctx, token)
			if err != nil || ss.UserID != user.ID {
				t.Fatalf("device session was not bound to approving owner: %v", err)
			}
			d, u = issue(second, "&user_id="+user.ID)
			premature := verify(first, u, other)
			if len(premature.data) != 2 {
				t.Fatal("pre-bound grant leaked owner metadata")
			}
			check(decide(first, "approve", u, other), 403, "access_denied")
			check(decide(first, "deny", u, owner), 200, "")
			refuse(decide(first, "approve", u, owner), 400, "invalid_request", "Device code already processed")
			refuse(decide(second, "deny", u, owner), 400, "invalid_request", "Device code already processed")
			check(poll(second, d, "tv"), 400, "access_denied")
			check(poll(second, d, "tv"), 400, "invalid_grant")
			d, u = issue(first, "")
			if _, err := stores[0].db.ExecContext(ctx, stores[0].bind(`UPDATE "deviceCode" SET "expiresAt"=? WHERE "deviceCode"=?`), stores[0].date(time.Now().Add(-time.Second)), d); err != nil {
				t.Fatal(err)
			}
			check(verify(second, u, owner), 400, "expired_token")
			for _, action := range []string{"approve", "deny"} {
				refuse(decide(first, action, u, owner), 400, "expired_token", "User code has expired")
			}
			check(poll(second, d, "tv"), 400, "expired_token")
			check(poll(first, d, "tv"), 400, "invalid_grant")
			d, u = issue(first, "")
			_ = d
			go func() { out <- verify(first, u, owner) }()
			go func() { out <- verify(second, u, other) }()
			a, b = <-out, <-out
			check(a, 200, "")
			check(b, 200, "")
			if (a.data["scope"] == nil) == (b.data["scope"] == nil) {
				t.Fatal("claim race must disclose grant details to exactly one owner")
			}
			// Default codes accept lower case, whitespace and punctuation at every browser route.
			spaced := func(code string) string {
				return " \t" + strings.ToLower(code[:2]) + "-" + code[2:4] + "." + code[4:] + " \n"
			}
			for action, status := range map[string]string{"approve": "approved", "deny": "denied"} {
				_, code := issue(first, "")
				check(verify(second, spaced(code), owner), 200, "")
				check(decide(first, action, spaced(code), owner), 200, "")
				if got := verify(second, code, owner); got.data["status"] != status {
					t.Fatalf("formatted %s recorded %v, want %s", action, got.data["status"], status)
				}
			}
			// Two 191-character default codes give 382 samples, which would almost surely include 0, O, 1 or I if they were allowed.
			long := opts
			long.UserCodeLength = 191
			wide := open(long, false)
			for range 2 {
				_, code := issue(wide, "")
				if len(code) != 191 || strings.ContainsFunc(code, func(r rune) bool { return !strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", r) }) {
					t.Fatalf("default user code used a character outside the alphabet: %q", code)
				}
			}
			// Protect OAuth client grants in a mixed-schema installation, including after a running migration.
			if _, err := stores[0].db.ExecContext(ctx, stores[0].bind(`ALTER TABLE "deviceCode" ADD COLUMN "oauthClientId" text`)); err != nil {
				t.Fatal(err)
			}
			d, u = issue(second, "&user_id="+user.ID)
			if _, err := stores[0].db.ExecContext(ctx, stores[0].bind(`UPDATE "deviceCode" SET "oauthClientId"=?, "status"='approved' WHERE "deviceCode"=?`), "external", d); err != nil {
				t.Fatal(err)
			}
			check(poll(first, d, "tv"), 400, "invalid_grant")
			check(verify(second, u, owner), 400, "invalid_grant")
			fixed := opts
			var attempts atomic.Int32
			fixed.GenerateDeviceCode = func(context.Context) (string, error) { attempts.Add(1); return "device-With-cAsE", nil }
			fixed.GenerateUserCode = func(context.Context) (string, error) { return "My+code@", nil }
			limited := open(fixed, true)
			d, u = issue(limited, "")
			check(poll(limited, strings.ToUpper(d), "tv"), 400, "invalid_grant")
			check(verify(limited, strings.ToLower(u), owner), 400, "invalid_request")
			check(verify(limited, u, owner), 200, "")
			refuse(send(limited, "POST", "/device/code", "client_id=tv", form, nil), 500, "server_error", "Failed to generate a unique device code")
			if attempts.Load() != 4 {
				t.Fatalf("made %d device code attempts, want one for the first code and three for the colliding request", attempts.Load())
			}
			for range 3 {
				check(verify(limited, u, owner), 200, "")
			}
			check(verify(limited, u, owner), 429, "")
		})
	}
}
