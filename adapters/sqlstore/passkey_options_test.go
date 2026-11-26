package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/go-webauthn/webauthn/protocol"
)

const passkeyPeerOrigin = "https://login.example.test"

// passkeyPeers are two auth instances on separate stores of one database, so
// a ceremony begun on first finishes on second.
type passkeyPeers struct {
	stores        [2]*Store
	first, second *auth.Auth
	owner         auth.AuthResult
	session       *http.Cookie
}

func newPasskeyPeers(t *testing.T, dialect string, plugin pk.Options, opts auth.Options) *passkeyPeers {
	t.Helper()
	ctx := t.Context()
	plugin.RPID, plugin.RPName, plugin.Origins = "example.test", "Test", []string{passkeyPeerOrigin}
	p, err := pk.New(plugin)
	if err != nil {
		t.Fatal(err)
	}
	ddl, err := schema.Generate(dialect, []string{"passkey"})
	if err != nil {
		t.Fatal(err)
	}
	dsn := organizationTestDSN(t, dialect)
	peers := &passkeyPeers{}
	for i := range peers.stores {
		s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		peers.stores[i] = s
	}
	off := false
	opts.Secret, opts.BaseURL, opts.EmailAndPassword, opts.RateLimit, opts.Plugins = "test-only-passkey-0123456789-abcdefgh", passkeyPeerOrigin, true, &off, []auth.Plugin{p}
	opts.Store = peers.stores[0]
	if peers.first, err = auth.New(opts); err != nil {
		t.Fatal(err)
	}
	opts.Store = peers.stores[1]
	if peers.second, err = auth.New(opts); err != nil {
		t.Fatal(err)
	}
	peers.owner, err = peers.first.SignUpEmail(ctx, auth.SignUpInput{Email: "owner@example.test", Name: "Owner", Password: "local sample passphrase"}, auth.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	peers.session = peers.first.SessionCookie(peers.owner.Token, true)
	return peers
}

// call sends one passkey request to server and fails unless it answers
// status. path is relative to /api/auth/passkey/ and may carry a query. A
// JSON array answer comes back under "items".
func (p *passkeyPeers) call(t *testing.T, server *auth.Auth, path string, payload any, status int, cookies ...*http.Cookie) (map[string]any, []*http.Cookie) {
	t.Helper()
	var body bytes.Buffer
	method := "GET"
	if payload != nil {
		method = "POST"
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, passkeyPeerOrigin+"/api/auth/passkey/"+path, &body)
	r.Header.Set("Origin", passkeyPeerOrigin)
	if payload != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("%s: got %d want %d: %s", path, w.Code, status, w.Body.String())
	}
	var out any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if items, ok := out.([]any); ok {
		return map[string]any{"items": items}, w.Result().Cookies()
	}
	return out.(map[string]any), w.Result().Cookies()
}

// Registration options advertise the configured attachment and resident-key
// requirement, the defaults when they are unset, and the attachment a
// request asks for; any other attachment is refused before the session is
// read.
func TestPasskeyAuthenticatorSelection(t *testing.T) {
	defaults := map[string]any{"residentKey": "preferred", "requireResidentKey": false, "userVerification": "preferred"}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range defaults {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	required := pk.AuthenticatorSelection{Attachment: protocol.CrossPlatform, ResidentKey: protocol.ResidentKeyRequirementRequired}
	for _, tc := range []struct {
		name   string
		config pk.AuthenticatorSelection
		query  string
		want   map[string]any
	}{
		{"defaults", pk.AuthenticatorSelection{}, "", defaults},
		{"platform request", pk.AuthenticatorSelection{}, "platform", with(map[string]any{"authenticatorAttachment": "platform"})},
		{"cross-platform request", pk.AuthenticatorSelection{}, "cross-platform", with(map[string]any{"authenticatorAttachment": "cross-platform"})},
		{"configured cross-platform", required, "", with(map[string]any{"authenticatorAttachment": "cross-platform", "residentKey": "required", "requireResidentKey": true})},
		{"request replaces configured", required, "platform", with(map[string]any{"authenticatorAttachment": "platform", "residentKey": "required", "requireResidentKey": true})},
		{"configured platform", pk.AuthenticatorSelection{Attachment: protocol.Platform, ResidentKey: protocol.ResidentKeyRequirementDiscouraged}, "", with(map[string]any{"authenticatorAttachment": "platform", "residentKey": "discouraged"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPasskeyPeers(t, "sqlite", pk.Options{AuthenticatorSelection: tc.config}, auth.Options{})
			path := "generate-register-options"
			if tc.query != "" {
				path += "?authenticatorAttachment=" + tc.query
			}
			options, _ := p.call(t, p.first, path, nil, 200, p.session)
			if got := options["authenticatorSelection"]; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("registration options advertised %v, want %v", got, tc.want)
			}
		})
	}
	p := newPasskeyPeers(t, "sqlite", pk.Options{}, auth.Options{})
	for _, refused := range []struct {
		query   string
		cookies []*http.Cookie
	}{{"roaming", nil}, {"roaming", []*http.Cookie{p.session}}, {"", []*http.Cookie{p.session}}, {"platform&authenticatorAttachment=platform", []*http.Cookie{p.session}}} {
		body, set := p.call(t, p.first, "generate-register-options?authenticatorAttachment="+refused.query, nil, 400, refused.cookies...)
		if body["code"] != "VALIDATION_ERROR" || body["message"] != `[query.authenticatorAttachment] Invalid option: expected one of "platform"|"cross-platform"` || len(set) != 0 {
			t.Fatalf("an unknown authenticator attachment was not refused: %v", body)
		}
	}
}

// Extension resolvers run for each options request, their inputs travel
// with the challenge to another instance, registration always asks for
// credProps, and unrequested client outputs are accepted. The sign-in
// callback sees each verified assertion outside any store transaction,
// before the counter is saved and the session issued, and can refuse it.
func TestPasskeyCeremonyOptionsAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var p *passkeyPeers
			calls := map[string]int{}
			misconfigured := false
			var refusal error
			var seen []pk.VerifiedAuthentication
			var during [][2]int
			// stored reads the passkey's counter and the owner's session count
			// on the instance that finishes the ceremony. SQLite has one
			// connection, so the read blocks if a transaction holds it.
			stored := func(ctx context.Context, id string) [2]int {
				var counter, sessions int
				st := p.stores[1]
				if err := st.db.QueryRowContext(ctx, st.bind(`SELECT "counter" FROM "passkey" WHERE "id"=?`), id).Scan(&counter); err != nil {
					t.Error(err)
				}
				if err := st.db.QueryRowContext(ctx, st.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), p.owner.User.ID).Scan(&sessions); err != nil {
					t.Error(err)
				}
				return [2]int{counter, sessions}
			}
			p = newPasskeyPeers(t, dialect, pk.Options{
				Registration: pk.RegistrationOptions{Extensions: func(c auth.EndpointContext) (protocol.AuthenticationExtensions, error) {
					calls[c.Request.URL.Path]++
					switch c.Request.URL.Query().Get("name") {
					case "refused":
						return protocol.AuthenticationExtensions{}, &auth.APIError{Status: 403, Code: "EXTENSIONS_REFUSED", Message: "Extensions refused"}
					case "sign-in-only":
						return protocol.AuthenticationExtensions{GetCredBlob: true}, nil
					}
					return protocol.AuthenticationExtensions{LargeBlob: protocol.LargeBlobInputs{Support: protocol.LargeBlobSupportRequired}}, nil
				}},
				Authentication: pk.AuthenticationOptions{
					Extensions: func(c auth.EndpointContext) (protocol.AuthenticationExtensions, error) {
						calls[c.Request.URL.Path]++
						if misconfigured {
							return protocol.AuthenticationExtensions{CredProps: true}, nil
						}
						if s, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header); err != nil || s != nil {
							return protocol.AuthenticationExtensions{LargeBlob: protocol.LargeBlobInputs{Read: true}}, err
						}
						return protocol.AuthenticationExtensions{}, nil
					},
					AfterVerification: func(c auth.EndpointContext, v pk.VerifiedAuthentication) error {
						ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
						defer cancel()
						seen = append(seen, v)
						during = append(during, stored(ctx, v.Passkey.ID))
						return refusal
					},
				},
			}, auth.Options{})

			if body, set := p.call(t, p.first, "generate-register-options?name=refused", nil, 403, p.session); body["code"] != "EXTENSIONS_REFUSED" || len(set) != 0 {
				t.Fatal("a refused extension resolver still issued registration options", body)
			}
			if _, set := p.call(t, p.first, "generate-register-options?name=sign-in-only", nil, 500, p.session); len(set) != 0 {
				t.Fatal("registration options carried a sign-in extension")
			}
			key := newSoftwareKey(t)
			register := func(outputs map[string]any, status int) map[string]any {
				t.Helper()
				options, set := p.call(t, p.first, "generate-register-options", nil, 200, p.session)
				if want := map[string]any{"credProps": true, "largeBlob": map[string]any{"support": "required"}}; !reflect.DeepEqual(options["extensions"], want) {
					t.Fatalf("registration options lost the resolved extensions: %v", options["extensions"])
				}
				key.handle = options["user"].(map[string]any)["id"].(string)
				resp := key.response(t, options["challenge"].(string), passkeyPeerOrigin, "example.test", 0, true)
				resp["clientExtensionResults"] = outputs
				row, _ := p.call(t, p.second, "verify-registration", map[string]any{"response": resp}, status, set[0], p.session)
				return row
			}
			if body := register(map[string]any{"credProps": map[string]any{"rk": true}}, 400); body["code"] != "FAILED_TO_VERIFY_REGISTRATION" {
				t.Fatal("another instance verified a registration without the large blob support its challenge required", body)
			}
			row := register(map[string]any{"credProps": map[string]any{"rk": true}, "largeBlob": map[string]any{"supported": true}, "hmacCreateSecret": true}, 200)
			if row["userId"] != p.owner.User.ID {
				t.Fatal("an extension output the server did not request refused the registration", row)
			}

			count := uint32(0)
			login := func(signedIn bool, outputs map[string]any, status int) (map[string]any, []*http.Cookie) {
				t.Helper()
				var cookies []*http.Cookie
				if signedIn {
					cookies = append(cookies, p.session)
				}
				options, set := p.call(t, p.first, "generate-authenticate-options", nil, 200, cookies...)
				var want any
				if signedIn {
					want = map[string]any{"largeBlob": map[string]any{"read": true}}
				}
				if !reflect.DeepEqual(options["extensions"], want) {
					t.Fatalf("a signed-out sign-in received the signed-in caller's extensions: %v", options["extensions"])
				}
				count++
				resp := key.response(t, options["challenge"].(string), passkeyPeerOrigin, "example.test", count, false)
				resp["clientExtensionResults"] = outputs
				return p.call(t, p.second, "verify-authentication", map[string]any{"response": resp}, status, set[0])
			}
			blob := map[string]any{"largeBlob": map[string]any{"blob": "AQID"}}
			written := map[string]any{"largeBlob": map[string]any{"written": true}}
			login(true, written, 400)
			signed, _ := login(true, blob, 200)
			if signed["user"].(map[string]any)["id"] != p.owner.User.ID {
				t.Fatal("the large blob read did not sign the owner in", signed)
			}
			login(false, written, 200)
			response := map[string]any{}
			if len(seen) == 2 {
				_ = json.Unmarshal(seen[0].Response, &response)
			}
			if len(seen) != 2 || seen[0].Passkey.ID != row["id"] || seen[0].Passkey.UserID != p.owner.User.ID || seen[0].Passkey.Counter != 0 || seen[0].Credential.Authenticator.SignCount != 2 ||
				!bytes.Equal(seen[0].Credential.ID, key.id) || during[0] != [2]int{0, 1} || !reflect.DeepEqual(response["clientExtensionResults"], blob) {
				t.Fatal("AfterVerification did not see the verified assertion before it was saved", len(seen), during)
			}
			refuse := func(err error, status int, code string) {
				t.Helper()
				refusal = err
				defer func() { refusal = nil }()
				before := stored(ctx, row["id"].(string))
				body, set := login(false, map[string]any{}, status)
				for _, c := range set {
					if c.MaxAge > 0 {
						t.Fatal("a refused sign-in set a session cookie")
					}
				}
				if body["code"] != code || stored(ctx, row["id"].(string)) != before {
					t.Fatal("a refused sign-in saved its counter or issued a session", body, before)
				}
			}
			refuse(&auth.APIError{Status: 403, Code: "SIGN_IN_PAUSED", Message: "Sign-in is paused"}, 403, "SIGN_IN_PAUSED")
			refuse(errors.New("audit log unavailable"), 400, "AUTHENTICATION_FAILED")
			login(false, map[string]any{}, 200)
			if len(seen) != 5 || stored(ctx, row["id"].(string)) != [2]int{int(count), 4} {
				t.Fatal("the counter a refused sign-in carried was not accepted later", len(seen), stored(ctx, row["id"].(string)))
			}

			misconfigured = true
			if _, set := p.call(t, p.first, "generate-authenticate-options", nil, 500); len(set) != 0 {
				t.Fatal("a registration-only input reached sign-in options")
			}
			misconfigured = false
			if calls["/api/auth/passkey/generate-register-options"] != 4 || calls["/api/auth/passkey/generate-authenticate-options"] != 7 {
				t.Fatal("the extension resolvers did not see each options request", calls)
			}
		})
	}
}

// The challenge cookie is <CookiePrefix>.passkey_challenge, and the core
// cookie override renames it for both ceremonies.
func TestPasskeyChallengeCookieName(t *testing.T) {
	ceremonyCookie := func(t *testing.T, set []*http.Cookie, name string) *http.Cookie {
		t.Helper()
		if len(set) != 1 || set[0].Name != name || set[0].MaxAge != 300 {
			t.Fatalf("the challenge cookie was %v, want %s", set, name)
		}
		return set[0]
	}
	prefixed := newPasskeyPeers(t, "sqlite", pk.Options{}, auth.Options{CookiePrefix: "company"})
	_, set := prefixed.call(t, prefixed.first, "generate-authenticate-options", nil, 200)
	ceremonyCookie(t, set, "__Secure-company.passkey_challenge")

	p := newPasskeyPeers(t, "sqlite", pk.Options{}, auth.Options{Cookies: map[string]auth.CookieOptions{"passkey_challenge": {Name: "app-passkey"}}})
	options, set := p.call(t, p.first, "generate-register-options", nil, 200, p.session)
	challenge := ceremonyCookie(t, set, "__Secure-app-passkey")
	key := newSoftwareKey(t)
	key.handle = options["user"].(map[string]any)["id"].(string)
	p.call(t, p.second, "verify-registration", map[string]any{"response": key.response(t, options["challenge"].(string), passkeyPeerOrigin, "example.test", 0, true)}, 200, challenge, p.session)

	options, set = p.call(t, p.first, "generate-authenticate-options", nil, 200)
	challenge = ceremonyCookie(t, set, "__Secure-app-passkey")
	payload := map[string]any{"response": key.response(t, options["challenge"].(string), passkeyPeerOrigin, "example.test", 1, false)}
	renamed := *challenge
	renamed.Name = "__Secure-authn.passkey_challenge"
	if body, _ := p.call(t, p.second, "verify-authentication", payload, 400, &renamed); body["code"] != "CHALLENGE_NOT_FOUND" {
		t.Fatal("the default cookie name redeemed a renamed challenge", body)
	}
	if signed, _ := p.call(t, p.second, "verify-authentication", payload, 200, challenge); signed["user"].(map[string]any)["id"] != p.owner.User.ID {
		t.Fatal("the renamed challenge cookie did not complete sign-in", signed)
	}
}
