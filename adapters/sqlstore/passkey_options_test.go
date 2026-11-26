package sqlstore

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

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
// status. path is relative to /api/auth/passkey/ and may carry a query.
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
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out, w.Result().Cookies()
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
