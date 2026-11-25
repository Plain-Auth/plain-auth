package sqlstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/kvtest"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

// DPoP replay records stay with the other verification records in the
// database when SecondaryStorage holds sessions: two issuers sharing the
// database refuse a proof the other accepted, and the storage receives no
// reservation.
func TestDPoPProofsStayInDatabaseWithSecondaryStorage(t *testing.T) {
	const base = "https://public.example.test"
	const path = "/api/auth/oauth2/token"
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	public := (&jose.JSONWebKey{Key: key}).Public()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, new(jose.SignerOptions).WithType("dpop+jwt").WithHeader("jwk", public))
	must(err)
	body, err := json.Marshal(map[string]any{"iat": time.Now().Unix(), "jti": rand.Text(), "htm": "POST", "htu": base + path})
	must(err)
	jwt, err := signer.Sign(body)
	must(err)
	proof, err := jwt.CompactSerialize()
	must(err)
	dsn := organizationTestDSN(t, "sqlite")
	s, err := OpenWithOptions(ctx, "sqlite", dsn, []string{"oauth-provider"}, schema.Options{})
	must(err)
	t.Cleanup(func() { s.Close() })
	peer, err := Open(ctx, "sqlite", dsn)
	must(err)
	t.Cleanup(func() { peer.Close() })
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","redirectUris") VALUES ('reg','app','secret','client_secret_post',?,?,?)`), `["client_credentials"]`, `["reports"]`, `[]`)
	must(err)
	storage := kvtest.New()
	newHost := func(store auth.Store) http.Handler {
		t.Helper()
		plug, err := op.New(op.Options{Registration: op.RegistrationOptions{VerifySecret: func(_ context.Context, raw, stored string) (bool, error) { return raw == stored, nil }}})
		must(err)
		off := false
		host, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("s", 40), Store: store, Plugins: []auth.Plugin{plug}, RateLimit: &off,
			SecondaryStorage: storage, StoreSessionInDatabase: true})
		must(err)
		return host
	}
	credentials := url.Values{"grant_type": {"client_credentials"}, "client_id": {"app"}, "client_secret": {"secret"}}
	call := func(host http.Handler) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://private.internal"+path, strings.NewReader(credentials.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()
		host.ServeHTTP(w, r)
		return w
	}
	if w := call(newHost(s)); w.Code != 200 || !strings.Contains(w.Body.String(), `"token_type":"DPoP"`) {
		t.Fatal("the first use of a proof was refused:", w.Code, w.Body.String())
	}
	if w := call(newHost(peer)); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_dpop_proof") {
		t.Fatal("a second issuer accepted a replayed proof:", w.Code, w.Body.String())
	}
	if ops := storage.Ops(); len(ops) != 0 {
		t.Fatal("DPoP reservations reached the secondary storage:", ops)
	}
}
