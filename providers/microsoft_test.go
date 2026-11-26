package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func jsonResponse(t *testing.T, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}
}

// A browser sign-in through Microsoft under an External ID authority uses the
// authority's endpoints and signing keys, fetches the configured photo size,
// and accepts directly submitted ID tokens for every configured client ID
// while the code exchange accepts the client ID only.
func TestMicrosoftBrowserSignIn(t *testing.T) {
	const tid = "20000000-aaaa-0000-bbbb-000000000000"
	authority := "https://" + tid + ".ciamlogin.com"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var nonce, challenge string
	var photoCalls int
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case authority + "/" + tid + "/discovery/v2.0/keys":
			return jsonResponse(t, map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}), nil
		case authority + "/" + tid + "/oauth2/v2.0/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" || r.Form.Get("code") != "ms-code" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
				t.Fatal("incorrect Microsoft code exchange:", r.Form)
			}
			raw := signedClaims(t, key, authority+"/"+tid+"/v2.0", "pairwise", nonce, map[string]any{"oid": "object-id", "tid": tid, "email": "person@example.org", "verified_primary_email": []string{"person@example.org"}, "name": "A Person"})
			return jsonResponse(t, map[string]any{"access_token": "access", "token_type": "bearer", "id_token": raw}), nil
		case "https://graph.microsoft.com/v1.0/me/photos/96x96/$value":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatal("the photo request lacks the access token")
			}
			photoCalls++
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("photo"))}, nil
		}
		t.Fatalf("unexpected request %s", r.URL)
		return nil, nil
	})}
	p, err := Microsoft("client", "secret", MicrosoftOptions{TenantID: tid, Authority: authority + "/", ProfilePhotoSize: 96, AdditionalClientIDs: []string{"native-app"}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const base = "https://app.example.org"
	h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, SocialProviders: map[string]auth.OAuthProvider{"microsoft": p}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"microsoft","callbackURL":"/done"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	u, err := url.Parse(res.Header().Get("Location"))
	if err != nil || res.Code != 200 {
		t.Fatalf("sign-in: %d %v", res.Code, err)
	}
	q := u.Query()
	nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
	if u.Scheme+"://"+u.Host+u.Path != authority+"/"+tid+"/oauth2/v2.0/authorize" || q.Get("scope") != "openid profile email User.Read offline_access" || q.Get("client_id") != "client" || q.Get("code_challenge_method") != "S256" || nonce == "" {
		t.Fatalf("authorize URL %s", u)
	}
	callback := httptest.NewRequest("GET", base+"/api/auth/callback/microsoft?"+url.Values{"code": {"ms-code"}, "state": {q.Get("state")}}.Encode(), nil)
	for _, c := range res.Result().Cookies() {
		callback.AddCookie(c)
	}
	res = httptest.NewRecorder()
	h.ServeHTTP(res, callback)
	if res.Code != 302 || res.Header().Get("Location") != "/done" {
		t.Fatalf("callback: %d %s %s", res.Code, res.Header().Get("Location"), res.Body)
	}
	req = httptest.NewRequest("GET", base+"/api/auth/get-session", nil)
	for _, c := range res.Result().Cookies() {
		req.AddCookie(c)
	}
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	var session auth.SessionResult
	if err := json.Unmarshal(res.Body.Bytes(), &session); err != nil || !session.User.EmailVerified || session.User.Image == nil || *session.User.Image != "data:image/jpeg;base64, "+base64.StdEncoding.EncodeToString([]byte("photo")) || photoCalls != 1 {
		t.Fatalf("session %s %v (photo calls %d)", res.Body, err, photoCalls)
	}

	ctx := context.Background()
	direct := func(issuer, aud, tenant string) error {
		raw := signedClaims(t, key, issuer, "sub", "n", map[string]any{"aud": aud, "oid": "oid", "tid": tenant, "email": "person@example.org"})
		_, _, err := p.VerifyIDToken(ctx, raw, "n")
		return err
	}
	const other = "30000000-aaaa-0000-bbbb-000000000000"
	if err := direct(authority+"/"+tid+"/v2.0", "native-app", tid); err != nil {
		t.Fatal("a token for an additional client ID was refused:", err)
	}
	for name, err := range map[string]error{
		"another audience":      direct(authority+"/"+tid+"/v2.0", "other", tid),
		"the default authority": direct(microsoftAuthority+"/"+tid+"/v2.0", "client", tid),
		"another tenant":        direct(authority+"/"+other+"/v2.0", "client", other),
	} {
		if err == nil {
			t.Fatal("a direct token from", name, "was accepted")
		}
	}
	raw := signedClaims(t, key, authority+"/"+tid+"/v2.0", "sub", "n", map[string]any{"aud": "native-app", "oid": "oid", "tid": tid})
	token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": raw})
	if _, err := p.Resolve(context.WithValue(ctx, oauth2.HTTPClient, client), token, "n"); err == nil {
		t.Fatal("the code exchange accepted a token for an additional client ID")
	}
}

// The Graph photo is fetched at 48 pixels by default and not at all with
// DisableProfilePhoto; a missing or oversized photo leaves the image unset.
func TestMicrosoftProfilePhoto(t *testing.T) {
	const tid = "10000000-aaaa-0000-bbbb-000000000000"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	picture := "https://example.org/picture.png"
	raw := signedClaims(t, key, microsoftAuthority+"/"+tid+"/v2.0", "sub", "n", map[string]any{"oid": "oid", "tid": tid, "picture": picture})
	token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": raw})
	for _, tc := range []struct {
		name    string
		options MicrosoftOptions
		status  int
		body    string
		want    string
		calls   int
	}{
		{"default", MicrosoftOptions{}, 200, "photo", "data:image/jpeg;base64, " + base64.StdEncoding.EncodeToString([]byte("photo")), 1},
		{"disabled", MicrosoftOptions{DisableProfilePhoto: true}, 200, "photo", picture, 0},
		{"missing", MicrosoftOptions{}, 404, "", picture, 1},
		{"oversized", MicrosoftOptions{}, 200, strings.Repeat("x", 1<<20+1), picture, 1},
	} {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://graph.microsoft.com/v1.0/me/photos/48x48/$value" {
				t.Fatalf("%s: unexpected request %s", tc.name, r.URL)
			}
			calls++
			return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		p := microsoftProvider("client", "secret", tid, tc.options, keys)
		profile, err := p.Resolve(context.WithValue(context.Background(), oauth2.HTTPClient, client), token, "n")
		if err != nil || profile.Image == nil || *profile.Image != tc.want || calls != tc.calls {
			t.Fatalf("%s: image %v, calls %d, err %v", tc.name, profile.Image, calls, err)
		}
	}
}

// Microsoft refuses an authority that is not a secure origin and a photo
// size Graph does not serve; without options it uses the common endpoint.
func TestMicrosoftOptionValidation(t *testing.T) {
	for _, bad := range []MicrosoftOptions{{ProfilePhotoSize: 50}, {Authority: "http://login.example"}, {Authority: "https://login.example/path"}, {Authority: "https://login.example?q=1"}, {Authority: "https://user@login.example"}} {
		if _, err := Microsoft("client", "secret", bad); err == nil {
			t.Fatalf("Microsoft accepted %+v", bad)
		}
	}
	p, err := Microsoft("client", "secret", MicrosoftOptions{Authority: "https://login.microsoftonline.us/"})
	if err != nil || p.Config.Endpoint.AuthURL != "https://login.microsoftonline.us/common/oauth2/v2.0/authorize" {
		t.Fatal("a sovereign-cloud authority was refused or misused:", p.Config.Endpoint.AuthURL, err)
	}
	p, err = Microsoft("client", "secret", MicrosoftOptions{})
	if err != nil || p.Config.Endpoint.AuthURL != microsoftAuthority+"/common/oauth2/v2.0/authorize" {
		t.Fatal("the default endpoint is wrong:", p.Config.Endpoint.AuthURL, err)
	}
}
