package providers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	jose "github.com/go-jose/go-jose/v4"
)

// A Kakao SDK ID token signs in for the REST API key or a listed native app
// key, with its nonce, as the same account the profile endpoint names: the
// numeric subject is the profile id, and the email is unverified.
func TestKakaoIDToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != kakaoKeys {
			t.Fatalf("unexpected request %s", r.URL)
		}
		return textResponse(200, "application/json", string(jwks)), nil
	})}
	p := Kakao("rest-key", "", KakaoOptions{Audiences: []string{"native-key"}, HTTPClient: client})
	token := func(issuer, aud, sub, nonce string) string {
		return signedClaims(t, key, issuer, sub, nonce, map[string]any{"aud": aud, "nickname": "Kim", "picture": "https://img.example/k.png", "email": "kim@example.org"})
	}
	for _, aud := range []string{"rest-key", "native-key"} {
		profile, _, err := p.VerifyIDToken(t.Context(), token(kakaoIssuer, aud, "4242", "n"), "n")
		if err != nil || profile.Subject != "4242" || profile.Name != "Kim" || profile.Email != "kim@example.org" || profile.EmailVerified ||
			profile.Image == nil || *profile.Image != "https://img.example/k.png" {
			t.Fatalf("a token for %s gave %+v, %v", aud, profile, err)
		}
		want := profileData{"id": json.Number("4242"), "kakao_account": map[string]any{"email": "kim@example.org", "profile": map[string]any{"nickname": "Kim", "thumbnail_image_url": "https://img.example/k.png"}}}
		if !reflect.DeepEqual(profile.Data, want) {
			t.Fatalf("the data is %#v", profile.Data)
		}
	}
	var me profileData
	d := json.NewDecoder(strings.NewReader(`{"id":4242,"kakao_account":{"email":"kim@example.org"}}`))
	d.UseNumber()
	_ = d.Decode(&me)
	if browser, _ := mapProfile("kakao", me); browser.Subject != "4242" {
		t.Fatal("the profile endpoint names", browser.Subject)
	}
	if profile, _, err := p.VerifyIDToken(t.Context(), token(kakaoIssuer, "rest-key", "0042", "n"), "n"); err != nil || profile.Subject != "42" {
		t.Fatal("a padded subject gave", profile.Subject, err)
	}
	for name, raw := range map[string]string{
		"an unlisted audience": token(kakaoIssuer, "other-key", "4242", "n"),
		"another issuer":       token("https://kakao.com", "rest-key", "4242", "n"),
		"another nonce":        token(kakaoIssuer, "rest-key", "4242", "other"),
		"a non-numeric sub":    token(kakaoIssuer, "rest-key", "abc", "n"),
	} {
		if _, _, err := p.VerifyIDToken(t.Context(), raw, "n"); err == nil {
			t.Fatal("Kakao accepted", name)
		}
	}

	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const base = "https://app.example.org"
	h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, SocialProviders: map[string]auth.OAuthProvider{"kakao": p}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"kakao","idToken":{"token":"`+token(kakaoIssuer, "native-key", "4242", "n")+`","nonce":"n"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	var signedIn struct {
		User struct {
			ID            string
			EmailVerified bool
		}
	}
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &signedIn) != nil || signedIn.User.EmailVerified {
		t.Fatal("the SDK token sign-in answered", res.Code, res.Body)
	}
	accounts, err := store.ListUserAccounts(t.Context(), signedIn.User.ID)
	if err != nil || len(accounts) != 1 || accounts[0].ProviderID != "kakao" || accounts[0].AccountID != "4242" {
		t.Fatal("the accounts are", accounts, err)
	}
	if p, _ := New("kakao", "rest-key", ""); p.VerifyIDToken == nil {
		t.Fatal("New(\"kakao\") has no ID-token sign-in")
	}
}
