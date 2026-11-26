package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	kakaoIssuer = "https://kauth.kakao.com"
	kakaoKeys   = "https://kauth.kakao.com/.well-known/jwks.json"
)

// KakaoOptions configures the Kakao preset.
type KakaoOptions struct {
	// Audiences lists the native app keys whose SDK ID tokens may sign in
	// directly; the client ID, the REST API key, is always accepted.
	Audiences []string
	// HTTPClient fetches Kakao's signing keys.
	HTTPClient *http.Client
}

// Kakao configures Kakao sign-in: the browser flow, and direct sign-in with
// an ID token from the Kakao SDKs.
func Kakao(clientID, secret string, o KakaoOptions) auth.OAuthProvider {
	p := fromCatalog("kakao", clientID, secret, catalog["kakao"])
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), noRedirects(client)), kakaoKeys)
	verifier := oidc.NewVerifier(kakaoIssuer, keys, &oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: []string{oidc.RS256}})
	apps := clientIDs(clientID, o.Audiences)
	p.VerifyIDToken = func(ctx context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
		return resolveSignedToken(ctx, verifier, idTokenRules{profile: kakaoIDTokenProfile}, apps, raw, nonce, "", true)
	}
	return p
}

// kakaoIDTokenProfile maps an ID token as the profile endpoint would
// describe the same user, so both sign in to one account. The token does
// not say whether the email is verified, so it is not.
func kakaoIDTokenProfile(token *oidc.IDToken) (auth.OAuthProfile, error) {
	var c struct{ Nickname, Picture, Email string }
	if err := token.Claims(&c); err != nil {
		return auth.OAuthProfile{}, err
	}
	// The profile endpoint's id is a number: "0042" and "42" are one user.
	id, err := strconv.ParseUint(token.Subject, 10, 64)
	if err != nil {
		return auth.OAuthProfile{}, errors.New("Kakao ID token subject is not numeric")
	}
	data := profileData{"id": json.Number(strconv.FormatUint(id, 10)), "kakao_account": map[string]any{
		"email": c.Email, "profile": map[string]any{"nickname": c.Nickname, "thumbnail_image_url": c.Picture},
	}}
	profile, err := mapProfile("kakao", data)
	profile.Data = data
	return profile, err
}
