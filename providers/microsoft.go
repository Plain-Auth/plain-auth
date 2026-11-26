package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const microsoftAuthority = "https://login.microsoftonline.com"
const microsoftConsumers = "9188040d-6c67-4c5b-b112-36a304b66dad"

var tenantIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

var microsoftPhotoSizes = []int{48, 64, 96, 120, 240, 360, 432, 504, 648}

// microsoftGraph returns the Graph origin of the cloud an authority belongs
// to, or "" for an authority whose Graph is unknown: the photo is then not
// fetched, so a token never leaves its cloud.
func microsoftGraph(authority string) string {
	host := strings.TrimPrefix(authority, "https://")
	switch {
	case host == "login.microsoftonline.com" || strings.HasSuffix(host, ".ciamlogin.com"):
		return "https://graph.microsoft.com"
	case host == "login.microsoftonline.us":
		return "https://graph.microsoft.us"
	case host == "login.chinacloudapi.cn" || host == "login.partner.microsoftonline.cn":
		return "https://microsoftgraph.chinacloudapi.cn"
	}
	return ""
}

// MicrosoftOptions selects an Entra account class or concrete tenant GUID.
// The default uses the common endpoint and fetches a 48-pixel profile photo.
type MicrosoftOptions struct {
	TenantID string
	// Authority is the sign-in origin; empty selects
	// https://login.microsoftonline.com. For External ID use
	// https://<tenant>.ciamlogin.com with the tenant GUID as TenantID.
	Authority string
	// AdditionalClientIDs are other client IDs a directly submitted ID token
	// may name as its audience; the code exchange uses the client ID. Empty
	// entries are ignored.
	AdditionalClientIDs []string
	// ProfilePhotoSize is the Graph photo size: 48 (the default), 64, 96,
	// 120, 240, 360, 432, 504 or 648 pixels.
	ProfilePhotoSize    int
	DisableProfilePhoto bool
	// ClientAssertion authenticates the code exchange and refresh with a
	// signed assertion, such as providers.PrivateKeyJWT or a federated
	// workload token, instead of a client secret; pass an empty secret.
	ClientAssertion authn.ClientAssertionFunc
	// HTTPClient fetches the signing keys, the token endpoint and the photo.
	HTTPClient *http.Client
}

// Microsoft configures the Microsoft identity platform v2 endpoints.
func Microsoft(id, secret string, options MicrosoftOptions) (authn.OAuthProvider, error) {
	tenant := strings.ToLower(options.TenantID)
	if tenant == "" {
		tenant = "common"
	}
	if tenant != "common" && tenant != "consumers" && tenant != "organizations" && !tenantIDPattern.MatchString(tenant) {
		return authn.OAuthProvider{}, errors.New("invalid Microsoft tenant ID")
	}
	authority := strings.TrimRight(options.Authority, "/")
	if authority == "" {
		authority = microsoftAuthority
	}
	if u, err := url.Parse(authority); err != nil || !secureEndpoint(authority) || u.Scheme+"://"+u.Host != authority {
		return authn.OAuthProvider{}, errors.New("invalid Microsoft authority")
	}
	options.Authority = authority
	if options.ProfilePhotoSize != 0 && !slices.Contains(microsoftPhotoSizes, options.ProfilePhotoSize) {
		return authn.OAuthProvider{}, errors.New("invalid Microsoft profile photo size")
	}
	if options.ClientAssertion != nil && secret != "" {
		return authn.OAuthProvider{}, errors.New("Microsoft: use a client assertion or a client secret, not both")
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), noRedirects(options.HTTPClient)), authority+"/"+tenant+"/discovery/v2.0/keys")
	return microsoftProvider(id, secret, tenant, options, keys), nil
}

func microsoftProvider(id, secret, tenant string, o MicrosoftOptions, keys oidc.KeySet) authn.OAuthProvider {
	authority := o.Authority
	if authority == "" {
		authority = microsoftAuthority
	}
	size := o.ProfilePhotoSize
	if size == 0 {
		size = 48
	}
	base := authority + "/" + tenant
	multi := tenant == "common" || tenant == "consumers" || tenant == "organizations"
	verifier := oidc.NewVerifier(base+"/v2.0", keys, &oidc.Config{ClientID: id, SupportedSigningAlgs: []string{"RS256"}, SkipIssuerCheck: multi})
	mapProfile := func(token *oidc.IDToken) (authn.OAuthProfile, error) {
		var c struct {
			OID, TID, Email, Name string
			Picture               *string
			Verified              json.RawMessage `json:"email_verified"`
			Primary               []string        `json:"verified_primary_email"`
			Secondary             []string        `json:"verified_secondary_email"`
		}
		if err := token.Claims(&c); err != nil {
			return authn.OAuthProfile{}, err
		}
		if !tenantIDPattern.MatchString(c.TID) || token.Issuer != authority+"/"+c.TID+"/v2.0" || strings.TrimSpace(c.OID) == "" ||
			(tenant == "consumers" && c.TID != microsoftConsumers) || (tenant == "organizations" && c.TID == microsoftConsumers) || (!multi && tenant != c.TID) {
			return authn.OAuthProfile{}, errors.New("Microsoft identity is outside the configured tenant")
		}
		verified := verifiedFlag(c.Verified)
		if len(c.Verified) == 0 {
			verified = c.Email != "" && (slices.Contains(c.Primary, c.Email) || slices.Contains(c.Secondary, c.Email))
		}
		return authn.OAuthProfile{Subject: c.OID, Email: c.Email, Name: c.Name, EmailVerified: verified, Image: c.Picture}, nil
	}
	p := signedProvider(id, secret, oauth2.Endpoint{AuthURL: base + "/oauth2/v2.0/authorize", TokenURL: base + "/oauth2/v2.0/token", AuthStyle: oauth2.AuthStyleInParams}, verifier, o.HTTPClient, idTokenRules{profile: mapProfile})
	p.Config.Scopes = []string{"openid", "profile", "email", "User.Read", "offline_access"}
	p.AllowVerifiedEmailLink = true
	if o.ClientAssertion != nil {
		p.TokenEndpointAuth = authn.TokenEndpointAuth{Method: authn.TokenAuthPrivateKeyJWT, ClientAssertion: o.ClientAssertion}
	}
	if ids := clientIDs(id, o.AdditionalClientIDs); len(ids) > 1 {
		// A directly submitted token may be issued to any of the app's client
		// IDs; the code exchange still checks the client ID only.
		direct := oidc.NewVerifier(base+"/v2.0", keys, &oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: []string{"RS256"}, SkipIssuerCheck: multi})
		p.VerifyIDToken = func(ctx context.Context, raw, nonce string) (authn.OAuthProfile, time.Time, error) {
			return resolveSignedToken(ctx, direct, idTokenRules{profile: mapProfile}, ids, raw, nonce, "", true)
		}
	}
	graph := microsoftGraph(authority)
	if !o.DisableProfilePhoto && graph != "" {
		resolve := p.Resolve
		p.Resolve = func(ctx context.Context, t *oauth2.Token, nonce string) (authn.OAuthProfile, error) {
			profile, err := resolve(ctx, t, nonce)
			if err != nil {
				return profile, err
			}
			if t.AccessToken != "" {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v1.0/me/photos/%dx%d/$value", graph, size, size), nil)
				if err != nil {
					return profile, err
				}
				req.Header.Set("Authorization", "Bearer "+t.AccessToken)
				client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
				if client == nil {
					client = o.HTTPClient
				}
				// The photo is fetched from Graph only, never from a redirect.
				res, err := noRedirects(client).Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode == 200 {
						image, err := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
						if err == nil && len(image) <= 1<<20 {
							data := fmt.Sprintf("data:image/jpeg;base64, %s", base64.StdEncoding.EncodeToString(image))
							profile.Image = &data
						}
					}
				}
			}
			return profile, nil
		}
	}
	return p
}
