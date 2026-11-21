package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	authn "github.com/FineStack/finestack-auth"
	"golang.org/x/oauth2"
)

const microsoftAuthority = "https://login.microsoftonline.com"
const microsoftConsumers = "9188040d-6c67-4c5b-b112-36a304b66dad"

var tenantIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

// MicrosoftOptions selects an Entra account class or concrete tenant GUID.
// The default uses the common endpoint and fetches a 48-pixel profile photo.
type MicrosoftOptions struct {
	TenantID            string
	DisableProfilePhoto bool
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
	client := &http.Client{Timeout: 15 * time.Second}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), microsoftAuthority+"/"+tenant+"/discovery/v2.0/keys")
	return microsoftProvider(id, secret, tenant, options.DisableProfilePhoto, keys, client), nil
}

func microsoftProvider(id, secret, tenant string, disablePhoto bool, keys oidc.KeySet, client *http.Client) authn.OAuthProvider {
	base := microsoftAuthority + "/" + tenant
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
		if !tenantIDPattern.MatchString(c.TID) || token.Issuer != microsoftAuthority+"/"+c.TID+"/v2.0" || strings.TrimSpace(c.OID) == "" ||
			(tenant == "consumers" && c.TID != microsoftConsumers) || (tenant == "organizations" && c.TID == microsoftConsumers) || (!multi && tenant != c.TID) {
			return authn.OAuthProfile{}, errors.New("Microsoft identity is outside the configured tenant")
		}
		verified := verifiedFlag(c.Verified)
		if len(c.Verified) == 0 {
			verified = c.Email != "" && (slices.Contains(c.Primary, c.Email) || slices.Contains(c.Secondary, c.Email))
		}
		return authn.OAuthProfile{Subject: c.OID, Email: c.Email, Name: c.Name, EmailVerified: verified, Image: c.Picture}, nil
	}
	p := signedProvider(id, secret, oauth2.Endpoint{AuthURL: base + "/oauth2/v2.0/authorize", TokenURL: base + "/oauth2/v2.0/token", AuthStyle: oauth2.AuthStyleInParams}, verifier, client, idTokenRules{profile: mapProfile})
	p.Config.Scopes = []string{"openid", "profile", "email", "User.Read", "offline_access"}
	p.AllowVerifiedEmailLink = true
	if !disablePhoto {
		resolve := p.Resolve
		p.Resolve = func(ctx context.Context, t *oauth2.Token, nonce string) (authn.OAuthProfile, error) {
			profile, err := resolve(ctx, t, nonce)
			if err != nil {
				return profile, err
			}
			if t.AccessToken != "" {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me/photos/48x48/$value", nil)
				if err != nil {
					return profile, err
				}
				req.Header.Set("Authorization", "Bearer "+t.AccessToken)
				res, err := client.Do(req)
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
