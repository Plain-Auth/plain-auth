package oauthprovider

import (
	"encoding/json"
	"net/url"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// OpenIDProviderMetadata describes the issuer document available to relying parties.
type OpenIDProviderMetadata struct {
	AuthorizationServerMetadata
	UserInfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	// EndSessionEndpoint is RP-Initiated Logout, published when the store
	// can end the session a hint names.
	EndSessionEndpoint           string   `json:"end_session_endpoint,omitempty"`
	ClaimsSupported              []string `json:"claims_supported,omitzero"`
	ClaimsParameterSupported     bool     `json:"claims_parameter_supported"`
	SubjectTypesSupported        []string `json:"subject_types_supported"`
	ACRValuesSupported           []string `json:"acr_values_supported"`
	IDTokenSigningAlgorithms     []string `json:"id_token_signing_alg_values_supported"`
	RequestParameterSupported    bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported bool     `json:"request_uri_parameter_supported"`
	PromptValuesSupported        []string `json:"prompt_values_supported"`
}

func openIDConfigPath(issuer *url.URL) string {
	return strings.TrimSuffix(issuer.EscapedPath(), "/") + "/.well-known/openid-configuration"
}

// GetOpenIDConfig returns the document served at the issuer's OpenID discovery URL.
func GetOpenIDConfig(a *auth.Auth) (OpenIDProviderMetadata, error) {
	var doc OpenIDProviderMetadata
	if a == nil || !a.HasPlugin("oauth-provider") {
		return doc, auth.ErrNotFound
	}
	u, err := issuerDiscoveryURL(a.OAuthIssuer())
	if err != nil {
		return doc, auth.ErrNotFound
	}
	raw, ok := a.WellKnownJSON(openIDConfigPath(u))
	if !ok {
		return doc, auth.ErrNotFound
	}
	err = json.Unmarshal(raw, &doc)
	return doc, err
}

func (opts Options) openIDMetadata(a *auth.Auth, server AuthorizationServerMetadata, userInfo, endSession string, interactiveConsent bool) OpenIDProviderMetadata {
	doc := OpenIDProviderMetadata{
		AuthorizationServerMetadata: server,
		UserInfoEndpoint:            userInfo,
		EndSessionEndpoint:          endSession,
		ClaimsSupported:             opts.supportedUserInfoClaims(), ClaimsParameterSupported: true,
		SubjectTypesSupported: []string{"public"}, ACRValuesSupported: []string{"0"},
		IDTokenSigningAlgorithms: []string{opts.idTokenAlgorithm(a)},
	}
	if opts.PairwiseSecret != "" {
		doc.SubjectTypesSupported = append(doc.SubjectTypesSupported, "pairwise")
	}
	pages := opts.Authorization
	if pages.LoginPage != "" {
		doc.PromptValuesSupported = append(doc.PromptValuesSupported, "login")
	}
	if interactiveConsent && pages.ConsentPage != "" {
		doc.PromptValuesSupported = append(doc.PromptValuesSupported, "consent")
	}
	if pages.LoginPage != "" || pages.SignupPage != "" {
		doc.PromptValuesSupported = append(doc.PromptValuesSupported, "create")
	}
	if pages.SelectAccount.Page != "" {
		doc.PromptValuesSupported = append(doc.PromptValuesSupported, "select_account")
	}
	doc.PromptValuesSupported = append(doc.PromptValuesSupported, "none")
	return doc
}

func (opts Options) idTokenAlgorithm(a *auth.Auth) string {
	if opts.DisableJWTPlugin {
		return "HS256"
	}
	return a.JWTSigningAlgorithm()
}
