package plainauth

import "testing"

// The OAuth issuer is published without a query, fragment or one trailing
// slash, and tokens naming either the published or the configured spelling
// are accepted, as another runtime accepts both.
func TestOAuthIssuerSpellings(t *testing.T) {
	for configured, published := range map[string]string{
		"https://idp.example.test/":            "https://idp.example.test",
		"https://idp.example.test/base/?x=1#f": "https://idp.example.test/base",
		"https://idp.example.test/base":        "https://idp.example.test/base",
		"https://idp.example.test/base//":      "https://idp.example.test/base/",
	} {
		a := &Auth{serviceJWT: &JWTOptions{Issuer: configured}}
		if got := a.OAuthIssuer(); got != published {
			t.Fatal("the issuer was not published normalized", configured, got)
		}
		if !a.oauthIssuerAccepted(published) || !a.oauthIssuerAccepted(configured) || a.oauthIssuerAccepted("https://other.example.test") {
			t.Fatal("the accepted issuer spellings are wrong", configured)
		}
	}
}
