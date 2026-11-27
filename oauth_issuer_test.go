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
		// Serialized as a WHATWG URL: lowercase host, no default port and
		// resolved dot segments.
		"https://IdP.Example.test:443/a/../tenant/": "https://idp.example.test/tenant",
		"http://idp.example.test:80/x/./y":          "http://idp.example.test/x/y",
		"https://idp.example.test:8443/x":           "https://idp.example.test:8443/x",
		"https://idp.example.test:/base/":           "https://idp.example.test/base",
		"https://Bücher.example/x":                  "https://xn--bcher-kva.example/x",
		"https://[0:0::1]:443/x":                    "https://[::1]/x",
		"https://[::ffff:127.0.0.1]/x":              "https://[::ffff:7f00:1]/x",
		"https://h.test:0443/x":                     "https://h.test/x",
		"https://h.test:08443/x":                    "https://h.test:8443/x",
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
