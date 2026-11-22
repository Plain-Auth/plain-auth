package oauthprovider

import (
	"encoding/json"
	"slices"
)

// ValidatePublicClientJWKS checks the public asymmetric key metadata supplied
// at client registration. Signature verification still validates the actual key and JWT.
func ValidatePublicClientJWKS(raw json.RawMessage) error {
	var doc map[string]json.RawMessage
	var keys []json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || json.Unmarshal(doc["keys"], &keys) != nil || len(keys) == 0 {
		return metadataProblem("jwks must be an RFC 7517 JWK Set object with a non-empty keys array")
	}
	for _, entry := range keys {
		if err := validatePublicClientKey(entry); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicClientKey(entry json.RawMessage) error {
	var key map[string]json.RawMessage
	const invalid = "jwks keys must be supported public JWKs with required key parameters"
	if json.Unmarshal(entry, &key) != nil || key == nil {
		return metadataProblem(invalid)
	}
	member := func(name string) string { var v string; _ = json.Unmarshal(key[name], &v); return v }
	for _, field := range []string{"k", "d", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, ok := key[field]; ok {
			return metadataProblem("jwks must contain only public asymmetric keys")
		}
	}
	var allowed []string
	switch member("kty") {
	case "oct":
		return metadataProblem("jwks must contain only public asymmetric keys")
	case "RSA":
		if member("n") == "" || member("e") == "" {
			return metadataProblem(invalid)
		}
		allowed = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	case "EC":
		alg := map[string]string{"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}[member("crv")]
		if alg == "" || member("x") == "" || member("y") == "" {
			return metadataProblem(invalid)
		}
		allowed = []string{alg}
	case "OKP":
		if member("crv") != "Ed25519" || member("x") == "" {
			return metadataProblem(invalid)
		}
		allowed = []string{"EdDSA"}
	default:
		return metadataProblem(invalid)
	}
	if _, ok := key["alg"]; ok && !slices.Contains(allowed, member("alg")) {
		return metadataProblem("jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve")
	}
	return nil
}
