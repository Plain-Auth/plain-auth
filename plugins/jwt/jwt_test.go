package jwt_test

import (
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/jwt"
)

// New refuses an RSA modulus below 2048 bits or of odd length and accepts
// even lengths above it.
func TestNewChecksRSAModulusLength(t *testing.T) {
	for _, bits := range []int{1024, 2040, 2049, 3071} {
		if _, err := jwt.New(jwt.Options{Algorithm: "RS256", RSAModulusBits: bits}); err == nil {
			t.Fatalf("accepted a %d-bit RSA modulus", bits)
		}
	}
	for _, bits := range []int{2050, 3072, 4096} {
		if _, err := jwt.New(jwt.Options{Algorithm: "PS256", RSAModulusBits: bits}); err != nil {
			t.Fatalf("refused a %d-bit RSA modulus: %v", bits, err)
		}
	}
}

// New refuses key-agreement and HMAC algorithms, which cannot publish a
// public signing key, as the signing algorithm or an additional one.
func TestNewRefusesUnsupportedAlgorithms(t *testing.T) {
	for _, alg := range []string{"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "HS256", "none"} {
		if _, err := jwt.New(jwt.Options{Algorithm: alg}); err == nil {
			t.Fatalf("accepted %s as the signing algorithm", alg)
		}
		if _, err := jwt.New(jwt.Options{AdditionalAlgorithms: []string{alg}}); err == nil {
			t.Fatalf("accepted %s as an additional algorithm", alg)
		}
	}
}
