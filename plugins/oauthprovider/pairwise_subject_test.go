package oauthprovider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestPairwiseSubjectSector(t *testing.T) {
	for _, tc := range []struct{ uri, host string }{
		{"https://BÜCHER.example:0443/path", "xn--bcher-kva.example"},
		{"https://EXAMPLE.test:08443/first", "example.test:8443"},
		{"http://127.0.0.1:80", "127.0.0.1"},
		{"http://[2001:db8::1]:5133/return", "[2001:db8::1]:5133"},
		{"http://[::ffff:127.0.0.1]/return", "[::ffff:7f00:1]"},
		{"com.example:/callback", ""},
	} {
		mac := hmac.New(sha256.New, []byte("secret"))
		mac.Write([]byte(tc.host + ".owner"))
		want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		sub, err := pairwiseSubject("secret", "owner", []string{tc.uri, "https://other.example.test/path"})
		if err != nil || sub != want {
			t.Errorf("sector %q: %q, %v", tc.uri, sub, err)
		}
	}
	for _, redirects := range [][]string{nil, {""}, {"relative/path"}} {
		if _, err := pairwiseSubject("secret", "owner", redirects); err == nil {
			t.Fatal("missing or invalid pairwise sector accepted")
		}
	}
}
