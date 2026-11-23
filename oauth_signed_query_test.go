package plainauth

import (
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSignedOAuthPageQuery(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	old := strings.Repeat("s", 40)
	a := &Auth{opts: Options{Secret: old}, now: func() time.Time { return now }}
	values := url.Values{"scope": {"read ~* &+"}, "resource": {"\ue000", "𐀀"}, "state": {"café"}, "ba_pl": {"untrusted"}, "sig": {"inbound"}}
	expiry := now.Add(time.Second)
	wire := a.SignOAuthQuery(values, expiry)
	// Generated independently with URLSearchParams and Web Crypto-compatible HMAC.
	const golden = "DosJSvRf5JqjEZEPTcRXhS9A5/S2K0SzpaPgZECRQvU="
	fields, err := url.ParseQuery(wire)
	if err != nil || fields.Get("sig") != golden || fields.Has("ba_pl") || values.Get("sig") != "inbound" {
		t.Fatal("incorrect signed browser form or caller mutation")
	}
	fields.Set("sig", strings.TrimRight(strings.ReplaceAll(golden, "/", "_"), "="))
	slices.Reverse(fields["resource"])
	a.opts.Secret = strings.Repeat("n", 40)
	a.opts.Secrets = []VersionedSecret{{Version: 2, Value: a.opts.Secret}, {Version: 1, Value: old}}
	if _, err := a.VerifyOAuthQuery(fields.Encode()); err != nil {
		t.Fatal("rotated signing key, value ordering or URL-safe alphabet was rejected")
	}
	fields.Set("locale", "en")
	if _, err := a.VerifyOAuthQuery(fields.Encode()); err == nil {
		t.Fatal("unsigned field in submitted form was accepted")
	}
	clean, err := a.VerifyOAuthPageQuery(fields.Encode())
	if err != nil || clean.Has("locale") || clean.Get("state") != "café" {
		t.Fatal("page-local field altered verification", err)
	}
	for _, bad := range []string{wire + "&sig=another", strings.Replace(wire, "caf%C3%A9", "changed", 1), wire + "&exp=9999999999", strings.Replace(wire, "ba_param=scope", "ba_param=locale", 1)} {
		if _, err := a.VerifyOAuthPageQuery(bad); err == nil {
			t.Fatal("modified consent page signature accepted")
		}
	}
	now = expiry
	if _, err := a.VerifyOAuthQuery(wire); err != nil {
		t.Fatal("query rejected at expiry boundary")
	}
	now = expiry.Add(time.Millisecond)
	if _, err := a.VerifyOAuthQuery(wire); err == nil {
		t.Fatal("expired query verified")
	}
}
