package oauthprovider

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

func TestKeyRotationConfiguration(t *testing.T) {
	p, err := New(Options{Assertions: AssertionOptions{AllowKeyRotation: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateStore(memory.New()); err == nil || !strings.Contains(err.Error(), "atomic single-use") {
		t.Fatal("enabled rotation requires transactional replay protection", err)
	}
	for _, tc := range []struct {
		rule *auth.RateLimitRule
		want int
	}{
		{nil, 5}, {&auth.RateLimitRule{Max: 7, Window: time.Minute}, 7}, {&auth.RateLimitRule{}, 0},
	} {
		p, err := New(Options{Assertions: AssertionOptions{KeyRotationRateLimit: tc.rule}})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ep := range p.Endpoints {
			if ep.Path != "/oauth2/client/rotate-keys" {
				continue
			}
			found = true
			if ep.Method != http.MethodPost || ep.RawBody || !json.Valid(ep.OpenAPI) {
				t.Fatal("incorrect rotation route")
			}
			if tc.want == 0 {
				if ep.RateLimit != nil {
					t.Fatal("expected global rate limit")
				}
			} else if ep.RateLimit == nil || ep.RateLimit.Max != tc.want || ep.RateLimit.Window != time.Minute || ep.RateLimit == tc.rule {
				t.Fatal("incorrect key rotation rate limit", ep.RateLimit)
			}
		}
		if !found {
			t.Fatal("missing rotation endpoint")
		}
	}
}
