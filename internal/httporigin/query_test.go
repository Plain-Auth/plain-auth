package httporigin

import (
	"net/url"
	"testing"
)

// Query parameters added to a deep link keep its original spelling.
func TestSetQueryKeepsDeepLinks(t *testing.T) {
	for target, want := range map[string]string{
		"myapp://":                        "myapp://?token=x",
		"myapp://?state=1":                "myapp://?state=1&token=x",
		"myapp:///dashboard":              "myapp:///dashboard?token=x",
		"myapp://home/reset":              "myapp://home/reset?token=x",
		"https://app.example/reset?a=b#f": "https://app.example/reset?a=b&token=x#f",
		"/reset":                          "/reset?token=x",
	} {
		if got := SetQuery(target, url.Values{"token": {"x"}}); got != want {
			t.Errorf("SetQuery(%q) = %q, want %q", target, got, want)
		}
	}
}
