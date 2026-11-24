package httporigin

import (
	"strings"
	"testing"
	"time"
)

// Several ** segments stay linear in the URL's segments.
func TestMatchSegmentsIsLinear(t *testing.T) {
	pattern := splitPath("/**/a/**/b/**/c/**/d/**/e")
	segments := splitPath("/" + strings.Repeat("x/", 2000) + "z")
	start := time.Now()
	if matchSegments(pattern, segments) {
		t.Fatal("matched a path without the required segments")
	}
	if time.Since(start) > time.Second {
		t.Fatal("matching took too long", time.Since(start))
	}
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"/**", "", true}, {"/**", "/a/b", true}, {"/a/**", "/a", true}, {"/a/**", "/ab", false},
		{"/**/cb", "/x/y/cb", true}, {"/**/cb", "/x/cb/y", false}, {"/a/*/c", "/a/b/c", true}, {"/a/*/c", "/a/b/x/c", false},
	} {
		if got := matchSegments(splitPath(tc.pattern), splitPath(tc.path)); got != tc.want {
			t.Errorf("%s against %s: got %v", tc.pattern, tc.path, got)
		}
	}
}
