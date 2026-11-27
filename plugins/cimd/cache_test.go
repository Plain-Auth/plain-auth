package cimd

import (
	"net/http"
	"testing"
	"time"
)

// Document freshness follows the response's caching headers under the
// revalidation interval.
func TestFreshness(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	date := func(d time.Duration) string { return now.Add(d).Format(http.TimeFormat) }
	// zoned writes an RFC 1123 date in a zone hours from UTC, by its name.
	zoned := func(d time.Duration, hours int, name string) string {
		return now.Add(d).In(time.FixedZone("", hours*3600)).Format("Mon, 02 Jan 2006 15:04:05") + " " + name
	}
	for name, tc := range map[string]struct {
		h         cacheHeaders
		interval  time.Duration
		cacheable bool
		lifetime  time.Duration
	}{
		"default":                {cacheHeaders{}, time.Hour, true, time.Hour},
		"max-age":                {cacheHeaders{CacheControl: "max-age=600"}, time.Hour, true, 10 * time.Minute},
		"capped":                 {cacheHeaders{CacheControl: "max-age=7200"}, time.Hour, true, time.Hour},
		"s-maxage wins":          {cacheHeaders{CacheControl: "max-age=600, s-maxage=60"}, time.Hour, true, time.Minute},
		"s-maxage zero":          {cacheHeaders{CacheControl: "s-maxage=0, max-age=600"}, time.Hour, true, 0},
		"repeated max-age":       {cacheHeaders{CacheControl: "max-age=60, max-age=600"}, time.Hour, true, 0},
		"invalid max-age":        {cacheHeaders{CacheControl: "max-age=soon"}, time.Hour, true, 0},
		"quoted":                 {cacheHeaders{CacheControl: `max-age="120"`}, time.Hour, true, 2 * time.Minute},
		"age":                    {cacheHeaders{CacheControl: "max-age=600", Age: "100"}, time.Hour, true, 500 * time.Second},
		"date":                   {cacheHeaders{CacheControl: "max-age=600", Date: date(-200 * time.Second)}, time.Hour, true, 400 * time.Second},
		"expires":                {cacheHeaders{Expires: date(5 * time.Minute), Date: date(0)}, time.Hour, true, 5 * time.Minute},
		"max-age over exp":       {cacheHeaders{CacheControl: "max-age=60", Expires: date(5 * time.Minute)}, time.Hour, true, time.Minute},
		"no-cache":               {cacheHeaders{CacheControl: "no-cache"}, time.Hour, true, 0},
		"no-store":               {cacheHeaders{CacheControl: "no-store"}, time.Hour, false, 0},
		"private":                {cacheHeaders{CacheControl: "private, max-age=60"}, time.Hour, false, 0},
		"vary star":              {cacheHeaders{Vary: "Accept, *"}, time.Hour, false, 0},
		"every resolution":       {cacheHeaders{CacheControl: "max-age=600"}, -1, true, 0},
		"uppercase":              {cacheHeaders{CacheControl: "MAX-AGE=60"}, time.Hour, true, time.Minute},
		"past expires":           {cacheHeaders{Expires: date(-time.Minute), Date: date(0)}, time.Hour, true, 0},
		"bad expires":            {cacheHeaders{Expires: "tomorrow"}, time.Hour, true, 0},
		"expires zero":           {cacheHeaders{Expires: "0"}, time.Hour, true, 0},
		"huge max-age":           {cacheHeaders{CacheControl: "max-age=10000000000"}, time.Hour, true, time.Hour},
		"huge age":               {cacheHeaders{CacheControl: "max-age=600", Age: "10000000000"}, time.Hour, true, 0},
		"unsafe max-age":         {cacheHeaders{CacheControl: "max-age=99999999999999999999"}, time.Hour, true, 0},
		"age over max-age":       {cacheHeaders{CacheControl: "max-age=60", Age: "600"}, time.Hour, true, 0},
		"date in the future":     {cacheHeaders{CacheControl: "max-age=60", Date: date(time.Hour)}, time.Hour, true, time.Minute},
		"past expires, huge age": {cacheHeaders{Expires: date(-time.Minute), Date: date(0), Age: "10000000000"}, time.Hour, true, 0},
		"year one expires":       {cacheHeaders{Expires: "Mon, 01 Jan 0001 00:00:00 GMT", Date: date(-time.Second)}, time.Hour, true, 0},
		"utc expires":            {cacheHeaders{Expires: now.Add(5 * time.Minute).Format(time.RFC1123), Date: date(0)}, time.Hour, true, 5 * time.Minute},
		"numeric zone expires":   {cacheHeaders{Expires: now.Add(5 * time.Minute).In(time.FixedZone("", 3600)).Format(time.RFC1123Z), Date: date(0)}, time.Hour, true, 5 * time.Minute},
		"iso expires":            {cacheHeaders{Expires: now.Add(5 * time.Minute).Format(time.RFC3339), Date: date(0)}, time.Hour, true, 5 * time.Minute},
		"est expires":            {cacheHeaders{Expires: zoned(5*time.Minute, -5, "EST"), Date: date(0)}, time.Hour, true, 5 * time.Minute},
		"pdt date":               {cacheHeaders{CacheControl: "max-age=600", Date: zoned(-200*time.Second, -7, "PDT")}, time.Hour, true, 400 * time.Second},
		"unknown zone expires":   {cacheHeaders{Expires: zoned(5*time.Minute, 1, "CET"), Date: date(0)}, time.Hour, true, 0},
	} {
		cacheable, expires := freshness(tc.h, tc.interval, now)
		if cacheable != tc.cacheable || (cacheable && expires.Sub(now) != tc.lifetime) {
			t.Error("wrong freshness for", name, cacheable, expires.Sub(now))
		}
	}
}

// The cache evicts the least recently used entry at its bound.
func TestDocumentCache(t *testing.T) {
	c := newDocumentCache(2)
	a, b, d := &cacheEntry{}, &cacheEntry{}, &cacheEntry{}
	c.put("a", a)
	c.put("b", b)
	c.get("a")
	c.put("d", d)
	if c.peek("b") != nil || c.peek("a") != a || c.peek("d") != d {
		t.Fatal("the least recently used entry was not evicted")
	}
	c.put("a", b)
	if c.peek("a") != b || c.order.Len() != 2 {
		t.Fatal("a replaced entry was duplicated")
	}
	merged := mergeHeaders(cacheHeaders{ETag: `"1"`, CacheControl: "max-age=1"}, cacheHeaders{CacheControl: "max-age=2"})
	if merged.ETag != `"1"` || merged.CacheControl != "max-age=2" {
		t.Fatal("revalidated headers were not merged", merged)
	}
}
