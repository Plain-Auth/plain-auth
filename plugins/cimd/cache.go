package cimd

import (
	"container/list"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// cacheEntry is a validated document with its freshness and validators.
// saved reports that the stored client matches it.
type cacheEntry struct {
	doc     oauthprovider.ClientMetadataDocument
	expires time.Time
	headers cacheHeaders
	saved   bool
}

// documentCache is a least-recently-used cache of validated documents.
type documentCache struct {
	max     int
	order   *list.List
	entries map[string]*list.Element
}

type cached struct {
	id    string
	entry *cacheEntry
}

func newDocumentCache(max int) *documentCache {
	return &documentCache{max: max, order: list.New(), entries: map[string]*list.Element{}}
}

// get returns a client's entry and marks it recently used.
func (c *documentCache) get(id string) *cacheEntry {
	if e, ok := c.entries[id]; ok {
		c.order.MoveToFront(e)
		return e.Value.(cached).entry
	}
	return nil
}

// peek returns a client's entry without marking it.
func (c *documentCache) peek(id string) *cacheEntry {
	if e, ok := c.entries[id]; ok {
		return e.Value.(cached).entry
	}
	return nil
}

func (c *documentCache) put(id string, entry *cacheEntry) {
	c.remove(id)
	for c.order.Len() >= c.max {
		c.remove(c.order.Back().Value.(cached).id)
	}
	c.entries[id] = c.order.PushFront(cached{id, entry})
}

func (c *documentCache) remove(id string) {
	if e, ok := c.entries[id]; ok {
		c.order.Remove(e)
		delete(c.entries, id)
	}
}

var digits = regexp.MustCompile(`^\d+$`)

// cacheControl parses Cache-Control directives, noting repeated ones.
func cacheControl(value string) (map[string]string, map[string]bool) {
	directives, repeated := map[string]string{}, map[string]bool{}
	for _, raw := range strings.Split(value, ",") {
		name, arg, _ := strings.Cut(strings.TrimSpace(raw), "=")
		name = strings.ToLower(name)
		if name == "" {
			continue
		}
		if _, ok := directives[name]; ok {
			repeated[name] = true
		}
		directives[name] = strings.Trim(strings.TrimSpace(arg), `"`)
	}
	return directives, repeated
}

func seconds(value string) (time.Duration, bool) {
	if !digits.MatchString(value) {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n > 1<<53-1 {
		return 0, false
	}
	// Lifetimes beyond what a Duration holds are capped there.
	return time.Duration(min(n, int64(math.MaxInt64/time.Second))) * time.Second, true
}

// freshness computes when a fetched document expires, as another runtime's
// computeExpiresAt does: no-store, private and Vary: * are not cached,
// no-cache is cached already expired, s-maxage wins over max-age, which wins
// over Expires, an invalid or repeated applicable directive gives no
// lifetime, Age and Date reduce it, and the revalidation interval caps it
// and stands in for a missing one.
func freshness(h cacheHeaders, interval time.Duration, now time.Time) (bool, time.Time) {
	directives, repeated := cacheControl(h.CacheControl)
	_, noStore := directives["no-store"]
	_, private := directives["private"]
	varyAll := false
	for _, field := range strings.Split(h.Vary, ",") {
		varyAll = varyAll || strings.TrimSpace(field) == "*"
	}
	if noStore || private || varyAll {
		return false, now
	}
	operator := max(interval, 0)
	if _, ok := directives["no-cache"]; ok {
		return true, now
	}
	age, _ := seconds(h.Age)
	date := now
	if parsed, ok := parseDate(h.Date); ok {
		date = parsed
	}
	current := max(now.Sub(date), age, 0)
	lifetime := operator
	shared, hasShared := directives["s-maxage"]
	own, hasOwn := directives["max-age"]
	switch {
	case hasShared:
		maxAge, ok := seconds(shared)
		if !ok || repeated["s-maxage"] {
			maxAge = 0
		}
		lifetime = min(operator, max(maxAge-current, 0))
	case hasOwn:
		maxAge, ok := seconds(own)
		if !ok || repeated["max-age"] {
			maxAge = 0
		}
		lifetime = min(operator, max(maxAge-current, 0))
	case h.Expires != "":
		// An invalid date, such as "0", means already expired (RFC 9111
		// section 5.3), where another runtime keeps the interval for a value
		// its date parser refuses.
		lifetime = 0
		if expires, ok := parseDate(h.Expires); ok {
			// Subtracting only a smaller age cannot wrap around.
			if remaining := expires.Sub(date); remaining > current {
				lifetime = min(operator, remaining-current)
			}
		}
	}
	return true, now.Add(lifetime)
}

// mergeHeaders keeps a revalidated response's caching headers over the
// cached ones.
func mergeHeaders(previous, revalidated cacheHeaders) cacheHeaders {
	pick := func(next, old string) string {
		if next != "" {
			return next
		}
		return old
	}
	return cacheHeaders{pick(revalidated.CacheControl, previous.CacheControl), pick(revalidated.Vary, previous.Vary), pick(revalidated.Expires, previous.Expires),
		pick(revalidated.Date, previous.Date), pick(revalidated.Age, previous.Age), pick(revalidated.ETag, previous.ETag), pick(revalidated.LastModified, previous.LastModified)}
}

// zoneHours are the zone names another runtime's date parser reads in an
// RFC 1123 date, as hours from UTC.
var zoneHours = map[string]int{"UT": 0, "UTC": 0, "GMT": 0, "Z": 0, "EST": -5, "EDT": -4, "CST": -6, "CDT": -5, "MST": -7, "MDT": -6, "PST": -8, "PDT": -7}

// parseDate reads an HTTP date, also in RFC 1123 with a numeric zone or a
// zone name in zoneHours, and in RFC 3339, which another runtime's date
// parser accepts too. Other zone names do not parse, so the host's own time
// zone never decides.
func parseDate(value string) (time.Time, bool) {
	if t, err := http.ParseTime(value); err == nil {
		return t, true
	}
	for _, layout := range []string{time.RFC1123Z, time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	if i := strings.LastIndexByte(value, ' '); i > 0 {
		if hours, ok := zoneHours[value[i+1:]]; ok {
			if t, err := time.ParseInLocation("Mon, 02 Jan 2006 15:04:05", value[:i], time.UTC); err == nil {
				return t.Add(-time.Duration(hours) * time.Hour), true
			}
		}
	}
	return time.Time{}, false
}
