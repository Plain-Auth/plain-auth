package plainauth

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

var errOAuthQuery = errors.New("auth: invalid or expired signed OAuth query")

// OAuth page signatures use the browser's form encoding and UTF-16 sort order.
func oauthFormString(values url.Values) string {
	keys := slices.Collect(maps.Keys(values))
	less := func(a, b string) bool { return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) < 0 }
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })
	encode := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(s), "~", "%7E"), "%2A", "*")
	}
	var form strings.Builder
	for _, k := range keys {
		items := slices.Clone(values[k])
		sort.Slice(items, func(i, j int) bool { return less(items[i], items[j]) })
		for _, v := range items {
			if form.Len() > 0 {
				form.WriteByte('&')
			}
			form.WriteString(encode(k))
			form.WriteByte('=')
			form.WriteString(encode(v))
		}
	}
	return form.String()
}

// SignOAuthQuery signs the fields for a validated, issuer-controlled interaction.
// The returned form includes the expiry and the names of all covered fields.
func (a *Auth) SignOAuthQuery(fields url.Values, expires time.Time) string {
	return a.SignOAuthConsentQuery(fields, expires, "")
}

// SignOAuthConsentQuery signs a consent page after the issuer has verified its
// post-login step for clearedSessionID. An empty ID omits that attestation.
func (a *Auth) SignOAuthConsentQuery(fields url.Values, expires time.Time, clearedSessionID string) string {
	q := maps.Clone(fields)
	if q == nil {
		q = url.Values{}
	}
	q.Del("sig")
	q.Del("ba_param")
	q.Del("ba_pl")
	if clearedSessionID != "" {
		q.Set("ba_pl", clearedSessionID)
	}
	q.Set("ba_iat", strconv.FormatInt(a.now().UnixMilli(), 10))
	q.Set("exp", strconv.FormatInt(expires.Unix(), 10))
	q["ba_param"] = append(slices.Sorted(maps.Keys(q)), "ba_param")
	q.Set("sig", signCookieValue(oauthFormString(q), a.opts.Secret))
	return q.Encode()
}

// VerifyOAuthPageQuery extracts verified fields from a host interaction page.
// Page-local query parameters outside the signed manifest are omitted.
func (a *Auth) VerifyOAuthPageQuery(raw string) (url.Values, error) {
	q, err := url.ParseQuery(raw)
	if err != nil || len(q["ba_param"]) == 0 {
		return nil, errOAuthQuery
	}
	keep := map[string]bool{"sig": true, "ba_param": true}
	for _, name := range q["ba_param"] {
		keep[name] = true
	}
	for name := range q {
		if !keep[name] {
			q.Del(name)
		}
	}
	return a.verifyOAuthQuery(q)
}

// VerifyOAuthQuery authenticates the exact form submitted to the issuer.
func (a *Auth) VerifyOAuthQuery(raw string) (url.Values, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, errOAuthQuery
	}
	return a.verifyOAuthQuery(q)
}

func (a *Auth) verifyOAuthQuery(q url.Values) (url.Values, error) {
	if len(q["sig"]) != 1 || len(q["exp"]) != 1 {
		return nil, errOAuthQuery
	}
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil || a.now().After(time.Unix(exp, 0)) {
		return nil, errOAuthQuery
	}
	signature := strings.NewReplacer(" ", "+", "-", "+", "_", "/").Replace(q.Get("sig"))
	mac, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimRight(signature, "="))
	if err != nil || len(mac) != 32 {
		return nil, errOAuthQuery
	}
	q.Del("sig")
	canonical := oauthFormString(q)
	wire := base64.StdEncoding.EncodeToString(mac)
	matches := func(secret string) bool {
		return hmac.Equal([]byte(wire), []byte(signCookieValue(canonical, secret)))
	}
	valid := matches(a.opts.Secret)
	for i := 1; !valid && i < len(a.opts.Secrets); i++ {
		valid = matches(a.opts.Secrets[i].Value)
	}
	if !valid {
		return nil, errOAuthQuery
	}
	q.Set("sig", wire)
	return q, nil
}
