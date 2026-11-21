package configenv

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// CookieDomain resolves an optional parent domain for a configured base host.
func CookieDomain(host, requested string) (string, error) {
	base, err := dnsCookieHost(host)
	if err != nil {
		return "", err
	}
	domain := base
	if requested != "" {
		domain, err = dnsCookieHost(strings.TrimPrefix(requested, "."))
		if err != nil {
			return "", err
		}
	}
	if base != domain && !strings.HasSuffix(base, "."+domain) {
		return "", errors.New("cookie domain must match the base hostname or one of its parent domains")
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(domain); err != nil {
		return "", errors.New("cookies cannot be shared on a public suffix")
	}
	return domain, nil
}

func dnsCookieHost(value string) (string, error) {
	dns, err := idna.Lookup.ToASCII(value)
	if err != nil || len(dns) > 253 || strings.Contains(dns, ":") {
		return "", errors.New("cookie domain must be a DNS hostname")
	}
	dns = strings.ToLower(dns)
	labels := strings.Split(dns, ".")
	if len(labels) < 2 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", errors.New("cookie sharing requires a registrable DNS hostname")
	}
	for _, label := range labels {
		badChar := strings.ContainsFunc(label, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-')
		})
		if badChar || len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("cookie domain contains an invalid DNS label")
		}
	}
	return dns, nil
}
