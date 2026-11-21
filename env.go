package authn

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// VersionedSecret identifies a signing key. The first entry issues credentials.
// Keep previous entries only for as long as credentials they signed should work.
type VersionedSecret struct {
	Version int
	Value   string
}

// resolveEnvironment takes a startup snapshot. It never modifies the host process.
func resolveEnvironment(opts *Options) error {
	first := func(names ...string) string {
		for _, name := range names {
			if value := os.Getenv(name); value != "" {
				return value
			}
		}
		return ""
	}
	if mode := first("AUTH_ENV", "NODE_ENV"); opts.RateLimit == nil && mode != "" {
		enabled := mode == "production"
		opts.RateLimit = &enabled
	}
	if opts.ErrorRedirectURL == "" && first("AUTH_ENV", "NODE_ENV") == "production" {
		opts.ErrorRedirectURL = "/"
	}
	if opts.Secret == "" {
		opts.Secret = first("BETTER_AUTH_SECRET", "AUTH_SECRET")
	}
	if opts.Secrets == nil {
		if raw := first("BETTER_AUTH_SECRETS", "AUTH_SECRETS"); raw != "" {
			for i, field := range strings.Split(raw, ",") {
				number, value, found := strings.Cut(strings.TrimSpace(field), ":")
				version, err := strconv.Atoi(number)
				if !found || err != nil || strconv.Itoa(version) != number {
					return fmt.Errorf("auth: invalid key version at position %d", i+1)
				}
				opts.Secrets = append(opts.Secrets, VersionedSecret{Version: version, Value: strings.TrimSpace(value)})
			}
		}
	}
	if opts.Secrets != nil {
		if len(opts.Secrets) == 0 {
			return errors.New("auth: empty signing key list")
		}
		opts.Secrets = append([]VersionedSecret(nil), opts.Secrets...)
		seen := map[int]bool{}
		for _, key := range opts.Secrets {
			if key.Version < 0 || seen[key.Version] || len(key.Value) < 32 {
				return errors.New("auth: signing keys require distinct non-negative versions and at least 32 bytes")
			}
			seen[key.Version] = true
		}
	}
	if opts.BaseURL == "" {
		opts.BaseURL = first("BETTER_AUTH_URL", "AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL", "PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL")
		if opts.BaseURL == "/" {
			opts.BaseURL = ""
		}
	}
	// A configured URL can include a mount path. A separately specified
	// BasePath wins to support routers that mount the handler elsewhere.
	if u, err := url.Parse(opts.BaseURL); err == nil && u.Host != "" && u.Path != "" && u.Path != "/" {
		if opts.BasePath == "" {
			opts.BasePath = strings.TrimRight(u.EscapedPath(), "/")
		}
		u.Path, u.RawPath = "", ""
		opts.BaseURL = u.String()
	}
	opts.TrustedOrigins = append([]string(nil), opts.TrustedOrigins...)
	if raw := first("BETTER_AUTH_TRUSTED_ORIGINS", "AUTH_TRUSTED_ORIGINS"); raw != "" {
		for value := range strings.SplitSeq(raw, ",") {
			if origin := strings.TrimSpace(value); origin != "" {
				opts.TrustedOrigins = append(opts.TrustedOrigins, origin)
			}
		}
	}
	return nil
}
