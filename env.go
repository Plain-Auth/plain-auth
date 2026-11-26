package plainauth

import (
	"errors"
	"fmt"
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
	mode := os.Getenv("AUTH_ENV")
	if opts.RateLimit == nil && mode != "" {
		enabled := mode == "production"
		opts.RateLimit = &enabled
	}
	if opts.ErrorRedirectURL == "" && opts.ErrorPage == nil && mode == "production" {
		opts.ErrorRedirectURL = "/"
	}
	if opts.Secret == "" {
		opts.Secret = os.Getenv("AUTH_SECRET")
	}
	if opts.Secrets == nil {
		if raw := os.Getenv("AUTH_SECRETS"); raw != "" {
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
	if opts.BaseURL == "" && opts.DynamicBaseURL == nil {
		opts.BaseURL = os.Getenv("AUTH_URL")
	}
	opts.TrustedOrigins = append([]string(nil), opts.TrustedOrigins...)
	if raw := os.Getenv("AUTH_TRUSTED_ORIGINS"); raw != "" {
		for value := range strings.SplitSeq(raw, ",") {
			if origin := strings.TrimSpace(value); origin != "" {
				opts.TrustedOrigins = append(opts.TrustedOrigins, origin)
			}
		}
	}
	return nil
}
