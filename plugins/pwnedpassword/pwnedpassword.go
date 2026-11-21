// Package pwnedpassword checks proposed credentials against the Pwned Passwords range API.
package pwnedpassword

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	authn "github.com/FineStack/frost-auth"
)

// Options configures a server-side password check. A nil Paths slice selects
// the defaults; a non-nil slice replaces them. A nil Enabled value means true.
type Options struct {
	Enabled                          *bool
	Paths                            []string
	CustomPasswordCompromisedMessage string
	// Transport overrides the range HTTP transport, for example for local tests.
	Transport http.RoundTripper
}

var defaultPaths = []string{"/sign-up/email", "/change-password", "/reset-password", "/email-otp/reset-password", "/phone-number/reset-password", "/admin/create-user", "/admin/set-user-password"}

// New installs checks at the selected credential-setting paths.
func New(o Options) authn.Plugin {
	plugin := authn.Plugin{ID: "have-i-been-pwned"}
	if o.Enabled != nil && !*o.Enabled {
		return plugin
	}
	paths := slices.Clone(o.Paths)
	if paths == nil {
		paths = defaultPaths
	}
	message := o.CustomPasswordCompromisedMessage
	if message == "" {
		message = "The password you entered has been compromised. Please choose a different password."
	}
	plugin.OnValidateNewPassword = func(ctx context.Context, path, password string) error {
		if !slices.Contains(paths, path) {
			return nil
		}
		unsafe, err := IsPasswordCompromised(ctx, password, o.Transport)
		if err != nil {
			return err
		}
		if unsafe {
			return &authn.APIError{Status: 400, Code: "PASSWORD_COMPROMISED", Message: message}
		}
		return nil
	}
	return plugin
}

func failed() error {
	return &authn.APIError{Status: 500, Code: "INTERNAL_SERVER_ERROR", Message: "Failed to check password. Please try again later."}
}

// IsPasswordCompromised checks a single proposed password. It sends the first
// five hexadecimal characters of the SHA-1 digest and compares suffixes locally.
// Pass nil for the normal HTTPS transport. An unavailable service returns an error.
func IsPasswordCompromised(ctx context.Context, password string, transport http.RoundTripper) (bool, error) {
	// SHA-1 is part of the range lookup protocol. Credential storage uses scrypt.
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+digest[:5], nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Go Authentication Password Checker")
	client := http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, failed()
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, &authn.APIError{Status: 500, Code: "INTERNAL_SERVER_ERROR", Message: fmt.Sprintf("Failed to check password. Status: %d", res.StatusCode)}
	}
	const maxRangeBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(res.Body, maxRangeBytes+1))
	if err != nil || len(body) > maxRangeBytes {
		return false, failed()
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		suffix, count, ok := strings.Cut(strings.TrimSuffix(line, "\r"), ":")
		if !ok || !strings.EqualFold(suffix, digest[5:]) {
			continue
		}
		n, err := strconv.ParseUint(count, 10, 53)
		if err != nil || strconv.FormatUint(n, 10) != count {
			return false, failed()
		}
		return n > 0, nil
	}
	return false, nil
}
