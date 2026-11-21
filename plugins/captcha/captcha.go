// Package captcha verifies challenge tokens on selected authentication HTTP routes.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	authn "github.com/FineStack/finestack-auth"
)

type Provider string

const (
	CloudflareTurnstile Provider = "cloudflare-turnstile"
	GoogleRecaptcha     Provider = "google-recaptcha"
	HCaptcha            Provider = "hcaptcha"
	CaptchaFox          Provider = "captchafox"
	VercelBotID         Provider = "vercel-botid"
)

var verifyURLs = map[Provider]string{
	CloudflareTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	GoogleRecaptcha:     "https://www.google.com/recaptcha/api/siteverify",
	HCaptcha:            "https://api.hcaptcha.com/siteverify",
	CaptchaFox:          "https://api.captchafox.com/siteverify",
}

type BotIDVerdict struct {
	IsBot, IsVerifiedBot                 bool
	VerifiedBotName, VerifiedBotCategory string
}

// Options selects the verification protocol and auth-mount-relative endpoints.
// CheckBotID and ValidateRequest receive the request with a ten-second deadline
// and must respect its context. Transport can inject a local verifier.
type Options struct {
	Provider              Provider
	SecretKey, SiteKey    string
	Endpoints             []string
	SiteVerifyURLOverride string
	ExpectedAction        string
	AllowedHostnames      []string
	MinScore              *float64
	Transport             http.RoundTripper
	CheckBotID            func(*http.Request) (BotIDVerdict, error)
	ValidateRequest       func(*http.Request, BotIDVerdict) (bool, error)
}

var defaultEndpoints = []string{"/sign-up/email", "/sign-in/email", "/request-password-reset"}

const verificationTimeout = 10 * time.Second

func New(o Options) (authn.Plugin, error) {
	address, ok := verifyURLs[o.Provider]
	if !ok && o.Provider != VercelBotID {
		return authn.Plugin{}, errors.New("captcha: unknown provider")
	}
	if o.Provider == VercelBotID && o.CheckBotID == nil {
		return authn.Plugin{}, errors.New("captcha: BotID requires a check callback")
	}
	if o.SiteVerifyURLOverride != "" {
		u, err := url.Parse(o.SiteVerifyURLOverride)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return authn.Plugin{}, errors.New("captcha: invalid verification URL")
		}
		address = o.SiteVerifyURLOverride
	}
	paths := o.Endpoints
	if len(paths) == 0 {
		paths = defaultEndpoints
	}
	matches, err := compilePaths(paths)
	if err != nil {
		return authn.Plugin{}, err
	}
	allowed := slices.Clone(o.AllowedHostnames)
	score := 0.5
	if o.MinScore != nil {
		score = *o.MinScore
		if math.IsNaN(score) || math.IsInf(score, 0) {
			return authn.Plugin{}, errors.New("captcha: invalid minimum score")
		}
	}
	client := &http.Client{Transport: o.Transport, Timeout: verificationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// A host BotID callback may block even after its context expires. Bound
	// outstanding callbacks while ensuring the auth request meets its deadline.
	var botWorkers chan struct{}
	if o.Provider == VercelBotID {
		botWorkers = make(chan struct{}, 64)
	}
	return authn.Plugin{ID: "captcha", OnRequest: func(c authn.RequestContext) error {
		if !matches(normalize(c.Path)) {
			return nil
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), verificationTimeout)
		defer cancel()
		if o.Provider == VercelBotID {
			return verifyBot(ctx, c.Request, o, botWorkers)
		}
		if o.SecretKey == "" {
			return unavailable()
		}
		values := c.Request.Header.Values("X-Captcha-Response")
		if len(values) != 1 || values[0] == "" {
			return &authn.APIError{Status: 400, Code: "MISSING_RESPONSE", Message: "Missing CAPTCHA response"}
		}
		result, err := verifyToken(ctx, client, address, o, values[0], c.ClientIP)
		if err != nil {
			return unavailable()
		}
		if !result.Success {
			return denied()
		}
		if o.Provider == GoogleRecaptcha && result.Score != nil && *result.Score < score {
			return denied()
		}
		if o.Provider == GoogleRecaptcha || o.Provider == CloudflareTurnstile {
			if o.ExpectedAction != "" && result.Action != o.ExpectedAction {
				return denied()
			}
			if len(allowed) != 0 && (result.Hostname == "" || !slices.Contains(allowed, result.Hostname)) {
				return denied()
			}
		}
		return nil
	}}, nil
}

func unavailable() error {
	return &authn.APIError{Status: 500, Code: "UNKNOWN_ERROR", Message: "Something went wrong"}
}
func denied() error {
	return &authn.APIError{Status: 403, Code: "VERIFICATION_FAILED", Message: "Captcha verification failed"}
}

func verifyBot(ctx context.Context, r *http.Request, o Options, workers chan struct{}) error {
	select {
	case workers <- struct{}{}:
	case <-ctx.Done():
		return unavailable()
	}
	result := make(chan error, 1)
	go func() {
		defer func() {
			<-workers
			if recovered := recover(); recovered != nil {
				result <- unavailable()
			}
		}()
		request := r.WithContext(ctx)
		verdict, err := o.CheckBotID(request)
		if err != nil || ctx.Err() != nil {
			result <- unavailable()
			return
		}
		allowed := !verdict.IsBot
		if o.ValidateRequest != nil {
			allowed, err = o.ValidateRequest(request, verdict)
			if err != nil {
				result <- unavailable()
				return
			}
		}
		if !allowed {
			result <- denied()
			return
		}
		result <- nil
	}()
	select {
	case <-ctx.Done():
		return unavailable()
	case err := <-result:
		if ctx.Err() != nil {
			return unavailable()
		}
		return err
	}
}

type verification struct {
	Success  bool     `json:"success"`
	Score    *float64 `json:"score"`
	Action   string   `json:"action"`
	Hostname string   `json:"hostname"`
}

func verifyToken(ctx context.Context, client *http.Client, address string, o Options, token, ip string) (verification, error) {
	fields := map[string]string{"secret": o.SecretKey, "response": token}
	if ip != "" {
		key := "remoteip"
		if o.Provider == CaptchaFox {
			key = "remoteIp"
		}
		fields[key] = ip
	}
	if (o.Provider == HCaptcha || o.Provider == CaptchaFox) && o.SiteKey != "" {
		fields["sitekey"] = o.SiteKey
	}
	var body string
	contentType := "application/x-www-form-urlencoded"
	if o.Provider == CloudflareTurnstile {
		data, err := json.Marshal(fields)
		if err != nil {
			return verification{}, err
		}
		body = string(data)
		contentType = "application/json"
	} else {
		form := url.Values{}
		for k, v := range fields {
			form.Set(k, v)
		}
		body = form.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, strings.NewReader(body))
	if err != nil {
		return verification{}, err
	}
	req.Header.Set("Content-Type", contentType)
	res, err := client.Do(req)
	if err != nil {
		return verification{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return verification{}, errors.New("captcha: provider unavailable")
	}
	const maxBytes = 1 << 16
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return verification{}, errors.New("captcha: invalid provider response")
	}
	var v *verification
	if err := json.Unmarshal(data, &v); err != nil || v == nil {
		return verification{}, errors.New("captcha: invalid verification response")
	}
	return *v, nil
}

// Normalization mirrors the public route matcher: repeated and trailing slashes
// are ignored while dots and escaped delimiters retain their original meaning.
func normalize(p string) string {
	return "/" + strings.Join(strings.FieldsFunc(p, func(r rune) bool { return r == '/' }), "/")
}

func compilePaths(paths []string) (func(string) bool, error) {
	exact := map[string]bool{}
	var patterns []*regexp.Regexp
	for _, pattern := range paths {
		if !strings.HasPrefix(pattern, "/") {
			return nil, errors.New("captcha: route must begin with a slash")
		}
		if !strings.Contains(pattern, "*") {
			exact[pattern] = true
			continue
		}
		var expr strings.Builder
		expr.WriteString("^")
		for _, part := range strings.Split(strings.TrimPrefix(pattern, "/"), "/") {
			if part == "**" {
				expr.WriteString("(?:/[^/]+)*")
				continue
			}
			expr.WriteByte('/')
			for i := 0; i < len(part); i++ {
				switch part[i] {
				case '*':
					expr.WriteString("[^/]*")
				case '?':
					expr.WriteString("[^/]")
				case '\\':
					if i+1 < len(part) {
						i++
						expr.WriteString(regexp.QuoteMeta(part[i : i+1]))
					}
				default:
					expr.WriteString(regexp.QuoteMeta(part[i : i+1]))
				}
			}
		}
		expr.WriteString("$")
		re, err := regexp.Compile(expr.String())
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, re)
	}
	return func(route string) bool {
		if exact[route] {
			return true
		}
		for _, re := range patterns {
			if re.MatchString(route) {
				return true
			}
		}
		return false
	}, nil
}
