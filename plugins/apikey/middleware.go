package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
)

var headerPattern = regexp.MustCompile("^[!#$%&'*+.^_\x60|~a-zA-Z0-9-]+$")

func headerNames(input []string) ([]string, error) {
	if len(input) == 0 {
		return []string{"X-Api-Key"}, nil
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]bool, len(input))
	for _, header := range input {
		name := http.CanonicalHeaderKey(header)
		if !headerPattern.MatchString(header) || seen[name] {
			return nil, errors.New("apikey: invalid or repeated header name")
		}
		seen[name] = true
		result = append(result, name)
	}
	return result, nil
}

// credential returns the key and its source. An empty source means no credential.
func (s *Service) credential(r *http.Request) (secret, source string, err error) {
	if err := r.Context().Err(); err != nil {
		return "", "", err
	}
	if extract := s.opts.ExtractKey; extract != nil {
		value, present, err := extract(r)
		if err != nil {
			return "", "", hookFailure{errExtractor, err}
		}
		if err := r.Context().Err(); err != nil {
			return "", "", err
		}
		if !present && value == "" {
			return "", "", nil
		}
		if !present || !portableSecret(value) {
			return "", "", invalidSessionKey
		}
		return value, "custom extractor", nil
	}
	for _, name := range s.opts.Headers {
		values := r.Header.Values(name)
		if len(values) == 0 {
			continue
		}
		if len(values) != 1 || source != "" || values[0] == "" || len(values[0]) > 4096 {
			return "", "", invalidSessionKey
		}
		secret, source = values[0], name
	}
	return secret, source, nil
}

// VerifyRequest extracts and consumes one credential. Multiple built-in key
// headers are ambiguous. A custom extractor replaces those headers.
func (s *Service) VerifyRequest(r *http.Request, required Permissions) (Verification, error) {
	secret, _, err := s.credential(r)
	if errors.Is(err, invalidSessionKey) {
		return Verification{Error: &VerifyError{Code: "INVALID_API_KEY", Message: "Invalid API key"}}, nil
	}
	if err != nil {
		return Verification{}, err
	}
	return s.Verify(r.Context(), secret, required)
}

type verifiedKeyContext struct{}

// FromContext returns the verified key metadata for a request served by Middleware.
func FromContext(ctx context.Context) (*Key, bool) {
	v, ok := ctx.Value(verifiedKeyContext{}).(*Key)
	return v, ok
}

// Middleware protects an application handler with the configured key headers.
// The handler receives key metadata through FromContext after the policy and
// rate checks commit. It never creates a browser session.
func (s *Service) Middleware(required Permissions, next http.Handler) http.Handler {
	grants := clonePermissions(required)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, err := s.VerifyRequest(r, grants)
		if err == nil && v.Valid {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), verifiedKeyContext{}, v.Key)))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		status := http.StatusUnauthorized
		failure := v.Error
		if err != nil {
			status = http.StatusInternalServerError
			failure = &VerifyError{Code: "INTERNAL_SERVER_ERROR", Message: "Could not verify application credentials"}
		} else if failure.Code == "RATE_LIMIT_EXCEEDED" || failure.Code == "USAGE_EXCEEDED" {
			status = http.StatusTooManyRequests
			if failure.TryAgainIn != nil {
				w.Header().Set("Retry-After", strconv.FormatInt(max(1, (*failure.TryAgainIn+999)/1000), 10))
			}
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(failure)
	})
}
