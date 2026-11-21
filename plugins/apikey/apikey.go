// Package apikey provides user-owned application credentials with independent
// expiration, scoped permissions, usage budgets and per-key rate limits.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf16"

	stonewrit "github.com/Stonewrit/stonewrit-auth"
)

type Permissions map[string][]string

// Key is safe to include in management and verification responses.
type Key struct {
	ID                  string         `json:"id"`
	ConfigID            string         `json:"configId"`
	ReferenceID         string         `json:"referenceId"`
	Name                *string        `json:"name"`
	Prefix              *string        `json:"prefix"`
	Start               *string        `json:"start"`
	Enabled             bool           `json:"enabled"`
	RateLimitEnabled    bool           `json:"rateLimitEnabled"`
	RateLimitTimeWindow *int64         `json:"rateLimitTimeWindow"`
	RateLimitMax        *int64         `json:"rateLimitMax"`
	RequestCount        int64          `json:"requestCount"`
	Remaining           *int64         `json:"remaining"`
	RefillInterval      *int64         `json:"refillInterval"`
	RefillAmount        *int64         `json:"refillAmount"`
	LastRefillAt        *time.Time     `json:"lastRefillAt"`
	LastRequest         *time.Time     `json:"lastRequest"`
	ExpiresAt           *time.Time     `json:"expiresAt"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
	Permissions         Permissions    `json:"permissions"`
	Metadata            map[string]any `json:"metadata"`
}

// Created includes the only recoverable copy of the secret.
type Created struct {
	Key
	Secret string `json:"key"`
}

type Owner struct{ UserID, SessionToken string }
type Lookup struct{ ConfigID, ID, Digest string }
type Mutation uint8

const (
	Read Mutation = iota
	Save
	Remove
)

type PageOptions struct {
	Limit, Offset         *int
	SortBy, SortDirection string
}
type Page struct {
	Keys   []Key `json:"apiKeys"`
	Total  int   `json:"total"`
	Limit  *int  `json:"limit,omitempty"`
	Offset *int  `json:"offset,omitempty"`
}

// Store rechecks ownership and session validity and serializes the decision on
// each key with its write. An empty owner is supported only for digest lookup.
type Store interface {
	CheckAPIKeySchema(context.Context) error
	CreateAPIKey(context.Context, Owner, Key, string) error
	WithAPIKey(context.Context, Owner, Lookup, time.Time, func(*Key) (Mutation, error)) error
	ListAPIKeys(context.Context, Owner, string, time.Time, PageOptions) (Page, error)
	DeleteExpiredAPIKeys(context.Context, string, time.Time) (int64, error)
}

type Options struct {
	// Headers names the request headers accepted by Middleware. The default is X-API-Key.
	Headers                                                                           []string
	Store                                                                             Store
	ConfigID, DefaultPrefix                                                           string
	KeyLength, StartLength                                                            int
	HideStart, RequireName, EnableMetadata, DisableCustomExpiration, DisableRateLimit bool
	MinNameLength, MaxNameLength, MinPrefixLength, MaxPrefixLength                    int
	MinExpiration, MaxExpiration, DefaultExpiration, RateWindow                       time.Duration
	RateMax                                                                           int64
	DefaultPermissions                                                                Permissions
}
type Service struct{ opts Options }

var safePrefix = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func New(o Options) (*Service, error) {
	if o.Store == nil {
		return nil, errors.New("apikey: a store is required")
	}
	if o.ConfigID == "" {
		o.ConfigID = "default"
	}
	if o.KeyLength == 0 {
		o.KeyLength = 64
	}
	if o.StartLength == 0 {
		o.StartLength = 6
	}
	if o.MinNameLength == 0 {
		o.MinNameLength = 1
	}
	if o.MaxNameLength == 0 {
		o.MaxNameLength = 32
	}
	if o.MinPrefixLength == 0 {
		o.MinPrefixLength = 1
	}
	if o.MaxPrefixLength == 0 {
		o.MaxPrefixLength = 32
	}
	if o.MinExpiration == 0 {
		o.MinExpiration = 24 * time.Hour
	}
	if o.MaxExpiration == 0 {
		o.MaxExpiration = 365 * 24 * time.Hour
	}
	if o.RateWindow == 0 {
		o.RateWindow = 24 * time.Hour
	}
	if o.RateMax == 0 {
		o.RateMax = 10
	}
	if len(o.ConfigID) > 191 || o.KeyLength < 32 || o.KeyLength > 1024 ||
		o.StartLength < 1 || o.StartLength > o.KeyLength-24 {
		return nil, errors.New("apikey: invalid generation or display length")
	}
	if o.MinNameLength < 1 || o.MaxNameLength < o.MinNameLength ||
		o.MinPrefixLength < 1 || o.MaxPrefixLength < o.MinPrefixLength || o.MaxPrefixLength > 128 {
		return nil, errors.New("apikey: invalid name or prefix length")
	}
	if o.MinExpiration < time.Second || o.MaxExpiration < o.MinExpiration || o.DefaultExpiration < 0 ||
		o.RateWindow.Milliseconds() < 1 || o.RateWindow.Milliseconds() > 2147483647 || o.RateMax < 1 || o.RateMax > 2147483647 {
		return nil, errors.New("apikey: invalid expiration or rate policy")
	}
	if o.DefaultPrefix != "" && (!safePrefix.MatchString(o.DefaultPrefix) || len(o.DefaultPrefix) < o.MinPrefixLength || len(o.DefaultPrefix) > o.MaxPrefixLength) {
		return nil, errors.New("apikey: invalid default prefix")
	}
	o.DefaultPermissions = clonePermissions(o.DefaultPermissions)
	headers, err := headerNames(o.Headers)
	if err != nil {
		return nil, err
	}
	o.Headers = headers
	return &Service{opts: o}, nil
}

func clonePermissions(source Permissions) Permissions {
	if source == nil {
		return nil
	}
	destination := make(Permissions, len(source))
	for resource, actions := range source {
		destination[resource] = slices.Clone(actions)
	}
	return destination
}

type Policy struct {
	Enabled, RateLimitEnabled             *bool
	RateLimitMax, Remaining, RefillAmount *int64
	RateWindow, RefillInterval            *time.Duration
	Permissions                           Permissions
}

type CreateInput struct {
	Name, Prefix string
	ExpiresIn    time.Duration
	Metadata     map[string]any
	Policy       Policy
}
type UpdateInput struct {
	Name      *string
	ExpiresIn *time.Duration
	Metadata  map[string]any
	Policy    Policy
}

func (in UpdateInput) empty() bool {
	p := in.Policy
	return in.Name == nil && in.ExpiresIn == nil && in.Metadata == nil &&
		p.Enabled == nil && p.RateLimitEnabled == nil && p.RateLimitMax == nil &&
		p.Remaining == nil && p.RefillAmount == nil && p.RateWindow == nil &&
		p.RefillInterval == nil && p.Permissions == nil
}

func problem(status int, code, msg string) *stonewrit.APIError {
	return &stonewrit.APIError{Status: status, Code: code, Message: msg}
}

var ErrMissing = problem(404, "KEY_NOT_FOUND", "API Key not found")
var ErrSession = problem(401, "UNAUTHORIZED_SESSION", "Unauthorized or invalid session")
var ErrBanned = problem(403, "USER_BANNED", "User is banned")

func Digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func ptr[T any](v T) *T { return &v }
func textPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func current() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

func randomSecret(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	buf := make([]byte, 0, length)
	// 208 is the largest multiple of 52 below 256.
	var raw [64]byte
	for len(buf) < length {
		rand.Read(raw[:])
		for _, v := range raw {
			if v < 208 {
				buf = append(buf, letters[int(v)%len(letters)])
				if len(buf) == length {
					break
				}
			}
		}
	}
	return string(buf)
}
func (s *Service) apply(k *Key, in UpdateInput, now time.Time) error {
	if in.Name != nil {
		n := len(utf16.Encode([]rune(*in.Name)))
		if n == 0 && s.opts.RequireName {
			return problem(400, "NAME_REQUIRED", "Name is required")
		}
		if n != 0 && (n < s.opts.MinNameLength || n > s.opts.MaxNameLength) {
			return problem(400, "INVALID_NAME_LENGTH", "Invalid name length")
		}
		k.Name = textPtr(*in.Name)
	}
	if in.ExpiresIn != nil {
		d := *in.ExpiresIn
		if s.opts.DisableCustomExpiration {
			return problem(400, "KEY_DISABLED_EXPIRATION", "Custom key expiration values are disabled")
		}
		if d != 0 && d < s.opts.MinExpiration {
			return problem(400, "EXPIRES_IN_IS_TOO_SMALL", "Expiration is too short")
		}
		if d > s.opts.MaxExpiration {
			return problem(400, "EXPIRES_IN_IS_TOO_LARGE", "Expiration is too long")
		}
		k.ExpiresAt = nil
		if d != 0 {
			k.ExpiresAt = ptr(now.Add(d))
		}
	}
	if in.Metadata != nil {
		if !s.opts.EnableMetadata {
			return problem(400, "METADATA_DISABLED", "Metadata is disabled")
		}
		k.Metadata = in.Metadata
	}
	p := in.Policy
	if p.Enabled != nil {
		k.Enabled = *p.Enabled
	}
	if p.RateLimitEnabled != nil {
		k.RateLimitEnabled = *p.RateLimitEnabled
	}
	if p.Remaining != nil {
		if *p.Remaining < 0 || *p.Remaining > 2147483647 {
			return problem(400, "INVALID_REMAINING", "Invalid remaining count")
		}
		k.Remaining = p.Remaining
	}
	if p.RateLimitMax != nil {
		if *p.RateLimitMax < 1 || *p.RateLimitMax > 2147483647 {
			return problem(400, "VALIDATION_ERROR", "Invalid rate limit")
		}
		k.RateLimitMax = p.RateLimitMax
	}
	if p.RateWindow != nil {
		ms := p.RateWindow.Milliseconds()
		if ms < 1 || ms > 2147483647 {
			return problem(400, "VALIDATION_ERROR", "Invalid rate window")
		}
		k.RateLimitTimeWindow = &ms
	}
	if (p.RefillInterval == nil) != (p.RefillAmount == nil) {
		return problem(400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED", "Provide a refill amount and interval")
	}
	if p.RefillInterval != nil {
		ms := p.RefillInterval.Milliseconds()
		if ms < 1 || ms > 2147483647 || *p.RefillAmount < 1 || *p.RefillAmount > 2147483647 {
			return problem(400, "VALIDATION_ERROR", "Invalid refill policy")
		}
		k.RefillInterval = &ms
		k.RefillAmount = p.RefillAmount
	}
	if p.Permissions != nil {
		k.Permissions = p.Permissions
	}
	return nil
}

// Create issues a key for an authenticated user selected by trusted server code.
func (s *Service) Create(ctx context.Context, userID string, in CreateInput) (*Created, error) {
	return s.create(ctx, Owner{UserID: userID}, in)
}
func (s *Service) create(ctx context.Context, owner Owner, in CreateInput) (*Created, error) {
	if owner.UserID == "" {
		return nil, ErrSession
	}
	prefix := in.Prefix
	if prefix == "" {
		prefix = s.opts.DefaultPrefix
	}
	if prefix != "" && (!safePrefix.MatchString(prefix) || len(prefix) < s.opts.MinPrefixLength || len(prefix) > s.opts.MaxPrefixLength) {
		return nil, problem(400, "INVALID_PREFIX_LENGTH", "Invalid prefix")
	}
	now := current()
	secret := prefix + randomSecret(s.opts.KeyLength)
	k := Key{
		ID: rand.Text(), ConfigID: s.opts.ConfigID, ReferenceID: owner.UserID, Prefix: textPtr(prefix),
		CreatedAt: now, UpdatedAt: now, Enabled: true, RateLimitEnabled: !s.opts.DisableRateLimit,
		RateLimitTimeWindow: ptr(s.opts.RateWindow.Milliseconds()), RateLimitMax: ptr(s.opts.RateMax),
		Permissions: clonePermissions(s.opts.DefaultPermissions),
	}
	if !s.opts.HideStart {
		k.Start = ptr(secret[:s.opts.StartLength])
	}
	if s.opts.DefaultExpiration > 0 {
		k.ExpiresAt = ptr(now.Add(s.opts.DefaultExpiration))
	}
	up := UpdateInput{Name: &in.Name, Metadata: in.Metadata, Policy: in.Policy}
	if in.ExpiresIn != 0 {
		up.ExpiresIn = &in.ExpiresIn
	}
	if err := s.apply(&k, up, now); err != nil {
		return nil, err
	}
	if err := s.opts.Store.CreateAPIKey(ctx, owner, k, Digest(secret)); err != nil {
		return nil, err
	}
	return &Created{Key: k, Secret: secret}, nil
}

func (s *Service) Get(ctx context.Context, userID, id string) (*Key, error) {
	return s.manage(ctx, Owner{UserID: userID}, id, Read, UpdateInput{})
}
func (s *Service) Update(ctx context.Context, userID, id string, in UpdateInput) (*Key, error) {
	return s.manage(ctx, Owner{UserID: userID}, id, Save, in)
}
func (s *Service) Delete(ctx context.Context, userID, id string) error {
	_, err := s.manage(ctx, Owner{UserID: userID}, id, Remove, UpdateInput{})
	return err
}
func (s *Service) manage(ctx context.Context, owner Owner, id string, action Mutation, in UpdateInput) (*Key, error) {
	if owner.UserID == "" {
		return nil, ErrSession
	}
	if id == "" {
		return nil, ErrMissing
	}
	now := current()
	var result *Key
	err := s.opts.Store.WithAPIKey(ctx, owner, Lookup{ConfigID: s.opts.ConfigID, ID: id}, now, func(k *Key) (Mutation, error) {
		if action == Save {
			if in.empty() {
				return Read, problem(400, "NO_VALUES_TO_UPDATE", "No values to update")
			}
			if err := s.apply(k, in, now); err != nil {
				return Read, err
			}
			k.UpdatedAt = now
		}
		result = k
		return action, nil
	})
	return result, err
}
func (s *Service) List(ctx context.Context, userID string, o PageOptions) (Page, error) {
	return s.list(ctx, Owner{UserID: userID}, o)
}
func (s *Service) list(ctx context.Context, owner Owner, o PageOptions) (Page, error) {
	if owner.UserID == "" {
		return Page{}, ErrSession
	}
	if o.Limit != nil && *o.Limit < 0 || o.Offset != nil && *o.Offset < 0 {
		return Page{}, problem(400, "VALIDATION_ERROR", "Invalid pagination")
	}
	return s.opts.Store.ListAPIKeys(ctx, owner, s.opts.ConfigID, current(), o)
}
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	return s.opts.Store.DeleteExpiredAPIKeys(ctx, s.opts.ConfigID, current())
}

type VerifyError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	TryAgainIn *int64 `json:"tryAgainIn,omitempty"`
}
type Verification struct {
	Valid bool         `json:"valid"`
	Key   *Key         `json:"key"`
	Error *VerifyError `json:"error"`
}

// Verify checks the secret and every required resource/action. Successful
// verification consumes one use in the same transaction as the rate check.
func (s *Service) Verify(ctx context.Context, secret string, required Permissions) (Verification, error) {
	now := current()
	result := Verification{}
	invalid := func(code, msg string) { result.Error = &VerifyError{Code: code, Message: msg} }
	if secret == "" || len(secret) > 4096 {
		invalid("INVALID_API_KEY", "Invalid API key")
		return result, nil
	}
	err := s.opts.Store.WithAPIKey(ctx, Owner{}, Lookup{ConfigID: s.opts.ConfigID, Digest: Digest(secret)}, now, func(k *Key) (Mutation, error) {
		// Evaluate time-based policies after obtaining the key lock.
		now = current()
		if !k.Enabled {
			invalid("KEY_DISABLED", "API Key is disabled")
			return Read, nil
		}
		if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
			invalid("KEY_EXPIRED", "API Key has expired")
			return Remove, nil
		}
		for res, actions := range required {
			granted, ok := k.Permissions[res]
			if !ok {
				invalid("KEY_NOT_FOUND", "API Key not found")
				return Read, nil
			}
			for _, action := range actions {
				if !slices.Contains(granted, action) {
					invalid("KEY_NOT_FOUND", "API Key not found")
					return Read, nil
				}
			}
		}
		if k.Remaining != nil {
			remaining := *k.Remaining
			if k.RefillInterval != nil && k.RefillAmount != nil && *k.RefillInterval > 0 {
				since := k.CreatedAt
				if k.LastRefillAt != nil {
					since = *k.LastRefillAt
				}
				if now.Sub(since).Milliseconds() > *k.RefillInterval {
					remaining = *k.RefillAmount
					k.LastRefillAt = &now
				}
			}
			if remaining <= 0 {
				invalid("USAGE_EXCEEDED", "API Key has reached its usage limit")
				if k.RefillAmount == nil {
					return Remove, nil
				}
				return Read, nil
			}
			k.Remaining = ptr(remaining - 1)
		}
		if !s.opts.DisableRateLimit && k.RateLimitEnabled && k.RateLimitMax != nil && k.RateLimitTimeWindow != nil {
			if k.LastRequest == nil || now.Sub(*k.LastRequest).Milliseconds() > *k.RateLimitTimeWindow {
				k.RequestCount = 1
			} else if k.RequestCount >= *k.RateLimitMax {
				invalid("RATE_LIMIT_EXCEEDED", "Rate limit exceeded")
				result.Error.TryAgainIn = ptr(*k.RateLimitTimeWindow - now.Sub(*k.LastRequest).Milliseconds())
				return Read, nil
			} else {
				k.RequestCount++
			}
		}
		k.LastRequest = &now
		k.UpdatedAt = now
		result.Valid = true
		result.Key = k
		return Save, nil
	})
	if errors.Is(err, ErrMissing) {
		invalid("INVALID_API_KEY", "Invalid API key")
		return result, nil
	}
	if errors.Is(err, ErrBanned) {
		invalid("USER_BANNED", "User is banned")
		return result, nil
	}
	if err != nil {
		return Verification{}, fmt.Errorf("verify API key: %w", err)
	}
	return result, nil
}
