package oauthprovider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	jose "github.com/go-jose/go-jose/v4"
)

// ClientAssertionType is the RFC 7523 form parameter for JWT client authentication.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// AssertionOptions configures signed assertions from registered OAuth clients.
type AssertionOptions struct {
	// AllowKeyRotation lets an inline-key registration replace its keys using a
	// single-use assertion addressed to the rotation endpoint.
	AllowKeyRotation bool
	// KeyRotationRateLimit defaults to five requests per minute. An empty rule uses the global limit.
	KeyRotationRateLimit *auth.RateLimitRule
	// MaxLifetime limits remaining validity and the age of iat. Defaults to five minutes.
	MaxLifetime time.Duration
	// ClockTolerance permits clock differences of up to one minute.
	ClockTolerance time.Duration
	// JWKSTransport optionally supplies the HTTP transport for trusted HTTPS key endpoints.
	// A custom transport is responsible for enforcing public destination addresses.
	JWKSTransport http.RoundTripper
}

func (o *AssertionOptions) defaults() error {
	if o.MaxLifetime == 0 {
		o.MaxLifetime = 5 * time.Minute
	}
	if o.MaxLifetime < time.Second || o.MaxLifetime%time.Second != 0 {
		return errors.New("oauthprovider: assertion maximum lifetime must be a positive whole number of seconds")
	}
	o.ClockTolerance = min(time.Minute, max(0, o.ClockTolerance.Truncate(time.Second)))
	return nil
}

// ErrAssertionReplay means the client has already used this assertion identifier.
var ErrAssertionReplay = errors.New("oauthprovider: client assertion already used")

// ClientAssertionStore reserves an assertion identifier once across all endpoints and
// processes. The registration must pass check in the same transaction as the reservation.
type ClientAssertionStore interface {
	ConsumeOAuthClientAssertion(ctx context.Context, clientID, digest string, expires time.Time, check func(MachineClient) error) error
}

var assertionAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

type clientAssertion struct {
	clientID string
	token    *jose.JSONWebSignature
}

func parseClientAssertion(kind, compact, hint string) (*clientAssertion, error) {
	if kind != ClientAssertionType {
		return nil, invalidClient("unsupported client_assertion_type")
	}
	token, err := jose.ParseSignedCompact(compact, assertionAlgorithms)
	if err != nil || len(token.Signatures) != 1 {
		return nil, invalidClient("malformed client assertion or unsupported signing algorithm")
	}
	var identity map[string]json.RawMessage
	// Only use the unverified subject or issuer to locate a registered key.
	if json.Unmarshal(token.UnsafePayloadWithoutVerification(), &identity) != nil {
		return nil, invalidClient("malformed client assertion: invalid JWT payload")
	}
	candidate := identity["sub"]
	if candidate == nil || string(candidate) == "null" {
		candidate = identity["iss"]
	}
	var name string
	if json.Unmarshal(candidate, &name) != nil || name == "" {
		return nil, invalidClient("client assertion must contain sub or iss claim identifying the client")
	}
	if hint != "" && name != hint {
		return nil, invalidClient("client_id in body does not match assertion sub/iss")
	}
	return &clientAssertion{name, token}, nil
}

func failedAssertion() error {
	return registrationProblem(401, "invalid_client", "client assertion signature verification failed")
}

func (opts Options) verifyClientAssertion(c auth.EndpointContext, reader MachineClientReader, in tokenRequest, first MachineClient, endpoint string) error {
	store, ok := reader.(ClientAssertionStore)
	if !ok {
		return &auth.APIError{Status: 501, Code: "OAUTH_ASSERTION_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth client assertions"}
	}
	digest, expires, err := opts.signedAssertion(c, in.assertion, first, c.Auth.PublicURL()+endpoint, c.Auth.OAuthIssuer())
	if err != nil {
		return err
	}
	err = store.ConsumeOAuthClientAssertion(c.Request.Context(), first.ClientID, digest, expires, func(current MachineClient) error {
		if !time.Now().Before(expires) {
			return failedAssertion()
		}
		return in.recheckClient(first, current)
	})
	return assertionStoreError(err)
}

func assertionStoreError(err error) error {
	if errors.Is(err, ErrAssertionReplay) {
		return invalidClient("client assertion jti has already been used")
	}
	return err
}

// signedAssertion verifies the JWT before any replay or credential state is written.
func (opts Options) signedAssertion(c auth.EndpointContext, assertion *clientAssertion, first MachineClient, audiences ...string) (string, time.Time, error) {
	token := assertion.token
	key, err := opts.assertionKeys.verificationKey(c, first, token.Signatures[0].Protected)
	if err != nil {
		return "", time.Time{}, err
	}
	data, err := token.Verify(key.Key)
	if err != nil {
		return "", time.Time{}, failedAssertion()
	}
	jti, expires, err := opts.Assertions.checkClaims(data, first.ClientID, time.Now(), audiences...)
	if err != nil {
		return "", time.Time{}, err
	}
	sum := sha256.Sum256([]byte("private_key_jwt:" + first.ClientID + ":" + jti))
	digest := base64.RawURLEncoding.EncodeToString(sum[:24])
	return digest, expires, nil
}

func (opts AssertionOptions) checkClaims(data []byte, id string, now time.Time, accepted ...string) (string, time.Time, error) {
	var claims map[string]json.RawMessage
	var iss, sub string
	if json.Unmarshal(data, &claims) != nil || json.Unmarshal(claims["iss"], &iss) != nil ||
		json.Unmarshal(claims["sub"], &sub) != nil || iss != id || sub != id {
		return "", time.Time{}, failedAssertion()
	}
	var audience string
	var audiences []string
	if json.Unmarshal(claims["aud"], &audience) == nil {
		audiences = []string{audience}
	} else if json.Unmarshal(claims["aud"], &audiences) != nil {
		return "", time.Time{}, failedAssertion()
	}
	if !slices.ContainsFunc(accepted, func(v string) bool { return slices.Contains(audiences, v) }) {
		return "", time.Time{}, failedAssertion()
	}
	if claims["exp"] == nil {
		return "", time.Time{}, invalidClient("client assertion must include exp claim")
	}
	seconds, skew := float64(now.Unix()), opts.ClockTolerance.Seconds()
	limit := opts.MaxLifetime.Seconds()
	number := func(raw json.RawMessage) (float64, bool) {
		var value float64
		ok := len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &value) == nil
		return value, ok
	}
	exp, ok := number(claims["exp"])
	if !ok || exp <= seconds-skew {
		return "", time.Time{}, failedAssertion()
	}
	if claims["nbf"] != nil {
		if nbf, ok := number(claims["nbf"]); !ok || nbf > seconds+skew {
			return "", time.Time{}, failedAssertion()
		}
	}
	if exp-seconds > limit+skew {
		return "", time.Time{}, invalidClient(fmt.Sprintf("client assertion exp is too far in the future (max %.0fs)", limit))
	}
	if claims["iat"] != nil {
		iat, ok := number(claims["iat"])
		if !ok {
			return "", time.Time{}, failedAssertion()
		}
		if seconds-iat > limit+skew {
			return "", time.Time{}, invalidClient(fmt.Sprintf("client assertion iat is too far in the past (max %.0fs)", limit))
		}
	}
	var jti string
	if json.Unmarshal(claims["jti"], &jti) != nil || jti == "" {
		return "", time.Time{}, invalidClient("client assertion must include jti claim")
	}
	sec, fraction := math.Modf(exp + skew)
	return jti, time.Unix(int64(sec), int64(fraction*1e9)).UTC(), nil
}
