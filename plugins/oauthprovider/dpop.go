package oauthprovider

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	auth "github.com/Plain-Auth/plain-auth"
	jose "github.com/go-jose/go-jose/v4"
)

// DPoPReplayStore atomically reserves a proof digest through expiresAt.
// Return false when an unexpired reservation already exists.
type DPoPReplayStore interface {
	ReserveDPoPProof(ctx context.Context, key string, now, expiresAt time.Time) (bool, error)
}

// DPoPOptions controls proof verification and the lifetime of replay records.
type DPoPOptions struct {
	// ProofMaxAge defaults to five minutes. Up to five seconds of future clock skew is accepted.
	ProofMaxAge       time.Duration
	SigningAlgorithms []string
	// ReplayStore defaults to memory shared by calls on this verifier. Set a SQL
	// or Redis store to share reservations across server instances.
	ReplayStore DPoPReplayStore
}

// DPoPVerifier verifies proofs and is safe to share across concurrent requests.
type DPoPVerifier struct {
	algorithms []jose.SignatureAlgorithm
	maxAge     time.Duration
	store      DPoPReplayStore
	now        func() time.Time
}

// NewDPoPVerifier constructs a verifier. Reuse it for the lifetime of the service.
func NewDPoPVerifier(opts DPoPOptions) (*DPoPVerifier, error) {
	if opts.ProofMaxAge == 0 {
		opts.ProofMaxAge = 5 * time.Minute
	}
	if opts.ProofMaxAge < 0 {
		return nil, errors.New("oauthprovider: a DPoP proof maximum age must be positive")
	}
	if opts.SigningAlgorithms == nil {
		opts.SigningAlgorithms = resourceSigningAlgorithms()
	}
	var algorithms []jose.SignatureAlgorithm
	for _, name := range opts.SigningAlgorithms {
		alg := jose.SignatureAlgorithm(name)
		if !slices.Contains(assertionAlgorithms, alg) {
			return nil, errors.New("oauthprovider: unsupported DPoP signing algorithm")
		}
		algorithms = append(algorithms, alg)
	}
	if opts.ReplayStore == nil {
		opts.ReplayStore = &memoryDPoPReplay{entries: make(map[string]time.Time)}
	}
	return &DPoPVerifier{algorithms: algorithms, maxAge: opts.ProofMaxAge, store: opts.ReplayStore, now: time.Now}, nil
}

// DPoPProofRequest describes the actual request and the binding expected by the
// host. URL is the public absolute target of the request, including its path.
type DPoPProofRequest struct {
	Method                 string
	URL                    string
	AccessToken            string
	ExpectedThumbprint     string
	RequireAccessTokenHash bool
}

// DPoPProof contains authenticated claims, the normalized target and the
// single-use reservation derived from the key, method, target and proof ID.
type DPoPProof struct {
	PublicKey       json.RawMessage
	Thumbprint      string
	ID              string
	Method          string
	URL             string
	AccessTokenHash string
	ReplayKey       string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

func proofError(message string) error {
	return &auth.OAuthError{Status: 400, Code: "invalid_dpop_proof", Description: message}
}

// Verify verifies a JWS proof and consumes its replay reservation exactly once.
// AccessToken and ExpectedThumbprint can be omitted when verifying a token
// endpoint request before a sender-bound access token has been issued.
func (v *DPoPVerifier) Verify(ctx context.Context, compact string, request DPoPProofRequest) (*DPoPProof, error) {
	signed, err := jose.ParseSignedCompact(compact, v.algorithms)
	if err != nil {
		return nil, proofError("invalid compact DPoP proof or unsupported signing algorithm")
	}
	header := signed.Signatures[0].Protected
	if header.ExtraHeaders[jose.HeaderType] != "dpop+jwt" || header.ExtraHeaders["b64"] == false {
		return nil, proofError("DPoP proof requires an encoded dpop+jwt")
	}
	first, _, _ := strings.Cut(compact, ".")
	data, err := base64.RawURLEncoding.DecodeString(first)
	var protected map[string]json.RawMessage
	if err != nil || json.Unmarshal(data, &protected) != nil || validatePublicClientKey(protected["jwk"]) != nil {
		return nil, proofError("DPoP proof requires a public asymmetric JWK")
	}
	rawKey := protected["jwk"]
	key := header.JSONWebKey
	var usage struct {
		Ops []string `json:"key_ops"`
	}
	if json.Unmarshal(rawKey, &usage) != nil || key == nil || !key.IsPublic() || !key.Valid() ||
		!allowsVerificationKey(key, header.Algorithm, usage.Ops) {
		return nil, proofError("DPoP verification key is incompatible with the signing algorithm")
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return nil, proofError("invalid DPoP signature")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || fields == nil {
		return nil, proofError("invalid DPoP claims")
	}
	// JWT claim names are case-sensitive; Go struct field matching is not.
	stringClaim := func(name string) string {
		var value string
		_ = json.Unmarshal(fields[name], &value)
		return value
	}
	method, proofURL, id := stringClaim("htm"), stringClaim("htu"), stringClaim("jti")
	hash := stringClaim("ath")
	var issuedAt *float64
	if json.Unmarshal(fields["iat"], &issuedAt) != nil || issuedAt == nil || method == "" || proofURL == "" || id == "" {
		return nil, proofError("DPoP proof requires htm, htu, jti and iat")
	}
	length := 0
	for _, r := range id {
		length += utf16.RuneLen(r)
		if length > 512 {
			return nil, proofError("DPoP proof jti is too large")
		}
	}
	if strings.ToUpper(method) != strings.ToUpper(request.Method) {
		return nil, proofError("DPoP proof htm does not match the request method")
	}
	target, err := dpopTarget(request.URL)
	actual, urlErr := dpopTarget(proofURL)
	if err != nil || urlErr != nil || actual != target {
		return nil, proofError("DPoP proof htu does not match the request URL")
	}
	now := v.now().UTC().Truncate(time.Second)
	second := float64(now.Unix())
	iat := *issuedAt
	if iat > second+5 || second-iat > v.maxAge.Seconds() {
		return nil, proofError("DPoP proof iat is outside the accepted window")
	}
	for _, name := range []string{"nbf", "exp"} {
		if rawValue, present := fields[name]; present {
			var value *float64
			if json.Unmarshal(rawValue, &value) != nil || value == nil || (name == "nbf" && *value > second) || (name == "exp" && *value <= second) {
				return nil, proofError("DPoP proof is outside its validity period")
			}
		}
	}
	if request.RequireAccessTokenHash && hash == "" {
		return nil, proofError("DPoP proof requires an ath claim")
	}
	if request.AccessToken != "" && !sameProofValue(hash, tokenDigest(request.AccessToken)) {
		return nil, proofError("DPoP proof ath does not match the access token")
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, proofError("invalid DPoP public key")
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	if request.ExpectedThumbprint != "" && !sameProofValue(jkt, request.ExpectedThumbprint) {
		return nil, proofError("DPoP proof key does not match the bound token")
	}
	replayKey := tokenDigest(strings.Join([]string{jkt, strings.ToUpper(method), target, id}, "\n"))
	whole, fraction := math.Modf(iat)
	issued := time.Unix(int64(whole), int64(math.Round(fraction*1e9))).UTC()
	expires := issued.Add(v.maxAge).Add(time.Second)
	reserved, err := v.store.ReserveDPoPProof(ctx, replayKey, now, expires)
	if err != nil {
		return nil, err
	}
	if !reserved {
		return nil, proofError("DPoP proof has already been used")
	}
	return &DPoPProof{PublicKey: rawKey, Thumbprint: jkt, ID: id, Method: method, URL: target, AccessTokenHash: hash, ReplayKey: replayKey, IssuedAt: issued, ExpiresAt: expires}, nil
}

func sameProofValue(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// CheckBinding verifies the proof accompanying a previously validated access
// token. Set ExpectedThumbprint from the token's cnf.jkt. Supply the literal
// access token to bind the proof to this credential.
func (v *DPoPVerifier) CheckBinding(ctx context.Context, scheme, proof string, request DPoPProofRequest) error {
	if request.AccessToken == "" {
		return &auth.OAuthError{Status: 401, Code: "invalid_token", Description: "access token is required"}
	}
	dpop := strings.EqualFold(scheme, "DPoP")
	if request.ExpectedThumbprint == "" {
		if !dpop && !strings.EqualFold(scheme, "Bearer") {
			return &auth.OAuthError{Status: 401, Code: "invalid_token", Description: "unsupported access token authorization scheme"}
		}
		if dpop {
			return &auth.OAuthError{Status: 401, Code: "invalid_token", Description: "DPoP authorization requires a DPoP-bound access token"}
		}
		return nil
	}
	if !dpop {
		return &auth.OAuthError{Status: 401, Code: "invalid_token", Description: "DPoP-bound access token requires the DPoP authorization scheme"}
	}
	if proof == "" {
		return &auth.OAuthError{Status: 401, Code: "invalid_dpop_proof", Description: "DPoP proof header is required"}
	}
	request.RequireAccessTokenHash = true
	_, err := v.Verify(ctx, proof, request)
	var invalid *auth.OAuthError
	if errors.As(err, &invalid) && invalid.Code == "invalid_dpop_proof" {
		return &auth.OAuthError{Status: 401, Code: invalid.Code, Description: invalid.Description}
	}
	return err
}

func dpopTarget(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "\\") {
		return "", errors.New("invalid DPoP target URL")
	}
	host, err := pairwiseSector(u.Hostname(), u.Port(), u.Scheme)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	path := make([]string, 0, len(parts))
	for i, part := range parts {
		switch strings.ReplaceAll(strings.ToLower(part), "%2e", ".") {
		case "..":
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
			fallthrough
		case ".":
			if i == len(parts)-1 {
				path = append(path, "")
			}
		default:
			path = append(path, part)
		}
	}
	return u.Scheme + "://" + host + "/" + strings.Join(path, "/"), nil
}

type memoryDPoPReplay struct {
	mu        sync.Mutex
	entries   map[string]time.Time
	nextSweep time.Time
}

func (m *memoryDPoPReplay) ReserveDPoPProof(ctx context.Context, key string, now, expires time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !now.Before(m.nextSweep) {
		for k, end := range m.entries {
			if !end.After(now) {
				delete(m.entries, k)
			}
		}
		m.nextSweep = now.Add(time.Minute)
	}
	if m.entries[key].After(now) {
		return false, nil
	}
	m.entries[key] = expires
	return true, nil
}
