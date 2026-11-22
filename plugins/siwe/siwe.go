package siwe

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

type Options struct {
	// Domain is the authority (including its port), optionally with an HTTP(S) scheme.
	Domain string
	// Chains restricts accepted chain IDs. An empty list permits any positive ID supported by the shared SQL schema.
	Chains []int64
	// EmailDomainName sets the domain used for a new wallet account's placeholder email.
	EmailDomainName string
}

type Login struct {
	Address, CandidateID, Email string
	ChainID                     int64
	AllowSignUp                 bool
	Existing                    bool
}

type Store interface {
	CheckWalletSchema(context.Context) error
	SaveWalletNonce(context.Context, string, time.Time, time.Time) error
	TakeWalletNonce(context.Context, string, time.Time) (bool, error)
	WalletOwner(context.Context, string) (string, error)
	FinishWalletLogin(context.Context, Login, auth.StoredSession) (auth.User, error)
}

// ErrOwnerChanged asks the caller to read the wallet again after concurrent registration.
var ErrOwnerChanged = errors.New("siwe: wallet ownership changed")
var (
	errMismatch = &auth.APIError{Status: 401, Code: "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH", Message: "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID"}
	errExpired  = &auth.APIError{Status: 401, Code: "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED", Message: "Unauthorized: SIWE message has expired"}
	errEarly    = &auth.APIError{Status: 401, Code: "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID", Message: "Unauthorized: SIWE message is not yet valid"}
)

type Identity struct {
	ID            string `json:"id"`
	WalletAddress string `json:"walletAddress"`
	ChainID       int64  `json:"chainId"`
}
type Result struct {
	Token   string   `json:"token"`
	Success bool     `json:"success"`
	User    Identity `json:"user"`
}

func New(o Options) (auth.Plugin, error) {
	scheme, domain, ok := canonicalOrigin(o.Domain)
	if !ok {
		return auth.Plugin{}, errors.New("siwe: invalid relying-party domain")
	}
	emailDomain := strings.ToLower(o.EmailDomainName)
	if emailDomain == "" {
		emailDomain = "siwe.placeholder.invalid"
	}
	if a, err := mail.ParseAddress("wallet@" + emailDomain); len(emailDomain) > 210 || err != nil || a.Address != "wallet@"+emailDomain || strings.ContainsAny(emailDomain, "@[]") {
		return auth.Plugin{}, errors.New("siwe: invalid placeholder email domain")
	}
	chains := slices.Clone(o.Chains)
	for _, id := range chains {
		if id <= 0 || id > 1<<31-1 {
			return auth.Plugin{}, errors.New("siwe: unsupported chain ID")
		}
	}
	bad := &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Invalid wallet request"}
	nonce := func(c auth.EndpointContext) (any, error) {
		if len(c.Body) != 0 {
			return nil, bad
		}
		now := time.Now().UTC()
		n := rand.Text()
		if err := c.Store().(Store).SaveWalletNonce(c.Request.Context(), n, now, now.Add(15*time.Minute)); err != nil {
			return nil, err
		}
		c.ResponseHeader.Set("Cache-Control", "no-store")
		return map[string]string{"nonce": n}, nil
	}
	verify := func(c auth.EndpointContext) (any, error) {
		for key := range c.Body {
			if key != "message" && key != "signature" && key != "email" {
				return nil, bad
			}
		}
		text, _ := c.Body["message"].(string)
		signature, _ := c.Body["signature"].(string)
		if len(text) == 0 || len(text) > 16384 || signature == "" || strings.ContainsRune(text, 0) {
			return nil, bad
		}
		if v, ok := c.Body["email"]; ok {
			email, _ := v.(string)
			a, err := mail.ParseAddress(email)
			if err != nil || a.Address != email {
				return nil, bad
			}
		}
		lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		n := nonceFrom(lines)
		if n == "" {
			return nil, errMismatch
		}
		now := time.Now().UTC()
		ctx := c.Request.Context()
		store := c.Store().(Store)
		taken, err := store.TakeWalletNonce(ctx, n, now)
		if err != nil {
			return nil, err
		}
		if !taken {
			return nil, &auth.APIError{Status: 401, Code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE", Message: "Unauthorized: Invalid or expired nonce"}
		}
		m, err := parseMessage(lines, scheme, domain, now)
		if err != nil {
			return nil, err
		}
		if len(chains) > 0 && !slices.Contains(chains, m.chain) {
			return nil, errMismatch
		}
		if !validSignature(text, signature, m.address) {
			return nil, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized: Invalid SIWE signature"}
		}
		for range 2 {
			id, err := store.WalletOwner(ctx, m.address)
			if err != nil {
				return nil, err
			}
			existing := id != ""
			if !existing {
				id = rand.Text()
			}
			input := Login{Address: m.address, ChainID: m.chain, CandidateID: id, Existing: existing, Email: strings.ToLower(m.address) + "@" + emailDomain, AllowSignUp: c.SignUpAllowed()}
			result, err := c.IssueSession(id, func(ctx context.Context, s auth.StoredSession) (auth.User, error) {
				return store.FinishWalletLogin(ctx, input, s)
			})
			if errors.Is(err, ErrOwnerChanged) {
				continue
			}
			if err != nil {
				return nil, err
			}
			return Result{Token: result.Session.Token, Success: true, User: Identity{ID: id, WalletAddress: m.address, ChainID: m.chain}}, nil
		}
		return nil, errMismatch
	}
	return auth.Plugin{ID: "siwe", ValidateStore: func(s auth.Store) error {
		w, ok := s.(Store)
		if !ok {
			return errors.New("siwe: wallet storage is required")
		}
		return w.CheckWalletSchema(context.Background())
	}, Endpoints: []auth.Endpoint{
		{Method: http.MethodPost, Path: "/siwe/nonce", Handler: nonce},
		{Method: http.MethodPost, Path: "/siwe/get-nonce", Handler: nonce},
		{Method: http.MethodPost, Path: "/siwe/verify", Handler: verify},
	}}, nil
}
