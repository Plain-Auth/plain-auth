package siwe

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/emailaddress"
)

type Options struct {
	// Domain is the authority (including its port), optionally with an HTTP(S) scheme.
	Domain string
	// Chains restricts accepted chain IDs. An empty list permits any positive ID supported by the shared SQL schema.
	Chains []int64
	// RequireEmail requires a contact address on each verification. Only new owners can claim one.
	RequireEmail bool
	// EmailDomainName sets the domain used for a new wallet account's placeholder email.
	EmailDomainName string
	// GetNonce supplies a cryptographically random, globally unique challenge.
	GetNonce func(context.Context) (string, error)
	// VerifyMessage is the host's final signature decision for the exact address and chain.
	VerifyMessage func(context.Context, VerifyMessageArgs) (bool, error)
	// ENSLookup supplies display-only metadata when registering a new owner.
	ENSLookup func(context.Context, ENSLookupArgs) (ENSLookupResult, error)
}

type Login struct {
	Address, CandidateID, Email string
	ChainID                     int64
	AllowSignUp                 bool
	Existing                    bool
	Contract                    bool
	Profile                     ENSLookupResult
	ValidUntil                  time.Time
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
	maxDomain := 210
	if o.VerifyMessage != nil {
		maxDomain = 200
	} // Contract placeholders include a decimal chain ID.
	if a, err := mail.ParseAddress("wallet@" + emailDomain); len(emailDomain) > maxDomain || err != nil || a.Address != "wallet@"+emailDomain || strings.ContainsAny(emailDomain, "@[]") {
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
		ctx := c.Request.Context()
		n := rand.Text()
		save := c.Store().(Store).SaveWalletNonce
		if o.GetNonce != nil {
			var err error
			n, err = callHost(ctx, errNonceSource, func() (string, error) { return o.GetNonce(ctx) })
			if err != nil {
				return nil, err
			}
			if !validNonce(n) {
				return nil, errNonceSource
			}
			save = c.Store().(CustomNonceStore).SaveCustomWalletNonce
		}
		now := time.Now().UTC()
		if err := save(ctx, n, now, now.Add(15*time.Minute)); err != nil {
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
		var contact string
		if v, present := c.Body["email"]; present {
			email, ok := v.(string)
			if !ok || !emailaddress.ValidWalletContact(email) {
				return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body.email] Invalid email address"}
			}
			if o.RequireEmail {
				contact = strings.ToLower(email)
			}
		} else if o.RequireEmail {
			return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body.email] Email is required when the anonymous plugin option is disabled."}
		}
		lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		n := nonceFrom(lines)
		if n == "" {
			return nil, errMismatch
		}
		now := time.Now().UTC()
		ctx := c.Request.Context()
		store := c.Store().(Store)
		var deadline time.Time
		if o.VerifyMessage != nil || o.ENSLookup != nil {
			var err error
			deadline, err = store.(CallbackStore).TakeTimedWalletNonce(ctx, n, now)
			if err != nil {
				return nil, err
			}
			if deadline.IsZero() {
				return nil, errNoNonce
			}
		} else {
			taken, err := store.TakeWalletNonce(ctx, n, now)
			if err != nil {
				return nil, err
			}
			if !taken {
				return nil, errNoNonce
			}
		}
		m, err := parseMessage(lines, scheme, domain, now)
		if err != nil {
			return nil, err
		}
		if len(chains) > 0 && !slices.Contains(chains, m.chain) {
			return nil, errMismatch
		}
		contract, err := o.verifySignature(ctx, text, signature, m)
		if err != nil {
			return nil, err
		}
		emailLocal := strings.ToLower(m.address)
		if contract {
			emailLocal += "+" + strconv.FormatInt(m.chain, 10)
		}
		var profile ENSLookupResult
		var claim *ContactClaim
		triedContact := false
		for range 2 {
			var id string
			if contract {
				id, err = store.(ContractStore).ContractWalletOwner(ctx, m.address, m.chain)
			} else {
				id, err = store.WalletOwner(ctx, m.address)
			}
			if err != nil {
				return nil, err
			}
			existing := id != ""
			if !existing {
				if !c.SignUpAllowed() {
					return nil, &auth.APIError{Status: 403, Code: "SIGN_UP_DISABLED", Message: "Sign up is disabled"}
				}
				id = rand.Text()
				if contact != "" && !triedContact && !walletPlaceholder(contact, emailDomain) {
					triedContact = true
					claim, err = store.(ContactStore).ReserveWalletContact(ctx, contact, m.address)
					if err != nil {
						claim = nil
					}
					if claim != nil {
						defer releaseContact(ctx, store.(ContactStore), *claim)
					}
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
				}
				if profile.Name == "" {
					profile, err = o.profile(ctx, m)
					if err != nil {
						return nil, err
					}
				}
			}
			input := Login{Address: m.address, ChainID: m.chain, CandidateID: id, Existing: existing, Email: emailLocal + "@" + emailDomain, AllowSignUp: c.SignUpAllowed(), Contract: contract, Profile: profile}
			input.ValidUntil = deadline
			if !m.expiration.IsZero() && (input.ValidUntil.IsZero() || m.expiration.Before(input.ValidUntil)) {
				input.ValidUntil = m.expiration
			}
			result, err := c.IssueSession(id, func(ctx context.Context, s auth.StoredSession) (auth.User, error) {
				if err := ctx.Err(); err != nil {
					return auth.User{}, err
				}
				now := time.Now()
				if !deadline.IsZero() && !now.Before(deadline) {
					return auth.User{}, errNoNonce
				}
				if !m.expiration.IsZero() && !now.Before(m.expiration) {
					return auth.User{}, errExpired
				}
				if claim != nil && !input.Existing {
					return store.(ContactStore).FinishWalletContactLogin(ctx, input, s, *claim)
				}
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
	return auth.Plugin{ID: "siwe", ValidateStore: o.checkStore, Endpoints: []auth.Endpoint{
		{Method: http.MethodPost, Path: "/siwe/nonce", Handler: nonce},
		{Method: http.MethodPost, Path: "/siwe/get-nonce", Handler: nonce},
		{Method: http.MethodPost, Path: "/siwe/verify", Handler: verify},
	}}, nil
}
