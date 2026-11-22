package siwe

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auth "github.com/Plain-Auth/plain-auth"
)

// VerifyMessageArgs contains the original request's signed bytes and the identity
// read from those bytes after the stored challenge and relying party are checked.
type VerifyMessageArgs struct {
	Message, Signature, Address string
	ChainID                     int64
	Cacao                       Cacao
}

type Cacao struct {
	Header struct {
		Type string `json:"t"`
	} `json:"h"`
	Payload struct {
		Domain   string `json:"domain"`
		Audience string `json:"aud"`
		Nonce    string `json:"nonce"`
		Issuer   string `json:"iss"`
		Version  string `json:"version"`
	} `json:"p"`
	Signature struct {
		Type  string `json:"t"`
		Value string `json:"s"`
	} `json:"s"`
}

type ENSLookupArgs struct {
	WalletAddress string
	ChainID       int64
}

type ENSLookupResult struct {
	Name, Avatar string
}

// CustomNonceStore preserves past generator outputs after consuming or expiring
// the separate public challenge record.
type CustomNonceStore interface {
	PrepareWalletNonceHistory(context.Context) error
	SaveCustomWalletNonce(context.Context, string, time.Time, time.Time) error
}

// CallbackStore returns the consumed challenge's deadline so a slow verifier or
// ENS service cannot turn an expired challenge into a successful sign-in.
type CallbackStore interface {
	TakeTimedWalletNonce(context.Context, string, time.Time) (time.Time, error)
}

type ContractStore interface {
	ContractWalletOwner(context.Context, string, int64) (string, error)
}

var errUnavailable = &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Wallet verification failed"}
var errNonceSource = &auth.APIError{Status: 500, Code: "SIWE_INVALID_NONCE", Message: "The challenge generator must supply a new 8–250 character alphanumeric nonce"}
var errBadSignature = &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized: Invalid SIWE signature"}
var errNoNonce = &auth.APIError{Status: 401, Code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE", Message: "Unauthorized: Invalid or expired nonce"}

// Hooks are synchronous and receive the HTTP request's context. Do not expose
// resolver credentials, private RPC errors or panic text in the response.
func callHost[T any](ctx context.Context, public error, fn func() (T, error)) (out T, err error) {
	if err = ctx.Err(); err != nil {
		return out, err
	}
	defer func() {
		if recover() != nil {
			err = public
		}
	}()
	out, err = fn()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, public
	}
	return out, nil
}

func (o Options) checkStore(s auth.Store) error {
	w, ok := s.(Store)
	if !ok {
		return errors.New("siwe: wallet storage is required")
	}
	if err := w.CheckWalletSchema(context.Background()); err != nil {
		return err
	}
	if o.RequireEmail {
		if _, ok := s.(ContactStore); !ok {
			return errors.New("siwe: required contact email needs a ContactStore")
		}
	}
	if o.VerifyMessage != nil || o.ENSLookup != nil {
		if _, ok := s.(CallbackStore); !ok {
			return errors.New("siwe: wallet callbacks require consumption with a stored deadline")
		}
	}
	if o.VerifyMessage != nil {
		if _, ok := s.(ContractStore); !ok {
			return errors.New("siwe: custom verification requires chain-bound contract wallet storage")
		}
	}
	if o.GetNonce != nil {
		h, ok := s.(CustomNonceStore)
		if !ok {
			return errors.New("siwe: custom nonces require durable nonce history")
		}
		return h.PrepareWalletNonceHistory(context.Background())
	}
	return nil
}

func (o Options) verifySignature(ctx context.Context, text, signature string, m message) (contract bool, err error) {
	eoa := validSignature(text, signature, m.address)
	if o.VerifyMessage == nil {
		if !eoa {
			return false, errBadSignature
		}
		return false, nil
	}
	args := VerifyMessageArgs{Message: text, Signature: signature, Address: m.address, ChainID: m.chain}
	args.Cacao.Header.Type = "caip122"
	args.Cacao.Payload.Domain = o.Domain
	args.Cacao.Payload.Audience = o.Domain
	args.Cacao.Payload.Issuer = o.Domain
	args.Cacao.Payload.Version = "1"
	args.Cacao.Payload.Nonce = m.nonce
	args.Cacao.Signature.Type = "eip191"
	args.Cacao.Signature.Value = signature
	ok, err := callHost(ctx, errUnavailable, func() (bool, error) { return o.VerifyMessage(ctx, args) })
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errBadSignature
	}
	return !eoa, nil
}

func (o Options) profile(ctx context.Context, m message) (ENSLookupResult, error) {
	fallback := ENSLookupResult{Name: m.address}
	if o.ENSLookup == nil {
		return fallback, nil
	}
	out, err := callHost(ctx, errUnavailable, func() (ENSLookupResult, error) {
		return o.ENSLookup(ctx, ENSLookupArgs{WalletAddress: m.address, ChainID: m.chain})
	})
	if err != nil {
		return out, err
	}
	if !utf8.ValidString(out.Name) || len(out.Name) > 255 || strings.IndexFunc(out.Name, unicode.IsControl) >= 0 {
		return fallback, errUnavailable
	}
	if out.Name == "" {
		out.Name = m.address
	}
	if out.Avatar != "" {
		u, err := url.ParseRequestURI(out.Avatar)
		if len(out.Avatar) > 2048 || err != nil || u.User != nil || (u.Scheme != "https" && u.Scheme != "ipfs") || u.Host == "" {
			return fallback, errUnavailable
		}
	}
	return out, nil
}

// SignedBy reports whether this EIP-191 signature recovers the supplied EOA.
// A contract verifier must establish its own policy for this address and chain.
func (v VerifyMessageArgs) SignedBy(address string) bool {
	return validSignature(v.Message, v.Signature, address)
}
