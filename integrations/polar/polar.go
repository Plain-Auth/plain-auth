// Package polar integrates personal hosted checkout, verified checkout webhooks and optional customer self-service.
package polar

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/google/uuid"
	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
	"github.com/polarsource/polar-go/retry"
	standard "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

const apiVersion = "2026-10"
const attemptMetadata = "plainauth_checkout_attempt"

type Options struct {
	Client *polargo.Polar
	Ledger *Ledger
	// OrganizationID identifies the merchant organization in Polar.
	OrganizationID        string
	Products              map[string]string // application slug to Polar product UUID
	HostedOrigin          string            // exact HTTPS origin serving this merchant's Polar checkout
	SuccessURL, ReturnURL string
	WebhookSecret         string
	// Portal enables personal portal sessions and customer-state reads when configured.
	Portal *PortalOptions
	// LegacySecret selects the raw UTF-8 signing key used for secrets created before 8 September 2026.
	LegacySecret bool
	// OnCheckout runs in the same SQL transaction as the verified delivery receipt.
	// Use tx for local writes or an outbox. External effects belong outside this callback.
	OnCheckout func(context.Context, *sql.Tx, Event) error
}

// Service handles personal checkouts and signed deliveries for one merchant.
type Service struct {
	opts     Options
	products map[string]bool
	verifier *standard.Webhook
}

var requestKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// New registers checkout, signed deliveries and the configured customer endpoints.
func New(opts Options) (auth.Plugin, error) {
	s, err := NewService(opts)
	if err != nil {
		return auth.Plugin{}, err
	}
	return s.Plugin(), nil
}

// NewService also exposes server-side recovery for a known checkout ID.
func NewService(opts Options) (*Service, error) {
	if opts.Client == nil || opts.Ledger == nil || len(opts.Products) == 0 || opts.SuccessURL == "" || !canonicalID(opts.OrganizationID) {
		return nil, errors.New("polar: configure a client, ledger, merchant UUID, products and success URL")
	}
	origin, err := url.Parse(opts.HostedOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.String() != "https://"+origin.Host {
		return nil, errors.New("polar: hosted origin must be an exact HTTPS origin")
	}
	if opts.WebhookSecret == "" {
		return nil, errors.New("polar: a webhook signing secret is required")
	}
	var verifier *standard.Webhook
	if opts.LegacySecret {
		verifier, err = standard.NewWebhookRaw([]byte(opts.WebhookSecret))
	} else {
		verifier, err = standard.NewWebhook(opts.WebhookSecret)
	}
	if err != nil {
		return nil, errors.New("polar: invalid webhook signing secret")
	}
	if opts.Portal != nil {
		portal := *opts.Portal
		if err := portal.validate(); err != nil {
			return nil, err
		}
		opts.Portal = &portal
	}
	s := &Service{opts: opts, products: map[string]bool{}, verifier: verifier}
	s.opts.Products = make(map[string]string, len(opts.Products))
	for slug, id := range opts.Products {
		if !requestKey.MatchString(slug) || !canonicalID(id) {
			return nil, errors.New("polar: invalid product slug or UUID")
		}
		s.opts.Products[slug] = id
		s.products[id] = true
	}
	return s, nil
}

// Plugin returns the configured billing endpoints.
func (s *Service) Plugin() auth.Plugin {
	endpoints := []auth.Endpoint{
		{Method: "POST", Path: "/checkout", Handler: s.checkout},
		{Method: "POST", Path: "/polar/webhooks", RawBody: true, Handler: s.webhook},
	}
	if s.opts.Portal != nil {
		endpoints = append(endpoints,
			auth.Endpoint{Method: "GET", Path: "/customer/portal", Handler: s.portal},
			auth.Endpoint{Method: "POST", Path: "/customer/portal", Handler: s.portal},
			auth.Endpoint{Method: "GET", Path: "/customer/state", Handler: s.customerState},
		)
	}
	return auth.Plugin{ID: "polar", Endpoints: endpoints}
}

func canonicalID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func failure(status int, code, message string) error {
	return &auth.APIError{Status: status, Code: code, Message: message}
}

func (s *Service) owner(c auth.EndpointContext) (*auth.SessionResult, error) {
	session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if session == nil || session.User.IsAnonymous != nil && *session.User.IsAnonymous {
		return nil, failure(401, "POLAR_OWNER_REQUIRED", "Sign in with your own account")
	}
	if err = session.Session.RequireOwner(); err != nil {
		return nil, err
	}
	if !session.User.EmailVerified {
		return nil, failure(403, "POLAR_EMAIL_UNVERIFIED", "Verify your email before checkout")
	}
	verified, err := s.opts.Ledger.verifiedPersonalOwner(c.Request.Context(), session.User.ID, session.User.Email)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, failure(403, "POLAR_OWNER_REQUIRED", "A verified personal account is required")
	}
	return session, nil
}

func (s *Service) selection(body map[string]any) (id string, redirect bool, err error) {
	bad := failure(400, "POLAR_INVALID_PRODUCT", "Select one configured product by slug or ID")
	redirect = true
	for field, v := range body {
		switch field {
		case "slug":
			slug, _ := v.(string)
			if id != "" || s.opts.Products[slug] == "" {
				return "", false, bad
			}
			id = s.opts.Products[slug]
		case "products":
			var product string
			switch v := v.(type) {
			case string:
				product = v
			case []any:
				if len(v) == 1 {
					product, _ = v[0].(string)
				}
			}
			if id != "" || !s.products[product] {
				return "", false, bad
			}
			id = product
		case "redirect":
			var ok bool
			redirect, ok = v.(bool)
			if !ok {
				return "", false, bad
			}
		default:
			return "", false, failure(400, "POLAR_INVALID_FIELD", "Unsupported checkout field")
		}
	}
	if id == "" {
		return "", false, bad
	}
	return id, redirect, nil
}

func (s *Service) checkout(c auth.EndpointContext) (any, error) {
	ctx := c.Request.Context()
	session, err := s.owner(c)
	if err != nil {
		return nil, err
	}
	product, redirect, err := s.selection(c.Body)
	if err != nil {
		return nil, err
	}
	success, err := c.Auth.CallbackURL(s.opts.SuccessURL)
	if err != nil {
		return nil, err
	}
	back := s.opts.ReturnURL
	if back != "" {
		back, err = c.Auth.CallbackURL(back)
		if err != nil {
			return nil, err
		}
	}
	keys := c.Request.Header.Values("Idempotency-Key")
	if len(keys) > 1 || len(keys) == 1 && !requestKey.MatchString(keys[0]) {
		return nil, failure(400, "POLAR_INVALID_REQUEST_KEY", "Invalid Idempotency-Key")
	}
	key := "default:" + product
	if len(keys) == 1 {
		key = "explicit:" + keys[0]
	}
	keyParts, _ := json.Marshal([]string{s.opts.OrganizationID, session.User.ID, key})
	slot := sha256.Sum256(keyParts)
	contact := sha256.Sum256([]byte(session.User.Email))
	req := reservation{
		Slot: hex.EncodeToString(slot[:]), Attempt: uuid.NewString(),
		Owner: session.User.ID, ContactHash: hex.EncodeToString(contact[:]),
		Product: product, Merchant: s.opts.OrganizationID, Success: success, Return: back,
	}
	row, send, err := s.opts.Ledger.reserve(ctx, req)
	if err != nil {
		return nil, err
	}
	if send {
		if err = s.createRemote(ctx, req, session.User.Email); err != nil {
			return nil, err
		}
		row, err = s.opts.Ledger.read(ctx, req.Slot)
		if err != nil {
			return nil, err
		}
	}
	if row.ID == "" {
		return nil, pending()
	}
	if row.Status != "open" || row.Expires <= time.Now().UnixMilli() {
		return nil, failure(409, "POLAR_CHECKOUT_CLOSED", "Use a new request key for a new checkout")
	}
	// A checkout URL is a secret. Recheck the same direct session after any provider call.
	current, err := s.owner(c)
	if err != nil {
		return nil, err
	}
	if current.Session.ID != session.Session.ID || current.User.ID != row.Owner || current.User.Email != session.User.Email {
		return nil, conflict()
	}
	if !s.hosted(row.URL) {
		return nil, conflict()
	}
	return map[string]any{"url": row.URL, "redirect": redirect}, nil
}

func (s *Service) createRemote(ctx context.Context, req reservation, email string) error {
	payload := components.CheckoutCreate{
		Products: []string{req.Product}, ExternalCustomerID: &req.Owner, CustomerEmail: &email,
		SuccessURL: &req.Success, Metadata: map[string]components.CheckoutCreateMetadata{
			attemptMetadata: components.CreateCheckoutCreateMetadataStr(req.Attempt),
		},
	}
	if req.Return != "" {
		payload.ReturnURL = &req.Return
	}
	reply, err := s.opts.Client.Checkouts.Create(ctx, payload,
		operations.WithRetries(retry.Config{Strategy: "none"}),
		operations.WithSetHeaders(map[string]string{"Polar-Version": apiVersion}),
	)
	if err != nil || reply == nil || reply.Checkout == nil {
		return pending()
	}
	snapshot := fromSDK(reply.Checkout)
	if snapshot.Attempt != req.Attempt {
		return conflict()
	}
	return s.apply(ctx, snapshot, nil)
}

func pending() error {
	return failure(409, "POLAR_CHECKOUT_PENDING", "Checkout is awaiting provider confirmation. Retry with the same request key")
}
func conflict() error {
	return failure(409, "POLAR_CHECKOUT_CONFLICT", "Checkout details did not match the reserved purchase")
}

func (s *Service) hosted(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.User == nil && u.Scheme == "https" && u.Scheme+"://"+u.Host == s.opts.HostedOrigin && u.Path != "" && !strings.ContainsAny(raw, "\\\r\n") && u.Fragment == ""
}

// ReconcileCheckout reads a known Polar checkout after a lost response. It never
// creates a checkout, returns its hosted URL, or synthesizes a signed delivery.
func (s *Service) ReconcileCheckout(ctx context.Context, id string) error {
	if !canonicalID(id) {
		return errors.New("polar: invalid checkout UUID")
	}
	reply, err := s.opts.Client.Checkouts.Get(ctx, id, operations.WithSetHeaders(map[string]string{"Polar-Version": apiVersion}))
	if err != nil {
		return err
	}
	if reply == nil || reply.Checkout == nil || reply.Checkout.ID != id {
		return conflict()
	}
	return s.apply(ctx, fromSDK(reply.Checkout), nil)
}
