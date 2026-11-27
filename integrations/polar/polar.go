// Package polar integrates personal hosted checkout, verified checkout webhooks and optional customer self-service.
package polar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/google/uuid"
	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
	"github.com/polarsource/polar-go/retry"
	standard "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

const apiVersion = "2026-10"
const attemptMetadata = "plainauth_checkout_attempt"

// Options configures the Polar integration, as another runtime composes
// checkout, portal and webhook parts around one client. Client and
// OrganizationID are always required; each non-nil section enables one part
// and mounts only its routes.
type Options struct {
	// Client is the configured SDK client. Select the sandbox with
	// polargo.WithServer(polargo.ServerSandbox).
	Client *polargo.Polar
	// OrganizationID identifies the merchant organization in Polar.
	OrganizationID string
	// Ledger is required when Checkout, Portal or Webhooks is set.
	Ledger *Ledger
	// SignUpCustomer creates a Polar customer, identified by the account ID,
	// for each new account that is not a guest and whose email is verified
	// when it is created.
	SignUpCustomer *SignUpCustomerOptions
	// Checkout enables POST /checkout.
	Checkout *CheckoutOptions
	// Portal enables personal portal sessions and customer-state reads.
	Portal *PortalOptions
	// Webhooks enables POST /polar/webhooks.
	Webhooks *WebhookOptions
	// Usage enables GET /usage/meters/list, the signed-in customer's meters.
	Usage *UsageOptions
}

// CheckoutOptions enables personal hosted checkout.
type CheckoutOptions struct {
	Products              map[string]string // application slug to Polar product UUID
	HostedOrigin          string            // exact HTTPS origin serving this merchant's Polar checkout
	SuccessURL, ReturnURL string
}

// WebhookOptions enables verified checkout deliveries. A node with
// webhooks and no checkout still completes the checkouts other nodes
// reserved on the same ledger.
type WebhookOptions struct {
	Secret string
	// LegacySecret selects the raw UTF-8 signing key used for secrets created before 8 September 2026.
	LegacySecret bool
	// OnEvent receives every verified delivery once the integration has
	// recorded its own checkout state. It never runs inside a store
	// transaction or while a ledger lock is held. Polar retries a failed
	// delivery for a limited time, and a retry, a concurrent copy or a replay
	// inside the five-minute signature window runs OnEvent again with the
	// same DeliveryID, so make its effects idempotent. Deliveries for one
	// checkout can run concurrently and finish out of order (see
	// Purchase.Changed). An error or panic is logged without its text and
	// answered with 400 so Polar retries; it never undoes the recorded
	// checkout state.
	OnEvent func(context.Context, Event) error
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
	if opts.Client == nil || !canonicalID(opts.OrganizationID) {
		return nil, errors.New("polar: configure a client and the merchant organization UUID")
	}
	if (opts.Checkout != nil || opts.Portal != nil || opts.Webhooks != nil || opts.Usage != nil) && opts.Ledger == nil {
		return nil, errors.New("polar: checkout, portal, webhooks and usage need a ledger")
	}
	s := &Service{opts: opts, products: map[string]bool{}}
	if opts.Checkout != nil {
		checkout := *opts.Checkout
		if len(checkout.Products) == 0 || checkout.SuccessURL == "" {
			return nil, errors.New("polar: checkout needs products and a success URL")
		}
		origin, err := url.Parse(checkout.HostedOrigin)
		if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.String() != "https://"+origin.Host {
			return nil, errors.New("polar: hosted origin must be an exact HTTPS origin")
		}
		checkout.Products = make(map[string]string, len(opts.Checkout.Products))
		for slug, id := range opts.Checkout.Products {
			if !requestKey.MatchString(slug) || !canonicalID(id) {
				return nil, errors.New("polar: invalid product slug or UUID")
			}
			checkout.Products[slug] = id
			s.products[id] = true
		}
		s.opts.Checkout = &checkout
	}
	if opts.Webhooks != nil {
		webhooks := *opts.Webhooks
		if webhooks.Secret == "" {
			return nil, errors.New("polar: a webhook signing secret is required")
		}
		var err error
		if webhooks.LegacySecret {
			s.verifier, err = standard.NewWebhookRaw([]byte(webhooks.Secret))
		} else {
			s.verifier, err = standard.NewWebhook(webhooks.Secret)
		}
		if err != nil {
			return nil, errors.New("polar: invalid webhook signing secret")
		}
		s.opts.Webhooks = &webhooks
	}
	if opts.Portal != nil {
		portal := *opts.Portal
		if err := portal.validate(); err != nil {
			return nil, err
		}
		s.opts.Portal = &portal
	}
	if opts.SignUpCustomer != nil {
		signUp := *opts.SignUpCustomer
		s.opts.SignUpCustomer = &signUp
	}
	return s, nil
}

var errSignUpParams = errors.New("polar: SignUpCustomer.Params panicked")

// Plugin returns the configured billing endpoints.
func (s *Service) Plugin() auth.Plugin {
	var endpoints []auth.Endpoint
	if s.opts.Checkout != nil {
		endpoints = append(endpoints, auth.Endpoint{Method: "POST", Path: "/checkout", Handler: s.checkout})
	}
	if s.opts.Webhooks != nil {
		endpoints = append(endpoints, auth.Endpoint{Method: "POST", Path: "/polar/webhooks", RawBody: true, Handler: s.webhook})
	}
	if s.opts.Portal != nil {
		endpoints = append(endpoints,
			auth.Endpoint{Method: "GET", Path: "/customer/portal", Handler: s.portal},
			auth.Endpoint{Method: "POST", Path: "/customer/portal", Handler: s.portal},
			auth.Endpoint{Method: "GET", Path: "/customer/state", Handler: s.customerState},
			auth.Endpoint{Method: "GET", Path: "/customer/benefits/list", Handler: s.customerBenefits},
			auth.Endpoint{Method: "GET", Path: "/customer/orders/list", Handler: s.customerOrders},
			auth.Endpoint{Method: "GET", Path: "/customer/subscriptions/list", Handler: s.customerSubscriptions},
		)
	}
	if s.opts.Usage != nil {
		endpoints = append(endpoints, auth.Endpoint{Method: "GET", Path: "/usage/meters/list", Handler: s.customerMeters})
	}
	plugin := auth.Plugin{ID: "polar", Endpoints: endpoints}
	if s.opts.SignUpCustomer != nil {
		plugin.DatabaseHooks.User.Create.After = s.customerOnSignUp
	}
	return plugin
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

// maxCheckoutProducts bounds the products one checkout offers.
const maxCheckoutProducts = 10

// selection reads the products a checkout offers: products, a string or up
// to ten distinct configured product IDs in order, or a slug. When both are
// sent, as another runtime's client examples send them, the slug decides
// the purchase and products must still be valid.
func (s *Service) selection(body map[string]any) (products []string, redirect bool, err error) {
	bad := failure(400, "POLAR_INVALID_PRODUCT", "Select configured products by slug or ID")
	redirect = true
	var slugged string
	for field, v := range body {
		switch field {
		case "slug":
			slug, _ := v.(string)
			if s.opts.Checkout.Products[slug] == "" {
				return nil, false, bad
			}
			slugged = s.opts.Checkout.Products[slug]
		case "products":
			var listed []string
			switch v := v.(type) {
			case string:
				listed = []string{v}
			case []any:
				for _, entry := range v {
					id, _ := entry.(string)
					listed = append(listed, id)
				}
			}
			if len(listed) == 0 || len(listed) > maxCheckoutProducts {
				return nil, false, bad
			}
			for i, id := range listed {
				if !s.products[id] || slices.Contains(listed[:i], id) {
					return nil, false, bad
				}
			}
			products = listed
		case "redirect":
			var ok bool
			redirect, ok = v.(bool)
			if !ok {
				return nil, false, bad
			}
		default:
			return nil, false, failure(400, "POLAR_INVALID_FIELD", "Unsupported checkout field")
		}
	}
	if slugged != "" {
		products = []string{slugged}
	}
	if len(products) == 0 {
		return nil, false, bad
	}
	return products, redirect, nil
}

func (s *Service) checkout(c auth.EndpointContext) (any, error) {
	ctx := c.Request.Context()
	session, err := s.owner(c)
	if err != nil {
		return nil, err
	}
	products, redirect, err := s.selection(c.Body)
	if err != nil {
		return nil, err
	}
	success, err := c.CallbackURL(s.opts.Checkout.SuccessURL)
	if err != nil {
		return nil, err
	}
	back := s.opts.Checkout.ReturnURL
	if back != "" {
		back, err = c.CallbackURL(back)
		if err != nil {
			return nil, err
		}
	}
	keys := c.Request.Header.Values("Idempotency-Key")
	if len(keys) > 1 || len(keys) == 1 && !requestKey.MatchString(keys[0]) {
		return nil, failure(400, "POLAR_INVALID_REQUEST_KEY", "Invalid Idempotency-Key")
	}
	key := "default:" + strings.Join(products, ",")
	if len(keys) == 1 {
		key = "explicit:" + keys[0]
	}
	keyParts, _ := json.Marshal([]string{s.opts.OrganizationID, session.User.ID, key})
	slot := sha256.Sum256(keyParts)
	contact := sha256.Sum256([]byte(session.User.Email))
	req := reservation{
		Slot: hex.EncodeToString(slot[:]), Attempt: uuid.NewString(),
		Owner: session.User.ID, ContactHash: hex.EncodeToString(contact[:]),
		Product: products[0], Products: products, Merchant: s.opts.OrganizationID, Success: success, Return: back,
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
		Products: req.Products, ExternalCustomerID: &req.Owner, CustomerEmail: &email,
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
	_, err = s.apply(ctx, snapshot, nil)
	return err
}

func pending() error {
	return failure(409, "POLAR_CHECKOUT_PENDING", "Checkout is awaiting provider confirmation. Retry with the same request key")
}
func conflict() error {
	return failure(409, "POLAR_CHECKOUT_CONFLICT", "Checkout details did not match the reserved purchase")
}

// hosted checks a checkout URL's shape and, with Checkout, its exact
// hosted origin. A webhooks-only node has no origin to compare, so it
// accepts any host: the checkout route checks the exact origin again before
// it hands out a stored URL.
func (s *Service) hosted(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || strings.ContainsAny(raw, "\\\r\n") || u.Fragment != "" {
		return false
	}
	return s.opts.Checkout == nil || u.Scheme+"://"+u.Host == s.opts.Checkout.HostedOrigin
}

// ReconcileCheckout reads a known Polar checkout after a lost response. It never
// creates a checkout, returns its hosted URL, or synthesizes a signed delivery.
func (s *Service) ReconcileCheckout(ctx context.Context, id string) error {
	if s.opts.Checkout == nil {
		return errors.New("polar: checkout is not enabled")
	}
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
	_, err = s.apply(ctx, fromSDK(reply.Checkout), nil)
	return err
}
