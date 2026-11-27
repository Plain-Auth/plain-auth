package stripe

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// UserCustomerOptions keeps users' Stripe customers outside Checkout. The
// store needs the user's stripeCustomerId column, which the
// stripe-subscriptions and stripe-organization schema profiles add.
type UserCustomerOptions struct {
	// Client calls Stripe. Required.
	Client *sdk.Client
	// CreateCustomerOnSignUp creates or links a Stripe customer for every new
	// user once the user is stored, and stores it as the user's
	// stripeCustomerId. It runs for HTTP sign-ups and direct Go calls such
	// as Auth.SignUpEmail. A failure is logged and the sign-up still
	// succeeds.
	CreateCustomerOnSignUp bool
	// CustomerCreateParams adds parameters to a customer a sign-up creates.
	// The plugin's email, name and metadata keys replace the host's. Request
	// options (StripeAccount, StripeContext, Headers and Extra) are refused,
	// and the customer is not created.
	CustomerCreateParams func(context.Context, NewUserCustomer) (*sdk.CustomerCreateParams, error)
	// OnCustomerCreate runs once a sign-up has stored a customer it created
	// or linked. An error is logged.
	OnCustomerCreate func(context.Context, UserCustomerCreated) error
	// Logger receives the sign-up hook's log lines. Nil uses the endpoint's
	// Auth logger, or slog.Default() for a direct Go call; pass the logger
	// set in plainauth.Options.Logger to keep them together.
	Logger *slog.Logger
}

// NewUserCustomer describes the user a sign-up creates or links a customer for.
type NewUserCustomer struct {
	// User is the stored user. Fields holds the additional fields the
	// sign-up set; it is empty for a sign-in the store decides, such as
	// social sign-in.
	User auth.UserRecord
	// Hook is the endpoint call that created the user, or nil for a direct
	// Go call such as Auth.SignUpEmail.
	Hook *auth.HookContext
}

// UserCustomerCreated reports the customer stored as the user's stripeCustomerId.
type UserCustomerCreated struct {
	NewUserCustomer
	Customer *sdk.Customer
}

// UserCustomerStore links users to Stripe customers outside Checkout.
type UserCustomerStore interface {
	// CheckStripeCustomerSchema checks for the user's stripeCustomerId column.
	CheckStripeCustomerSchema(context.Context) error
	// LinkStripeUserCustomer stores customer as the user's stripeCustomerId
	// while the user has none and no personal Checkout reservation, and
	// reports whether it did. A customer another user or an organization
	// holds answers ErrCustomerInUse.
	LinkStripeUserCustomer(ctx context.Context, userID, customer string) (bool, error)
}

// customerCallTimeout bounds a sign-up hook's Stripe calls.
const customerCallTimeout = 30 * time.Second

// userCustomers runs the user customer hooks. One plugin value serves one
// Auth: the store comes from that Auth's ValidateStore.
type userCustomers struct {
	opts  UserCustomerOptions
	store UserCustomerStore
}

func (h *userCustomers) useStore(store auth.Store) error {
	if h.opts.Client == nil {
		return errors.New("stripe: user customer options require a client")
	}
	s, ok := store.(UserCustomerStore)
	if !ok {
		return errors.New("stripe: user customer options require a store that links Stripe customers")
	}
	if err := s.CheckStripeCustomerSchema(context.Background()); err != nil {
		return err
	}
	h.store = s
	return nil
}

func (h *userCustomers) logger(c *auth.HookContext) *slog.Logger {
	switch {
	case h.opts.Logger != nil:
		return h.opts.Logger
	case c != nil:
		return c.Auth.Logger()
	}
	return slog.Default()
}

// afterSignUp creates or links a new user's Stripe customer. It runs once
// the user is stored, outside any transaction, and never fails the sign-up.
func (h *userCustomers) afterSignUp(ctx context.Context, row auth.UserRecord, c *auth.HookContext) error {
	log := h.logger(c)
	// A client that disconnects cannot cancel a customer Stripe created.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), customerCallTimeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			log.ErrorContext(ctx, "Stripe sign-up customer hook panicked", "user_id", row.ID)
		}
	}()
	h.signUpCustomer(ctx, log, NewUserCustomer{User: row, Hook: c})
	return nil
}

// signUpCustomer links the customer Stripe has for a verified email when no
// other user owns it, as another runtime does, or creates one. An
// unverified email is not looked up, as at Checkout, where another runtime
// looks it up and discards the match. Log lines carry IDs, never the email
// or error text.
func (h *userCustomers) signUpCustomer(ctx context.Context, log *slog.Logger, in NewUserCustomer) {
	user := in.User
	if user.EmailVerified {
		match, err := findUserCustomer(ctx, h.opts.Client, log, user.Email)
		if err != nil {
			log.ErrorContext(ctx, "Stripe customer lookup failed", append([]any{"user_id", user.ID}, stripeErrorAttrs(err)...)...)
			return
		}
		if match != nil && (match.Metadata["userId"] == "" || match.Metadata["userId"] == user.ID) {
			linked, err := h.store.LinkStripeUserCustomer(ctx, user.ID, match.ID)
			switch {
			case errors.Is(err, ErrCustomerInUse):
				// Another account holds it: a new customer is created.
			case err != nil:
				log.ErrorContext(ctx, "Stripe customer not linked", "user_id", user.ID, "customer_id", match.ID)
				return
			case !linked:
				log.WarnContext(ctx, "Stripe customer not linked", "user_id", user.ID, "customer_id", match.ID)
				return
			default:
				h.created(ctx, log, in, match, "Linked existing Stripe customer")
				return
			}
		}
	}
	params, ok := h.createParams(ctx, log, in)
	if !ok {
		return
	}
	customer, err := h.opts.Client.V1Customers.Create(ctx, params)
	if err != nil || customer == nil || customer.ID == "" {
		log.ErrorContext(ctx, "Stripe customer creation failed", append([]any{"user_id", user.ID}, stripeErrorAttrs(err)...)...)
		return
	}
	linked, err := h.store.LinkStripeUserCustomer(ctx, user.ID, customer.ID)
	if err != nil && !errors.Is(err, ErrCustomerInUse) {
		log.ErrorContext(ctx, "Stripe customer not linked", "user_id", user.ID, "customer_id", customer.ID)
		return
	}
	if !linked {
		// The user already has a customer or a pending Checkout, or was
		// deleted: the customer this sign-up created is removed.
		log.WarnContext(ctx, "Stripe customer not linked", "user_id", user.ID, "customer_id", customer.ID)
		if _, err := h.opts.Client.V1Customers.Delete(ctx, customer.ID, nil); err != nil {
			log.WarnContext(ctx, "Stripe customer not deleted", append([]any{"customer_id", customer.ID}, stripeErrorAttrs(err)...)...)
		}
		return
	}
	h.created(ctx, log, in, customer, "Created Stripe customer")
}

func (h *userCustomers) created(ctx context.Context, log *slog.Logger, in NewUserCustomer, customer *sdk.Customer, message string) {
	log.InfoContext(ctx, message, "user_id", in.User.ID, "customer_id", customer.ID)
	if h.opts.OnCustomerCreate == nil {
		return
	}
	if err := h.opts.OnCustomerCreate(ctx, UserCustomerCreated{NewUserCustomer: in, Customer: customer}); err != nil {
		log.ErrorContext(ctx, "Stripe OnCustomerCreate failed", "user_id", in.User.ID, "customer_id", customer.ID)
	}
}

// createParams builds a new customer's parameters: the host's, then the
// user's email and name and the plugin's metadata keys over them, as
// another runtime merges them.
func (h *userCustomers) createParams(ctx context.Context, log *slog.Logger, in NewUserCustomer) (*sdk.CustomerCreateParams, bool) {
	user := in.User
	own := &sdk.CustomerCreateParams{Email: sdk.String(user.Email), Name: sdk.String(user.Name), Metadata: map[string]string{"userId": user.ID, "customerType": "user"}}
	if h.opts.CustomerCreateParams == nil {
		return own, true
	}
	extra, err := h.opts.CustomerCreateParams(ctx, in)
	switch {
	case err != nil:
		log.ErrorContext(ctx, "Stripe CustomerCreateParams failed", "user_id", user.ID)
		return nil, false
	case extra == nil:
		return own, true
	case extra.StripeAccount != nil || extra.StripeContext != nil || extra.Headers != nil || extra.Extra != nil:
		// A connected account's customer could not be used by this
		// account's Checkout.
		log.ErrorContext(ctx, "Stripe CustomerCreateParams returned unsupported options", "user_id", user.ID)
		return nil, false
	}
	params := *extra
	meta := maps.Clone(extra.Params.Metadata)
	if meta == nil {
		meta = map[string]string{}
	}
	maps.Copy(meta, extra.Metadata)
	maps.Copy(meta, own.Metadata)
	params.Params = sdk.Params{}
	params.UnsetFields = nil
	params.Metadata, params.Email, params.Name = meta, own.Email, own.Name
	return &params, true
}
