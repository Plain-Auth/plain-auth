package polar

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/polarsource/polar-go/models/apierrors"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
	"github.com/polarsource/polar-go/retry"
)

// SignUpCustomerOptions creates a Polar customer, identified by the account
// ID, for each new account that is not a guest and whose email is verified
// when it is created, as another runtime's createCustomerOnSignUp does.
type SignUpCustomerOptions struct {
	// Params optionally adds fields to the new customer, as another runtime's
	// getCustomerCreateParams does. r is the sign-up request, or nil for a
	// direct Go call. It runs outside any database transaction, under the
	// same 10 second bound as the provider call.
	Params func(ctx context.Context, user auth.User, r *http.Request) (CustomerParams, error)
	// Logger receives the hook's log lines. Nil uses the endpoint's Auth
	// logger, or slog.Default() for a direct Go call; pass the logger set in
	// plainauth.Options.Logger to keep them together.
	Logger *slog.Logger
}

// CustomerParams holds the fields a host adds to the customer created at
// sign-up. The integration always sets the external ID, email, name and
// type from the account.
type CustomerParams struct {
	Metadata       map[string]components.CustomerIndividualCreateMetadata
	BillingAddress *components.AddressInput
	TaxID          *string
	Locale         *string
}

// signUpCustomerTimeout bounds the parameters callback and the provider call.
var signUpCustomerTimeout = 10 * time.Second

// customerOnSignUp creates the new account's Polar customer once the account
// is stored, outside any transaction. A guest or an unverified email gets
// none, where another runtime creates one for every account: Polar binds a
// customer to its email, so only a verified one is used, and an
// unverified account gets its customer from its first checkout, which
// requires a verified email. A failure is logged by account ID alone and
// never fails the sign-up.
func (s *Service) customerOnSignUp(ctx context.Context, row auth.UserRecord, c *auth.HookContext) error {
	if row.IsAnonymous != nil && *row.IsAnonymous || !row.EmailVerified {
		return nil
	}
	log, r := slog.Default(), (*http.Request)(nil)
	if c != nil {
		log, r = c.Auth.Logger(), c.Request
	}
	if s.opts.SignUpCustomer.Logger != nil {
		log = s.opts.SignUpCustomer.Logger
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), signUpCustomerTimeout)
	defer cancel()
	// A panic, in the SDK's decoder or a host transport, never fails the sign-up.
	defer func() {
		if recover() != nil {
			log.ErrorContext(ctx, "polar: the customer hook for a new account panicked", "user_id", row.ID)
		}
	}()
	var params CustomerParams
	if s.opts.SignUpCustomer.Params != nil {
		var err error
		if params, err = s.signUpParams(ctx, row.User, r); err != nil {
			log.WarnContext(ctx, "polar: SignUpCustomer.Params failed; no customer was created", "user_id", row.ID)
			return nil
		}
	}
	create := components.CustomerIndividualCreate{ExternalID: &row.ID, Email: row.Email, Metadata: params.Metadata,
		BillingAddress: params.BillingAddress, TaxID: params.TaxID, Locale: params.Locale}
	if row.Name != "" {
		create.Name = &row.Name
	}
	reply, err := s.opts.Client.Customers.Create(ctx, components.CreateCustomerCreateCustomerIndividualCreate(create),
		operations.WithRetries(retry.Config{Strategy: "none"}),
		operations.WithSetHeaders(map[string]string{"Polar-Version": apiVersion}),
	)
	var refused *apierrors.HTTPValidationError
	if errors.As(err, &refused) {
		// Polar keeps a customer's email unique, so an address another
		// customer holds, such as one an earlier account gave up, is refused.
		log.WarnContext(ctx, "polar: Polar refused the customer for a new account, such as for an email another customer holds", "user_id", row.ID)
		return nil
	}
	if err != nil {
		log.WarnContext(ctx, "polar: could not create the customer for a new account", "user_id", row.ID)
		return nil
	}
	if reply == nil || reply.Customer == nil || reply.Customer.CustomerIndividual == nil {
		log.ErrorContext(ctx, "polar: Polar returned an unexpected customer for a new account", "user_id", row.ID)
		return nil
	}
	if got := reply.Customer.CustomerIndividual; got.ExternalID == nil || *got.ExternalID != row.ID || got.OrganizationID != s.opts.OrganizationID || got.Email != row.Email {
		log.ErrorContext(ctx, "polar: Polar returned an unexpected customer for a new account", "user_id", row.ID)
	}
	return nil
}

// signUpParams runs the host's Params, recovering a panic as an error.
func (s *Service) signUpParams(ctx context.Context, user auth.User, r *http.Request) (params CustomerParams, err error) {
	defer func() {
		if recover() != nil {
			params, err = CustomerParams{}, errSignUpParams
		}
	}()
	return s.opts.SignUpCustomer.Params(ctx, user, r)
}
