package stripe

import (
	"encoding/json"
	"errors"
	"net/http"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// CheckoutSessionInput is what CheckoutSessionParams learns about a new
// purchase. It runs before the purchase is reserved, so it has no local
// subscription ID, no trial decision, and Seats is 0 for a membership plan,
// whose members are counted when the purchase is reserved.
type CheckoutSessionInput struct {
	User    auth.User
	Session auth.Session
	Plan    Plan
	// ReferenceID is the billed user's or organization's ID; Organization
	// reports an organization purchase.
	ReferenceID  string
	Organization bool
	Interval     string
	Seats        int64
	// Request is a body-free copy of the upgrade request.
	Request *http.Request `json:"-"`
}

// maxCheckoutParamsBytes bounds the host's stored Checkout parameters, so
// the reservation stays within every store's column.
const maxCheckoutParamsBytes = 16 << 10

var errCheckoutParams = errors.New("stripe: Checkout Session parameters are unavailable")

// reservedMetadata are the metadata keys the plugin owns, which a host's
// values never replace, and the names another runtime drops for safety.
var reservedMetadata = map[string]bool{"userId": true, "referenceId": true, "subscriptionId": true, "checkoutAttemptId": true, "customerType": true, "organizationId": true,
	"__proto__": true, "constructor": true, "prototype": true}

// hostCheckoutParams asks the host's hook for a new purchase's Checkout
// parameters, outside any store transaction, and returns them encoded for
// the reservation. An APIError refuses the purchase with its status; any
// other failure is logged without its text and answers 500.
func (s *subscriptions) hostCheckoutParams(c auth.EndpointContext, in CheckoutSessionInput) (json.RawMessage, error) {
	ctx := c.Request.Context()
	params, err := s.checkoutParams(ctx, in)
	var refusal *auth.APIError
	switch {
	case errors.As(err, &refusal):
		return nil, err
	case err != nil:
		c.Auth.Logger().ErrorContext(ctx, "Stripe CheckoutSessionParams failed")
		return nil, errCheckoutParams
	case params == nil:
		return nil, nil
	}
	// Request options cannot be replayed from a stored reservation, and a
	// connected account's events are not reconciled.
	if params.StripeAccount != nil || params.StripeContext != nil || params.Headers != nil || params.Extra != nil {
		c.Auth.Logger().ErrorContext(ctx, "Stripe CheckoutSessionParams returned unsupported options")
		return nil, errCheckoutParams
	}
	raw, err := json.Marshal(params)
	if err != nil || len(raw) > maxCheckoutParamsBytes {
		c.Auth.Logger().ErrorContext(ctx, "Stripe CheckoutSessionParams returned parameters that cannot be stored")
		return nil, errCheckoutParams
	}
	return raw, nil
}

// checkoutSessionParams builds the Checkout Session request from the
// reservation: the host's stored parameters, then every plugin-owned field
// set from the reservation, so a retry sends an identical request.
func (a CheckoutAttempt) checkoutSessionParams(meta map[string]string, success string) (*sdk.CheckoutSessionCreateParams, error) {
	params := &sdk.CheckoutSessionCreateParams{}
	if len(a.CheckoutParams) > 0 {
		if err := json.Unmarshal(a.CheckoutParams, params); err != nil {
			return nil, err
		}
	}
	// The mode, customer, URLs, line items, expiry and hosted page are the
	// plugin's: a recovered session must match the reservation, and the
	// purchased lines must equal the reserved ones.
	params.Mode = sdk.String("subscription")
	params.Customer = sdk.String(a.Customer)
	params.ClientReferenceID = sdk.String(a.Owner)
	params.SuccessURL = sdk.String(success)
	params.CancelURL = sdk.String(a.CancelURL)
	params.ExpiresAt = sdk.Int64(a.Expires)
	params.LineItems = a.checkoutLines()
	params.CustomerEmail, params.CustomerCreation, params.CustomerAccount = nil, nil, nil
	params.AfterExpiration, params.OptionalItems, params.UIMode, params.ReturnURL, params.RedirectOnCompletion = nil, nil, nil, nil, nil
	params.Metadata = checkoutMetadata(params.Metadata, meta)
	if params.SubscriptionData == nil {
		params.SubscriptionData = &sdk.CheckoutSessionCreateSubscriptionDataParams{}
	}
	params.SubscriptionData.Metadata = checkoutMetadata(params.SubscriptionData.Metadata, meta)
	// The trial term is decided under lock against the owner's history.
	params.SubscriptionData.TrialPeriodDays, params.SubscriptionData.TrialEnd = nil, nil
	if a.TrialDays > 0 {
		params.SubscriptionData.TrialPeriodDays = sdk.Int64(a.TrialDays)
	}
	if a.Locale != "" {
		params.Locale = sdk.String(a.Locale)
	}
	// Checkout saves the buyer's address, and a person's name, onto the
	// existing customer, as another runtime does, unless the host chose.
	if params.CustomerUpdate == nil {
		params.CustomerUpdate = &sdk.CheckoutSessionCreateCustomerUpdateParams{Address: sdk.String("auto")}
		if a.OrganizationID == "" {
			params.CustomerUpdate.Name = sdk.String("auto")
		}
	}
	params.SetIdempotencyKey("auth-checkout-" + a.ID)
	return params, nil
}

// checkoutMetadata merges a host's metadata beneath the plugin's keys.
func checkoutMetadata(host, plugin map[string]string) map[string]string {
	out := make(map[string]string, len(host)+len(plugin))
	for k, v := range host {
		if !reservedMetadata[k] {
			out[k] = v
		}
	}
	for k, v := range plugin {
		out[k] = v
	}
	return out
}
