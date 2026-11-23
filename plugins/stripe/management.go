package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// SubscriptionManagementStore resolves a Stripe subscription only after checking
// the current owner session and the local customer mapping.
type SubscriptionManagementStore interface {
	ManagedStripeSubscription(ctx context.Context, referenceID, token, providerID string, now time.Time) (Subscription, error)
}

var ErrManagedSubscriptionNotFound = billingError(http.StatusBadRequest, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")

func managedSubscription(c auth.EndpointContext, selection billingSelection, id string) (Subscription, error) {
	store, ok := c.Store().(SubscriptionManagementStore)
	if !ok {
		return Subscription{}, errors.New("stripe: store does not support subscription management")
	}
	row, err := store.ManagedStripeSubscription(c.Request.Context(), selection.reference, selection.session.Session.Token, id, time.Now().UTC())
	if errors.Is(err, auth.ErrNotFound) {
		return Subscription{}, ErrManagedSubscriptionNotFound
	}
	return row, err
}

// recheckManaged binds each external operation to the same customer and
// subscription, including when the caller originally omitted a subscription ID.
func recheckManaged(c auth.EndpointContext, selection billingSelection, local Subscription) (Subscription, error) {
	if local.SubscriptionID == nil || local.CustomerID == nil {
		return Subscription{}, ErrCheckoutReconcile
	}
	row, err := managedSubscription(c, selection, *local.SubscriptionID)
	if err != nil {
		return row, err
	}
	if row.ID != local.ID || row.ReferenceID != selection.reference || row.CustomerID == nil || *row.CustomerID != *local.CustomerID ||
		row.SubscriptionID == nil || *row.SubscriptionID != *local.SubscriptionID {
		return row, ErrCheckoutReconcile
	}
	return row, nil
}

func providerManagementError(err error) error {
	var api *sdk.Error
	if errors.As(err, &api) {
		if api.HTTPStatusCode == 404 && api.Code == sdk.ErrorCodeResourceMissing {
			return ErrManagedSubscriptionNotFound
		}
		if api.HTTPStatusCode == 400 && api.Code != "" {
			return billingError(400, string(api.Code), "Stripe rejected this subscription change")
		}
	}
	return billingError(502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "Could not contact the billing provider")
}

func (s *subscriptions) currentManaged(c auth.EndpointContext, selection billingSelection, local Subscription) (*sdk.Subscription, error) {
	sub, err := s.refreshManagedSubscription(c, local, selection.session.Session.Token)
	var providerError *sdk.Error
	switch {
	case errors.As(err, &providerError):
		return nil, providerManagementError(err)
	case errors.Is(err, auth.ErrNotFound), err == nil && sub == nil:
		return nil, ErrManagedSubscriptionNotFound
	case errors.Is(err, ErrStripeRevisionChanged):
		return nil, ErrCheckoutReconcile
	default:
		return sub, err
	}
}

func (s *subscriptions) cancel(c auth.EndpointContext) (any, error) {
	selection, err := selectBilling(&c, cancelFields, "cancel-subscription", s.organization)
	if err != nil {
		return nil, err
	}
	raw, _ := c.Body["returnUrl"].(string)
	returnURL, err := c.Auth.CallbackURL(raw)
	if err != nil {
		return nil, err
	}
	disable, _ := c.Body["disableRedirect"].(bool)
	id, _ := c.Body["subscriptionId"].(string)
	local, err := managedSubscription(c, selection, id)
	if err != nil {
		return nil, err
	}
	sub, err := s.currentManaged(c, selection, local)
	if err != nil {
		return nil, err
	}
	if sub.Status != sdk.SubscriptionStatusActive && sub.Status != sdk.SubscriptionStatusTrialing {
		return nil, ErrManagedSubscriptionNotFound
	}
	params := &sdk.BillingPortalSessionCreateParams{
		Customer: sdk.String(sub.Customer.ID), ReturnURL: sdk.String(returnURL),
		FlowData: &sdk.BillingPortalSessionCreateFlowDataParams{
			Type:               sdk.String("subscription_cancel"),
			SubscriptionCancel: &sdk.BillingPortalSessionCreateFlowDataSubscriptionCancelParams{Subscription: sdk.String(sub.ID)},
		},
	}
	if _, err := recheckManaged(c, selection, local); err != nil {
		return nil, err
	}
	portal, err := s.client.V1BillingPortalSessions.Create(c.Request.Context(), params)
	if err != nil {
		var api *sdk.Error
		if errors.As(err, &api) && strings.Contains(strings.ToLower(api.Msg), "already set to be canceled") {
			if _, syncErr := s.currentManaged(c, selection, local); syncErr != nil {
				return nil, syncErr
			}
		}
		return nil, providerManagementError(err)
	}
	if portal == nil || portal.URL == "" || ((selection.organization || portal.Customer != "") && portal.Customer != sub.Customer.ID) {
		return nil, billingError(502, "UNABLE_TO_CREATE_BILLING_PORTAL", "Stripe did not return a billing portal URL")
	}
	row, err := recheckManaged(c, selection, local)
	if err != nil {
		return nil, err
	}
	if row.Status != "active" && row.Status != "trialing" {
		return nil, ErrManagedSubscriptionNotFound
	}
	return map[string]any{"url": portal.URL, "redirect": !disable}, nil
}

func (s *subscriptions) restore(c auth.EndpointContext) (any, error) {
	selection, err := selectBilling(&c, restoreFields, "restore-subscription", s.organization)
	if err != nil {
		return nil, err
	}
	id, _ := c.Body["subscriptionId"].(string)
	local, err := managedSubscription(c, selection, id)
	if err != nil {
		return nil, err
	}
	if local.Status != "active" && local.Status != "trialing" {
		return nil, billingError(400, "SUBSCRIPTION_NOT_ACTIVE", "Subscription is not active")
	}
	sub, err := s.currentManaged(c, selection, local)
	if err != nil {
		return nil, err
	}
	if sub.Status != sdk.SubscriptionStatusActive && sub.Status != sdk.SubscriptionStatusTrialing {
		return nil, ErrManagedSubscriptionNotFound
	}
	ctx := c.Request.Context()
	switch {
	case sub.Schedule != nil && sub.Schedule.ID != "":
		schedule, err := s.client.V1SubscriptionSchedules.Retrieve(ctx, sub.Schedule.ID, nil)
		if err != nil {
			return nil, providerManagementError(err)
		}
		if schedule == nil || schedule.ID != sub.Schedule.ID || schedule.Customer == nil || schedule.Customer.ID != sub.Customer.ID ||
			schedule.Subscription == nil || schedule.Subscription.ID != sub.ID || schedule.Status != sdk.SubscriptionScheduleStatusActive {
			return nil, ErrCheckoutReconcile
		}
		row, err := recheckManaged(c, selection, local)
		if err != nil {
			return nil, err
		}
		if row.ScheduleID == nil || *row.ScheduleID != schedule.ID {
			return nil, ErrCheckoutReconcile
		}
		if store, ok := c.Store().(ScheduleReleaseStore); ok {
			if err := store.PrepareStripeScheduleRelease(ctx, selection.session.Session.Token, row, schedule.ID, time.Now().UTC()); err != nil {
				return nil, err
			}
		}
		if _, err = s.client.V1SubscriptionSchedules.Release(ctx, schedule.ID, nil); err != nil {
			return nil, providerManagementError(err)
		}
		if store, ok := c.Store().(SubscriptionScheduleStore); ok {
			if err := store.ForgetStripeSchedule(ctx, selection.reference, selection.session.Session.Token, sub.ID, schedule.ID, time.Now().UTC()); err != nil {
				return nil, err
			}
		}
	case sub.CancelAt != 0 || sub.CancelAtPeriodEnd:
		params := &sdk.SubscriptionUpdateParams{}
		if sub.CancelAt != 0 {
			params.AddUnsetField(sdk.SubscriptionUpdateParamsUnsetFieldCancelAt)
		} else {
			params.CancelAtPeriodEnd = sdk.Bool(false)
		}
		row, err := recheckManaged(c, selection, local)
		if err != nil {
			return nil, err
		}
		dateChanged := sub.CancelAt != 0 && (row.CancelAt == nil || row.CancelAt.Unix() != sub.CancelAt)
		periodEndChanged := sub.CancelAt == 0 && (row.CancelAtPeriodEnd == nil || !*row.CancelAtPeriodEnd)
		if dateChanged || periodEndChanged {
			return nil, ErrCheckoutReconcile
		}
		if _, err = s.client.V1Subscriptions.Update(ctx, sub.ID, params); err != nil {
			return nil, providerManagementError(err)
		}
	default:
		// A provider change can succeed before the confirming request is retried.
		if local.ScheduleID != nil || local.CancelAt != nil || (local.CancelAtPeriodEnd != nil && *local.CancelAtPeriodEnd) {
			return subscriptionResponse(sub)
		}
		return nil, billingError(400, "SUBSCRIPTION_NOT_PENDING_CHANGE", "Subscription has no pending cancellation or scheduled plan change")
	}
	sub, err = s.currentManaged(c, selection, local)
	if err != nil {
		return nil, err
	}
	return subscriptionResponse(sub)
}

func subscriptionResponse(sub *sdk.Subscription) (json.RawMessage, error) {
	// Stripe expandable fields can be either IDs or objects. Marshalling the
	// Go struct turns every ID into an object and loses unknown provider fields.
	if sub == nil || sub.LastResponse == nil || !json.Valid(sub.LastResponse.RawJSON) {
		return nil, billingError(502, "INVALID_STRIPE_RESPONSE", "Stripe returned an invalid subscription")
	}
	return json.RawMessage(sub.LastResponse.RawJSON), nil
}
