package stripe

import (
	"context"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// ScheduleChange identifies the exact item, prices and billing window a user
// authorized. ID is the durable idempotency key shared between server instances.
type ScheduleChange struct {
	ID, Owner, Customer, LocalID, Subscription, Item, Current, Target, Schedule string
	CurrentPlan, CurrentInterval                                                string
	Start, End, Created                                                         int64
}

type SubscriptionScheduleStore interface {
	ReserveStripeSchedule(ctx context.Context, token string, want ScheduleChange, attached string, now time.Time) (ScheduleChange, error)
	BindStripeSchedule(ctx context.Context, token string, change ScheduleChange, schedule string, now time.Time) error
	ForgetStripeSchedule(ctx context.Context, owner, token, subscription, schedule string, now time.Time) error
}

// ScheduleReleaseStore records the observed schedule before releasing it. This
// lets a later request recover even if both creation and release responses are lost.
type ScheduleReleaseStore interface {
	PrepareStripeScheduleRelease(ctx context.Context, token string, subscription Subscription, schedule string, now time.Time) error
}

const scheduleSource = "stonewrit-auth"

func (s *subscriptions) scheduleChange(c stonewrit.EndpointContext, selection billingSelection, local Subscription, sub *sdk.Subscription, item *sdk.SubscriptionItem, target, returnURL string) (any, error) {
	store, ok := c.Store().(SubscriptionScheduleStore)
	if !ok {
		return nil, billingError(400, "SCHEDULING_UNAVAILABLE", "Subscription scheduling requires a schedule store")
	}
	now := time.Now().UTC()
	// Rewriting a discounted, taxed, or trial phase could change the invoice.
	// Restrict this operation to an ordinary, automatically charged single item.
	if sub.Status != sdk.SubscriptionStatusActive || item.CurrentPeriodStart <= 0 || item.CurrentPeriodStart > now.Unix() || item.CurrentPeriodEnd <= now.Unix() ||
		len(sub.Discounts) > 0 || len(sub.DefaultTaxRates) > 0 || sub.BillingThresholds != nil || (sub.AutomaticTax != nil && sub.AutomaticTax.Enabled) ||
		sub.ApplicationFeePercent != 0 || sub.OnBehalfOf != nil || sub.TransferData != nil || (sub.CollectionMethod != "" && sub.CollectionMethod != sdk.SubscriptionCollectionMethodChargeAutomatically) ||
		len(item.Discounts) > 0 || len(item.TaxRates) > 0 || item.BillingThresholds != nil || len(item.Metadata) > 0 {
		return nil, errUnsupportedItem
	}
	ctx := c.Request.Context()
	var attached string
	if sub.Schedule != nil {
		attached = sub.Schedule.ID
	}
	sourcePrice := s.prices[item.Price.ID]
	want := ScheduleChange{
		Owner: selection.reference, Customer: sub.Customer.ID, LocalID: local.ID, Subscription: sub.ID,
		Item: item.ID, Current: item.Price.ID, Target: target, CurrentPlan: sourcePrice.plan, CurrentInterval: sourcePrice.interval,
		Start: item.CurrentPeriodStart, End: item.CurrentPeriodEnd,
	}
	attempt, err := store.ReserveStripeSchedule(ctx, selection.session.Session.Token, want, attached, now)
	if err != nil {
		return nil, err
	}
	if attempt.Schedule != "" && attached == "" {
		prior, err := s.client.V1SubscriptionSchedules.Retrieve(ctx, attempt.Schedule, nil)
		if err != nil {
			return nil, providerManagementError(err)
		}
		if prior == nil || prior.ID != attempt.Schedule || prior.Customer == nil || prior.Customer.ID != sub.Customer.ID {
			return nil, ErrCheckoutReconcile
		}
		if prior.Status == sdk.SubscriptionScheduleStatusReleased && prior.ReleasedSubscription != nil && prior.ReleasedSubscription.ID == sub.ID {
			if err = store.ForgetStripeSchedule(ctx, selection.reference, selection.session.Session.Token, sub.ID, prior.ID, time.Now().UTC()); err != nil {
				return nil, err
			}
			attempt, err = store.ReserveStripeSchedule(ctx, selection.session.Session.Token, want, "", time.Now().UTC())
			if err != nil {
				return nil, err
			}
		} else if !ownerSchedule(prior, attempt) {
			return nil, ErrCheckoutReconcile
		}
	}
	if attempt.Item != want.Item || attempt.Current != want.Current || attempt.Target != want.Target || attempt.Start != want.Start || attempt.End != want.End {
		return nil, ErrPendingSchedule
	}
	if attempt.Schedule == "" {
		// A retried create receives the original schedule, even if the first
		// response was lost after Stripe attached it to the subscription.
		params := &sdk.SubscriptionScheduleCreateParams{FromSubscription: sdk.String(sub.ID)}
		params.SetIdempotencyKey("stonewrit-schedule-create-" + attempt.ID)
		created, err := s.client.V1SubscriptionSchedules.Create(ctx, params)
		if err != nil {
			return nil, providerManagementError(err)
		}
		if !ownerSchedule(created, attempt) || (attached != "" && created.ID != attached) {
			return nil, ErrCheckoutReconcile
		}
		if err := store.BindStripeSchedule(ctx, selection.session.Session.Token, attempt, created.ID, time.Now().UTC()); err != nil {
			return nil, err
		}
		attempt.Schedule = created.ID
	}
	schedule, err := s.client.V1SubscriptionSchedules.Retrieve(ctx, attempt.Schedule, nil)
	if err != nil {
		return nil, providerManagementError(err)
	}
	if !ownerSchedule(schedule, attempt) || schedule.ID != attempt.Schedule {
		return nil, ErrCheckoutReconcile
	}
	if !scheduledTarget(schedule, attempt) {
		if !unconfiguredSchedule(schedule, attempt) {
			return nil, ErrCheckoutReconcile
		}
		// This check also catches revocation or a restore while Stripe responded.
		if err := store.BindStripeSchedule(ctx, selection.session.Session.Token, attempt, schedule.ID, time.Now().UTC()); err != nil {
			return nil, err
		}
		first := &sdk.SubscriptionScheduleUpdatePhaseParams{StartDate: sdk.Int64(attempt.Start), EndDate: sdk.Int64(attempt.End), Items: scheduleItem(attempt.Current)}
		next := &sdk.SubscriptionScheduleUpdatePhaseParams{StartDate: sdk.Int64(attempt.End), ProrationBehavior: sdk.String("none"), Items: scheduleItem(attempt.Target)}
		params := &sdk.SubscriptionScheduleUpdateParams{EndBehavior: sdk.String("release"), Phases: []*sdk.SubscriptionScheduleUpdatePhaseParams{first, next},
			Metadata: map[string]string{"source": scheduleSource, "stonewritPlanChange": attempt.ID}}
		params.SetIdempotencyKey("stonewrit-schedule-update-" + attempt.ID)
		updated, err := s.client.V1SubscriptionSchedules.Update(ctx, schedule.ID, params)
		if err != nil {
			return nil, providerManagementError(err)
		}
		if !ownerSchedule(updated, attempt) || updated.ID != schedule.ID || !scheduledTarget(updated, attempt) {
			return nil, ErrCheckoutReconcile
		}
	}
	current, err := s.currentManaged(c, selection, local)
	if err != nil {
		return nil, err
	}
	if current.Schedule == nil || current.Schedule.ID != attempt.Schedule {
		return nil, ErrCheckoutReconcile
	}
	if err := store.BindStripeSchedule(ctx, selection.session.Session.Token, attempt, attempt.Schedule, time.Now().UTC()); err != nil {
		return nil, err
	}
	disable, _ := c.Body["disableRedirect"].(bool)
	return map[string]any{"url": returnURL, "redirect": !disable}, nil
}

func ownerSchedule(v *sdk.SubscriptionSchedule, a ScheduleChange) bool {
	return v != nil && v.ID != "" && v.Status == sdk.SubscriptionScheduleStatusActive && v.Customer != nil && v.Customer.ID == a.Customer && v.Subscription != nil && v.Subscription.ID == a.Subscription
}

func phaseItem(p *sdk.SubscriptionSchedulePhase, price string) bool {
	return p != nil && len(p.Items) == 1 && p.Items[0] != nil && p.Items[0].Price != nil && p.Items[0].Price.ID == price && p.Items[0].Quantity == 1
}

func scheduleItem(price string) []*sdk.SubscriptionScheduleUpdatePhaseItemParams {
	return []*sdk.SubscriptionScheduleUpdatePhaseItemParams{{Price: sdk.String(price), Quantity: sdk.Int64(1)}}
}

func scheduledTarget(v *sdk.SubscriptionSchedule, a ScheduleChange) bool {
	return v.Metadata["source"] == scheduleSource && v.Metadata["stonewritPlanChange"] == a.ID && v.EndBehavior == sdk.SubscriptionScheduleEndBehaviorRelease &&
		len(v.Phases) == 2 && phaseItem(v.Phases[0], a.Current) && v.Phases[0].StartDate == a.Start && v.Phases[0].EndDate == a.End &&
		phaseItem(v.Phases[1], a.Target) && v.Phases[1].StartDate == a.End && v.Phases[1].ProrationBehavior == "none"
}

func unconfiguredSchedule(v *sdk.SubscriptionSchedule, a ScheduleChange) bool {
	if len(v.Metadata) > 0 || len(v.Phases) != 1 || !phaseItem(v.Phases[0], a.Current) || len(v.PauseSchedules) > 0 {
		return false
	}
	p := v.Phases[0]
	i := p.Items[0]
	return p.StartDate == a.Start && p.EndDate == a.End && !p.Trial && p.TrialEnd == 0 &&
		len(p.AddInvoiceItems) == 0 && p.ApplicationFeePercent == 0 && (p.AutomaticTax == nil || !p.AutomaticTax.Enabled) &&
		p.BillingThresholds == nil && (p.CollectionMethod == nil || *p.CollectionMethod == sdk.SubscriptionCollectionMethodChargeAutomatically) &&
		p.DefaultPaymentMethod == nil && len(p.DefaultTaxRates) == 0 && p.Description == "" && len(p.Discounts) == 0 &&
		len(p.Metadata) == 0 && p.OnBehalfOf == nil && p.TransferData == nil &&
		(p.BillingCycleAnchor == "" || p.BillingCycleAnchor == "automatic") && ordinaryInvoice(p.InvoiceSettings) &&
		i.BillingThresholds == nil && len(i.Discounts) == 0 && len(i.Metadata) == 0 && len(i.TaxRates) == 0
}

func ordinaryInvoice(v *sdk.SubscriptionSchedulePhaseInvoiceSettings) bool {
	return v == nil || (len(v.AccountTaxIDs) == 0 && len(v.CustomFields) == 0 && v.DaysUntilDue == 0 && v.Description == "" && v.Footer == "" &&
		(v.Issuer == nil || (v.Issuer.Type == sdk.SubscriptionSchedulePhaseInvoiceSettingsIssuerTypeSelf && v.Issuer.Account == nil)))
}
