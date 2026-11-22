package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
)

func fixtureStripe(ctx context.Context, store *sqlstore.Store, endpoint string, organizations, managedSeats bool) (stonewrit.Plugin, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return stonewrit.Plugin{}, errors.New("Stripe fixture requires a loopback HTTP origin")
	}
	client := &http.Client{
		Transport: &http.Transport{}, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	backends := sdk.NewBackendsWithConfig(&sdk.BackendConfig{
		URL: sdk.String(endpoint), HTTPClient: client, MaxNetworkRetries: sdk.Int64(0),
	})
	provider := sdk.NewClient("sk_test_offline_fixture", sdk.WithBackends(backends))
	var org *billing.OrganizationOptions
	if organizations {
		org = &billing.OrganizationOptions{AuthorizeReference: func(v billing.ReferenceAuthorization) bool { return v.Role == "owner" || v.Role == "admin" }}
	}
	subscriptions := &billing.SubscriptionOptions{Client: provider, Plans: []billing.Plan{
		{Name: "basic", PriceID: "price_basic"}, {Name: "team", PriceID: "price_team", AnnualPriceID: "price_team_annual"},
	}}
	if os.Getenv("CONFORMANCE_STRIPE_METERED_ADDONS") == "1" {
		subscriptions.Plans[1].MeteredPriceIDs = []string{"price_storage_annual", "price_requests_annual"}
	}
	if managedSeats {
		subscriptions.Plans[0].SeatPriceID = subscriptions.Plans[0].PriceID
		switch os.Getenv("CONFORMANCE_STRIPE_SEPARATE_PRICE") {
		case "1":
			subscriptions.Plans[0].SeatPriceID = "price_member"
		case "annual-seat-only":
			subscriptions.Plans[0].AnnualPriceID = "price_basic_annual"
			subscriptions.Plans[0].SeatPriceID = "price_basic_annual"
		case "annual":
			subscriptions.Plans[0].AnnualPriceID = "price_basic_annual"
			subscriptions.Plans[0].SeatPriceID = "price_member_annual"
		}
		worker, err := billing.NewSeatWorker(store, *subscriptions)
		if err != nil {
			return stonewrit.Plugin{}, err
		}
		go worker.Run(ctx, 25*time.Millisecond, func(err error) { log.Print(err) })
	}
	opts := billing.Options{Organization: org, WebhookSecret: "whsec_offline_fixture",
		Portal: &billing.PortalOptions{Client: provider, Customers: store}, Subscriptions: subscriptions,
	}
	family := os.Getenv("CONFORMANCE_STRIPE_LIFECYCLE_OBSERVERS") == "1"
	if family || os.Getenv("CONFORMANCE_STRIPE_UPDATE_OBSERVER") == "1" {
		appendRecord := func(record any) error {
			f, err := os.OpenFile(os.Args[1]+".stripe-updates", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				return err
			}
			defer f.Close()
			return json.NewEncoder(f).Encode(record)
		}
		subscriptions.OnSubscriptionUpdate = func(ctx context.Context, u billing.SubscriptionUpdate) error {
			if err := appendRecord([]any{"update", u.Event.ID, u.StripeSubscription.ID, u.Subscription.ReferenceID, u.Subscription.Status, u.StripeSubscription.Status}); err != nil {
				return err
			}
			if family {
				return nil
			}
			return errors.New("expected test observer failure")
		}
		if family {
			subscriptions.OnSubscriptionCreated = func(ctx context.Context, p billing.SubscriptionCreated) error {
				return appendRecord([]string{"created", p.Event.ID, p.StripeSubscription.ID, p.Subscription.ReferenceID, p.Plan.Name, p.Subscription.Status})
			}
			subscriptions.OnSubscriptionCancel = func(ctx context.Context, p billing.SubscriptionCancellation) error {
				details := ""
				if p.CancellationDetails != nil {
					details = p.CancellationDetails.Comment
				}
				if err := appendRecord([]string{"cancel", p.Event.ID, p.StripeSubscription.ID, p.Subscription.ReferenceID, details}); err != nil {
					return err
				}
				if details == "fixture-failure" {
					return errors.New("expected cancellation observer failure")
				}
				return nil
			}
			subscriptions.OnSubscriptionDeleted = func(ctx context.Context, p billing.SubscriptionEvent) error {
				return appendRecord([]string{"deleted", p.Event.ID, p.StripeSubscription.ID, p.Subscription.ReferenceID, p.Subscription.Status})
			}
		}
		opts.OnEvent = func(ctx context.Context, e sdk.Event) error { return appendRecord([]string{"event", e.ID}) }
	}
	return billing.New(opts), nil
}
