package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
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
	if managedSeats {
		subscriptions.Plans[0].SeatPriceID = subscriptions.Plans[0].PriceID
		worker, err := billing.NewSeatWorker(store, *subscriptions)
		if err != nil {
			return stonewrit.Plugin{}, err
		}
		go worker.Run(ctx, 25*time.Millisecond, func(err error) { log.Print(err) })
	}
	return billing.New(billing.Options{Organization: org, WebhookSecret: "whsec_offline_fixture",
		Portal: &billing.PortalOptions{Client: provider, Customers: store}, Subscriptions: subscriptions,
	}), nil
}
