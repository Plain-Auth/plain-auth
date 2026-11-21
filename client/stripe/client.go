// Package stripe calls the hosted Checkout and subscription endpoints with an
// existing StoneWrit client. The application retains control of redirects.
package stripe

import (
	"context"
	"net/http"

	"github.com/Stonewrit/stonewrit-auth/client"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
)

type Client struct{ Auth *client.Client }

type Checkout struct {
	Plan            string `json:"plan"`
	Annual          bool   `json:"annual,omitempty"`
	SubscriptionID  string `json:"subscriptionId,omitempty"`
	ReturnURL       string `json:"returnUrl,omitempty"`
	SuccessURL      string `json:"successUrl,omitempty"`
	CancelURL       string `json:"cancelUrl,omitempty"`
	DisableRedirect bool   `json:"disableRedirect,omitempty"`
}

type HostedPage struct {
	ID       string `json:"id,omitempty"`
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

type Cancellation struct {
	SubscriptionID  string `json:"subscriptionId,omitempty"`
	ReturnURL       string `json:"returnUrl"`
	DisableRedirect bool   `json:"disableRedirect,omitempty"`
}

type Portal struct {
	ReturnURL       string `json:"returnUrl,omitempty"`
	Locale          string `json:"locale,omitempty"`
	DisableRedirect bool   `json:"disableRedirect,omitempty"`
}

func (c Client) Upgrade(ctx context.Context, in Checkout) (HostedPage, error) {
	var page HostedPage
	err := c.Auth.Do(ctx, http.MethodPost, "/subscription/upgrade", in, &page)
	return page, err
}

func (c Client) List(ctx context.Context) ([]billing.Subscription, error) {
	var rows []billing.Subscription
	err := c.Auth.Do(ctx, http.MethodGet, "/subscription/list", nil, &rows)
	return rows, err
}

func (c Client) Cancel(ctx context.Context, in Cancellation) (HostedPage, error) {
	var page HostedPage
	err := c.Auth.Do(ctx, http.MethodPost, "/subscription/cancel", in, &page)
	return page, err
}

// Restore releases a scheduled change or clears an upcoming cancellation.
// An empty subscriptionID selects the signed-in user's first active subscription.
func (c Client) Restore(ctx context.Context, subscriptionID string) (*sdk.Subscription, error) {
	body := struct {
		SubscriptionID string `json:"subscriptionId,omitempty"`
	}{subscriptionID}
	var sub sdk.Subscription
	if err := c.Auth.Do(ctx, http.MethodPost, "/subscription/restore", body, &sub); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (c Client) BillingPortal(ctx context.Context, in Portal) (HostedPage, error) {
	var page HostedPage
	err := c.Auth.Do(ctx, http.MethodPost, "/subscription/billing-portal", in, &page)
	return page, err
}
