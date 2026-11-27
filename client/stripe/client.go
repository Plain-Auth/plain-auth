// Package stripe calls the hosted Checkout and subscription endpoints with an
// existing Plain Auth client. The application retains control of redirects.
package stripe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/Plain-Org/plain-auth/client"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
)

type Client struct{ Auth *client.Client }

type Checkout struct {
	CustomerType        string `json:"customerType,omitempty"`
	ReferenceID         string `json:"referenceId,omitempty"`
	Plan                string `json:"plan"`
	Seats               int64  `json:"seats,omitempty"`
	ScheduleAtPeriodEnd bool   `json:"scheduleAtPeriodEnd,omitempty"`
	Annual              bool   `json:"annual,omitempty"`
	SubscriptionID      string `json:"subscriptionId,omitempty"`
	ReturnURL           string `json:"returnUrl,omitempty"`
	SuccessURL          string `json:"successUrl,omitempty"`
	CancelURL           string `json:"cancelUrl,omitempty"`
	DisableRedirect     bool   `json:"disableRedirect,omitempty"`
	// Locale is the Checkout display language, such as "ko"; empty lets
	// Checkout use the browser's.
	Locale string `json:"locale,omitempty"`
}

type HostedPage struct {
	ID       string `json:"id,omitempty"`
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
	// Session is the Checkout Session a new purchase answers, read again
	// for a pending purchase; nil when the server could not read it or the
	// page is not a Checkout.
	Session *sdk.CheckoutSession `json:"-"`
}

type Cancellation struct {
	CustomerType    string `json:"customerType,omitempty"`
	ReferenceID     string `json:"referenceId,omitempty"`
	SubscriptionID  string `json:"subscriptionId,omitempty"`
	ReturnURL       string `json:"returnUrl"`
	DisableRedirect bool   `json:"disableRedirect,omitempty"`
}

type Portal struct {
	CustomerType    string `json:"customerType,omitempty"`
	ReferenceID     string `json:"referenceId,omitempty"`
	ReturnURL       string `json:"returnUrl,omitempty"`
	Locale          string `json:"locale,omitempty"`
	DisableRedirect bool   `json:"disableRedirect,omitempty"`
}

func (c Client) Upgrade(ctx context.Context, in Checkout) (HostedPage, error) {
	var raw json.RawMessage
	if err := c.Auth.Do(ctx, http.MethodPost, "/subscription/upgrade", in, &raw); err != nil {
		return HostedPage{}, err
	}
	var page HostedPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return page, err
	}
	// A new purchase answers Stripe's Checkout Session; a plan change
	// answers only a URL.
	var session sdk.CheckoutSession
	if json.Unmarshal(raw, &session) == nil && session.Object == "checkout.session" {
		page.Session = &session
	}
	return page, nil
}

func (c Client) List(ctx context.Context) ([]billing.Subscription, error) {
	var rows []billing.Subscription
	err := c.Auth.Do(ctx, http.MethodGet, "/subscription/list", nil, &rows)
	return rows, err
}

// ListOrganization lists subscriptions for an explicit or active organization.
func (c Client) ListOrganization(ctx context.Context, id string) ([]billing.Subscription, error) {
	q := url.Values{"customerType": {"organization"}}
	if id != "" {
		q.Set("referenceId", id)
	}
	var rows []billing.Subscription
	err := c.Auth.Do(ctx, http.MethodGet, "/subscription/list?"+q.Encode(), nil, &rows)
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
	return c.restore(ctx, subscriptionID, "", "")
}

// RestoreOrganization restores a subscription belonging to the selected organization.
// An empty referenceID selects the session's active organization.
func (c Client) RestoreOrganization(ctx context.Context, referenceID, subscriptionID string) (*sdk.Subscription, error) {
	return c.restore(ctx, subscriptionID, referenceID, "organization")
}

func (c Client) restore(ctx context.Context, subscriptionID, referenceID, kind string) (*sdk.Subscription, error) {
	body := struct {
		SubscriptionID string `json:"subscriptionId,omitempty"`
		ReferenceID    string `json:"referenceId,omitempty"`
		CustomerType   string `json:"customerType,omitempty"`
	}{subscriptionID, referenceID, kind}
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
