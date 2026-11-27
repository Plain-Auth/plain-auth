package polar

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/polarsource/polar-go/models/components"
)

// Event is one verified Polar webhook delivery. Where another runtime offers
// a catch-all handler plus one handler per event type, OnEvent receives every
// type and the host switches on Type.
type Event struct {
	// DeliveryID is the webhook-id header. Polar sends the same value on every retry.
	DeliveryID string
	// Type is the event type, such as components.WebhookEventTypeOrderPaid.
	// A type the pinned SDK does not define keeps its wire value.
	Type components.WebhookEventType
	// Timestamp is the payload's timestamp, or zero when it is missing or not RFC 3339.
	Timestamp time.Time
	// Body is the verified request body. A checkout body carries the
	// checkout's client secret and hosted URL, and customer bodies carry
	// personal data: keep Body out of logs, analytics and error messages.
	Body json.RawMessage
	// Purchase is set for a checkout event of a checkout this installation
	// reserved when, after the ledger commits, the reservation holds exactly
	// this delivery's state. Another runtime has no equivalent.
	Purchase *Purchase
}

// Purchase is the locally recorded state of a reserved checkout. Separate
// deliveries can carry the same state, and a retry has no Purchase once a
// newer state has been recorded: fulfil once per CheckoutID and Status.
type Purchase struct {
	CheckoutID, OwnerID, ProductID, Status string
	// Changed orders the checkout's states: Polar's modified_at, or
	// created_at for a checkout Polar has not modified. Purchases can arrive
	// out of order: apply one only when Changed is newer than the one you
	// stored, and never move away from succeeded, expired or failed.
	Changed time.Time
}

type delivery struct{ key, hash string }

type productRef struct {
	ID string `json:"id"`
}

type checkoutSnapshot struct {
	ID       string                     `json:"id"`
	Merchant string                     `json:"organization_id"`
	Owner    string                     `json:"external_customer_id"`
	Product  string                     `json:"product_id"`
	Products []productRef               `json:"products"`
	URL      string                     `json:"url"`
	Success  string                     `json:"success_url"`
	Return   string                     `json:"return_url"`
	Status   string                     `json:"status"`
	Expires  time.Time                  `json:"expires_at"`
	Created  time.Time                  `json:"created_at"`
	Modified time.Time                  `json:"modified_at"`
	Metadata map[string]json.RawMessage `json:"metadata"`
	Attempt  string                     `json:"-"`
}

func fromSDK(cs *components.Checkout) checkoutSnapshot {
	v := checkoutSnapshot{
		ID: cs.ID, Merchant: cs.OrganizationID, Owner: val(cs.ExternalCustomerID), Product: val(cs.ProductID),
		URL: cs.URL, Success: cs.SuccessURL, Return: val(cs.ReturnURL),
		Status: string(cs.Status), Expires: cs.ExpiresAt, Created: cs.CreatedAt,
	}
	if cs.ModifiedAt != nil {
		v.Modified = *cs.ModifiedAt
	}
	v.Attempt = val(cs.Metadata[attemptMetadata].Str)
	for _, p := range cs.Products {
		v.Products = append(v.Products, productRef{ID: p.ID})
	}
	return v
}

func val(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func (s *Service) webhook(c auth.EndpointContext) (any, error) {
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, failure(400, "POLAR_INVALID_WEBHOOK", "Unreadable webhook")
	}
	h := c.Request.Header
	for _, name := range []string{"webhook-id", "webhook-timestamp", "webhook-signature"} {
		if len(h.Values(name)) != 1 {
			return nil, failure(403, "POLAR_INVALID_SIGNATURE", "Invalid delivery signature")
		}
	}
	if !requestKey.MatchString(h.Get("webhook-id")) || s.verifier.Verify(raw, h) != nil {
		return nil, failure(403, "POLAR_INVALID_SIGNATURE", "Invalid delivery signature")
	}
	var envelope struct {
		Type      string          `json:"type"`
		Version   string          `json:"api_version"`
		Timestamp json.RawMessage `json:"timestamp"`
		Data      json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Type == "" {
		return nil, failure(400, "POLAR_INVALID_WEBHOOK", "Invalid delivery")
	}
	ctx, id := c.Request.Context(), h.Get("webhook-id")
	var purchase *Purchase
	if envelope.Type == "checkout.created" || envelope.Type == "checkout.updated" || envelope.Type == "checkout.expired" {
		// The ledger commits before any host code runs, so a handler failure
		// never undoes a recorded checkout.
		if purchase, err = s.checkoutDelivery(ctx, id, envelope.Type, envelope.Version, envelope.Data, raw); err != nil {
			return nil, err
		}
	}
	received := map[string]bool{"received": true}
	if s.opts.Webhooks.OnEvent == nil {
		return received, nil
	}
	e := Event{DeliveryID: id, Type: components.WebhookEventType(envelope.Type), Body: raw, Purchase: purchase}
	if json.Unmarshal(envelope.Timestamp, &e.Timestamp) != nil {
		e.Timestamp = time.Time{}
	}
	if err := s.handle(ctx, e); err != nil {
		// The host's error text can carry payload data, so only the delivery
		// is logged, where another runtime logs the error.
		c.Auth.Logger().ErrorContext(ctx, "Polar webhook handler failed", "delivery_id", id, "type", envelope.Type)
		return nil, failure(400, "POLAR_WEBHOOK_ERROR", "Webhook error: See server logs for more information.")
	}
	return received, nil
}

// handle runs OnEvent outside any transaction, turning a panic into an
// error, as another runtime catches a throwing handler.
func (s *Service) handle(ctx context.Context, e Event) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("polar: event handler panicked")
		}
	}()
	return s.opts.Webhooks.OnEvent(ctx, e)
}

// checkoutDelivery records a checkout event against the ledger and returns
// the purchase it holds, nil for an untagged or stale checkout. A payload
// the ledger refuses answers 400 or 409 before any handler runs.
func (s *Service) checkoutDelivery(ctx context.Context, id, kind, version string, data json.RawMessage, raw []byte) (*Purchase, error) {
	if version != apiVersion {
		return nil, failure(400, "POLAR_WEBHOOK_VERSION", "Unsupported Polar checkout event version")
	}
	var v checkoutSnapshot
	if json.Unmarshal(data, &v) != nil || !canonicalID(v.ID) {
		return nil, failure(400, "POLAR_INVALID_WEBHOOK", "Invalid checkout payload")
	}
	// Only manage sessions initiated by this installation. Other merchant checkouts are legitimate.
	tag := v.Metadata[attemptMetadata]
	if len(tag) == 0 {
		return nil, nil
	}
	if json.Unmarshal(tag, &v.Attempt) != nil || !canonicalID(v.Attempt) || kind == "checkout.expired" && v.Status != "expired" {
		return nil, conflict()
	}
	key := sha256.Sum256([]byte(s.opts.OrganizationID + "\x00" + id))
	hash := sha256.Sum256(raw)
	current, err := s.apply(ctx, v, &delivery{key: hex.EncodeToString(key[:]), hash: hex.EncodeToString(hash[:])})
	if err != nil || !current {
		return nil, err
	}
	return &Purchase{CheckoutID: v.ID, OwnerID: v.Owner, ProductID: v.Products[0].ID, Status: v.Status, Changed: v.changed()}, nil
}

// changed is the ledger's ordering key for a snapshot.
func (v checkoutSnapshot) changed() time.Time {
	if v.Modified.IsZero() {
		return v.Created
	}
	return v.Modified
}

func terminal(status string) bool {
	return status == "succeeded" || status == "expired" || status == "failed"
}

func successMatches(expected, actual, id string) bool {
	// Polar may return a URI-escaped template or expand the placeholder to the checkout ID.
	expected = strings.ReplaceAll(strings.ReplaceAll(expected, "%7BCHECKOUT_ID%7D", "{CHECKOUT_ID}"), "{CHECKOUT_ID}", id)
	actual = strings.ReplaceAll(strings.ReplaceAll(actual, "%7BCHECKOUT_ID%7D", "{CHECKOUT_ID}"), "{CHECKOUT_ID}", id)
	a, e1 := url.Parse(expected)
	b, e2 := url.Parse(actual)
	return e1 == nil && e2 == nil && a.String() == b.String()
}

// apply records a checkout snapshot against its reservation and reports
// whether the committed reservation holds exactly that snapshot's state. A
// duplicate delivery is checked against the reservation as its first copy
// was, and changes nothing.
func (s *Service) apply(ctx context.Context, v checkoutSnapshot, d *delivery) (bool, error) {
	if !canonicalID(v.ID) || !canonicalID(v.Attempt) || v.Merchant != s.opts.OrganizationID || len(v.Products) != 1 || !s.hosted(v.URL) || v.Created.IsZero() || v.Expires.IsZero() ||
		v.Status != "open" && v.Status != "confirmed" && !terminal(v.Status) {
		return false, conflict()
	}
	product := v.Products[0].ID
	if v.Product != "" && v.Product != product {
		return false, conflict()
	}
	l := s.opts.Ledger
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	fresh := true
	if d != nil {
		if fresh, err = l.claimDelivery(ctx, tx, d); err != nil {
			return false, err
		}
	}
	q := "SELECT " + columns + " FROM plainauth_polar_checkout WHERE attempt=?"
	if l.dialect != "sqlite" {
		q += " FOR UPDATE"
	}
	row, err := scan(tx.QueryRowContext(ctx, l.bind(q), v.Attempt))
	if errors.Is(err, sql.ErrNoRows) {
		return false, conflict()
	}
	if err != nil {
		return false, err
	}
	if row.Owner != v.Owner || row.Merchant != v.Merchant || row.Product != product || !successMatches(row.Success, v.Success, v.ID) || row.Return != v.Return ||
		row.ID != "" && (row.ID != v.ID || row.URL != v.URL) {
		return false, conflict()
	}
	change := v.changed()
	// Once checkout ends, a delayed snapshot cannot reopen it. Notification ordering is local to the checkout.
	stale := change.UnixMicro() < row.Changed || terminal(row.Status) && row.Status != v.Status || row.Status == "confirmed" && v.Status == "open"
	if fresh && !stale {
		q = `UPDATE plainauth_polar_checkout SET checkout_id=?,hosted_url=?,status=?,expires_ms=?,changed_us=? WHERE slot=?`
		if _, err = tx.ExecContext(ctx, l.bind(q), v.ID, v.URL, v.Status, v.Expires.UnixMilli(), change.UnixMicro(), row.Slot); err != nil {
			return false, err
		}
		row.ID, row.Status, row.Changed = v.ID, v.Status, change.UnixMicro()
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return row.ID == v.ID && row.Status == v.Status && row.Changed == change.UnixMicro(), nil
}
