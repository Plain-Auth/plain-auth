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

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/polarsource/polar-go/models/components"
)

// Event contains only the verified, locally bound checkout fields made available to a host callback.
type Event struct{ DeliveryID, Type, CheckoutID, OwnerID, ProductID, Status string }

type delivery struct{ id, kind, key, hash string }

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
		Type    string          `json:"type"`
		Version string          `json:"api_version"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Type == "" {
		return nil, failure(400, "POLAR_INVALID_WEBHOOK", "Invalid delivery")
	}
	received := map[string]bool{"received": true}
	if envelope.Type != "checkout.created" && envelope.Type != "checkout.updated" && envelope.Type != "checkout.expired" {
		return received, nil
	}
	if envelope.Version != apiVersion {
		return nil, failure(400, "POLAR_WEBHOOK_VERSION", "Unsupported Polar checkout event version")
	}
	var v checkoutSnapshot
	if json.Unmarshal(envelope.Data, &v) != nil || !canonicalID(v.ID) {
		return nil, failure(400, "POLAR_INVALID_WEBHOOK", "Invalid checkout payload")
	}
	// Only manage sessions initiated by this installation. Other merchant checkouts are legitimate.
	tag := v.Metadata[attemptMetadata]
	if len(tag) == 0 {
		return received, nil
	}
	if json.Unmarshal(tag, &v.Attempt) != nil || !canonicalID(v.Attempt) || envelope.Type == "checkout.expired" && v.Status != "expired" {
		return nil, conflict()
	}
	id := h.Get("webhook-id")
	key := sha256.Sum256([]byte(s.opts.OrganizationID + "\x00" + id))
	hash := sha256.Sum256(raw)
	err = s.apply(c.Request.Context(), v, &delivery{id: id, kind: envelope.Type, key: hex.EncodeToString(key[:]), hash: hex.EncodeToString(hash[:])})
	return received, err
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

func (s *Service) apply(ctx context.Context, v checkoutSnapshot, d *delivery) error {
	if !canonicalID(v.ID) || !canonicalID(v.Attempt) || v.Merchant != s.opts.OrganizationID || len(v.Products) != 1 || !s.hosted(v.URL) || v.Created.IsZero() || v.Expires.IsZero() ||
		v.Status != "open" && v.Status != "confirmed" && !terminal(v.Status) {
		return conflict()
	}
	product := v.Products[0].ID
	if v.Product != "" && v.Product != product {
		return conflict()
	}
	l := s.opts.Ledger
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if d != nil {
		fresh, err := l.claimDelivery(ctx, tx, d)
		if err != nil {
			return err
		}
		if !fresh {
			return tx.Commit()
		}
	}
	q := "SELECT " + columns + " FROM plainauth_polar_checkout WHERE attempt=?"
	if l.dialect != "sqlite" {
		q += " FOR UPDATE"
	}
	row, err := scan(tx.QueryRowContext(ctx, l.bind(q), v.Attempt))
	if errors.Is(err, sql.ErrNoRows) {
		return conflict()
	}
	if err != nil {
		return err
	}
	if row.Owner != v.Owner || row.Merchant != v.Merchant || row.Product != product || !successMatches(row.Success, v.Success, v.ID) || row.Return != v.Return ||
		row.ID != "" && (row.ID != v.ID || row.URL != v.URL) {
		return conflict()
	}
	change := v.Modified
	if change.IsZero() {
		change = v.Created
	}
	// Once checkout ends, a delayed snapshot cannot reopen it. Notification ordering is local to the checkout.
	stale := change.UnixMicro() < row.Changed || terminal(row.Status) && row.Status != v.Status || row.Status == "confirmed" && v.Status == "open"
	if !stale {
		q = `UPDATE plainauth_polar_checkout SET checkout_id=?,hosted_url=?,status=?,expires_ms=?,changed_us=? WHERE slot=?`
		if _, err = tx.ExecContext(ctx, l.bind(q), v.ID, v.URL, v.Status, v.Expires.UnixMilli(), change.UnixMicro(), row.Slot); err != nil {
			return err
		}
		if d != nil && s.opts.OnCheckout != nil {
			err = s.opts.OnCheckout(ctx, tx, Event{DeliveryID: d.id, Type: d.kind, CheckoutID: v.ID, OwnerID: row.Owner, ProductID: product, Status: v.Status})
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
