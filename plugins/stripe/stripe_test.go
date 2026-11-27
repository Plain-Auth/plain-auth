package stripe_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	stripeplugin "github.com/Plain-Org/plain-auth/plugins/stripe"
	stripesdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

func TestSignedWebhookDelivery(t *testing.T) {
	const key = "whsec_local_webhook_fixture"
	payload := []byte(`{"id":"evt_local","object":"event","api_version":"2025-01-27.acacia","type":"invoice.paid","data":{"object":{"id":"in_local"}}}`)
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var callbacks int
	var callbackErr error
	opt := stripeplugin.Options{WebhookSecret: key, OnEvent: func(_ context.Context, e stripesdk.Event) error {
		callbacks++
		if e.ID != "evt_local" || e.Data == nil || string(e.Data.Raw) != `{"id":"in_local"}` {
			t.Fatalf("unexpected event: %+v", e)
		}
		return callbackErr
	}}
	auth, err := authn.New(authn.Options{Store: db, BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk", Plugins: []authn.Plugin{stripeplugin.New(opt)}})
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(target *authn.Auth, payload []byte, signature string, wantStatus int, wantCode string) {
		t.Helper()
		r := httptest.NewRequest("POST", "http://auth.test/api/auth/stripe/webhook", bytes.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Stripe-Signature", signature)
		w := httptest.NewRecorder()
		target.ServeHTTP(w, r)
		var body struct {
			Success bool
			Code    string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != wantStatus || body.Code != wantCode || body.Success != (wantStatus == 200) {
			t.Fatalf("expected %d %q, got %d %s", wantStatus, wantCode, w.Code, w.Body.String())
		}
	}
	send := func(payload []byte, signature string, wantStatus int, wantCode string) {
		t.Helper()
		deliver(auth, payload, signature, wantStatus, wantCode)
	}
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: key})
	send(nil, "", 400, "INVALID_REQUEST_BODY")
	send(payload, "", 400, "STRIPE_SIGNATURE_NOT_FOUND")
	send(append([]byte(" "), payload...), signed.Header, 400, "FAILED_TO_CONSTRUCT_STRIPE_EVENT")
	stale := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: key, Timestamp: time.Now().Add(-time.Hour)})
	send(payload, stale.Header, 400, "FAILED_TO_CONSTRUCT_STRIPE_EVENT")
	// Another secret's signature, a body over 1 MiB with or without a
	// signature, and a delivery with no secret configured never reach the
	// application.
	other := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: "whsec_other"})
	send(payload, other.Header, 400, "FAILED_TO_CONSTRUCT_STRIPE_EVENT")
	large := bytes.Repeat([]byte(" "), 1<<20+1)
	send(large, signed.Header, 413, "PAYLOAD_TOO_LARGE")
	send(large, "", 413, "PAYLOAD_TOO_LARGE")
	unsigned, err := authn.New(authn.Options{Store: db, BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk", Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{OnEvent: opt.OnEvent})}})
	if err != nil {
		t.Fatal(err)
	}
	deliver(unsigned, payload, signed.Header, 500, "STRIPE_WEBHOOK_SECRET_NOT_FOUND")
	if callbacks != 0 {
		t.Fatal("rejected deliveries reached the application callback", callbacks)
	}
	send(payload, signed.Header, 200, "")
	callbackErr = errors.New("application error")
	send(payload, signed.Header, 400, "STRIPE_WEBHOOK_ERROR")
	if callbacks != 2 {
		t.Fatalf("got %d callbacks", callbacks)
	}
}

// Subscription billing refuses to start without a webhook signing secret.
func TestWebhookSecretRequiredForSubscriptions(t *testing.T) {
	_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
		Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{Subscriptions: &stripeplugin.SubscriptionOptions{Client: stripesdk.NewClient("sk_test_local"), Plans: []stripeplugin.Plan{{Name: "pro", PriceID: "price_pro"}}}})}})
	if err == nil || !strings.Contains(err.Error(), "stripe: subscription checkout requires a webhook signing secret") {
		t.Fatal("subscriptions started without a webhook signing secret", err)
	}
}

// Subscription options without a client or plans, or with a store that
// cannot hold subscriptions, refuse to start.
func TestSubscriptionOptionsAtStartup(t *testing.T) {
	pro := []stripeplugin.Plan{{Name: "pro", PriceID: "price_pro"}}
	client := stripesdk.NewClient("sk_test_local")
	for name, tc := range map[string]struct {
		opts *stripeplugin.SubscriptionOptions
		want string
	}{
		"no client": {&stripeplugin.SubscriptionOptions{Plans: pro}, "stripe: subscriptions require a client and plans"},
		"no plans":  {&stripeplugin.SubscriptionOptions{Client: client}, "stripe: subscriptions require a client and plans"},
		"no store":  {&stripeplugin.SubscriptionOptions{Client: client, Plans: pro}, "stripe: store does not support subscriptions"},
	} {
		_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
			Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{WebhookSecret: "whsec_local", Subscriptions: tc.opts})}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Error("subscription options started", name, err)
		}
	}
}
