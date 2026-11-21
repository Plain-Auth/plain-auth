package stripe_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	authn "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlite"
	stripeplugin "github.com/nabuhadba/go-better-auth/plugins/stripe"
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
	send := func(payload []byte, signature string, wantStatus int, wantCode string) {
		t.Helper()
		r := httptest.NewRequest("POST", "http://auth.test/api/auth/stripe/webhook", bytes.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Stripe-Signature", signature)
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
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
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: key})
	send(nil, "", 400, "INVALID_REQUEST_BODY")
	send(payload, "", 400, "STRIPE_SIGNATURE_NOT_FOUND")
	send(append([]byte(" "), payload...), signed.Header, 400, "FAILED_TO_CONSTRUCT_STRIPE_EVENT")
	stale := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: key, Timestamp: time.Now().Add(-time.Hour)})
	send(payload, stale.Header, 400, "FAILED_TO_CONSTRUCT_STRIPE_EVENT")
	if callbacks != 0 {
		t.Fatal("invalid events reached application callback")
	}
	send(payload, signed.Header, 200, "")
	callbackErr = errors.New("application error")
	send(payload, signed.Header, 400, "STRIPE_WEBHOOK_ERROR")
	if callbacks != 2 {
		t.Fatalf("got %d callbacks", callbacks)
	}
}
