package organization

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

func TestInvitationHookOwnsItsPayload(t *testing.T) {
	var request auth.User
	if err := json.Unmarshal([]byte(`{"id":"u","name":"original","email":"earlier@example.test","createdAt":"2025-01-01T00:00:00Z","department":"studio"}`), &request); err != nil {
		t.Fatal(err)
	}
	team := "team"
	event := InvitationDecisionEvent{Actor: request, Invitation: Invitation{TeamID: &team}, Organization: Organization{Metadata: json.RawMessage(`{"plan":"school"}`)}}
	event.Actor.Email = "current@example.test"
	hook := decisionHook(func(_ context.Context, e InvitationDecisionEvent) error {
		if value, ok := e.Actor.AdditionalField("department"); !ok || value != "studio" || e.Actor.Email != "current@example.test" {
			t.Fatal("callback lost the public session fields or the current mailbox", value, e.Actor.Email)
		}
		*e.Invitation.TeamID = "changed"
		e.Organization.Metadata[0] = 'X'
		return nil
	}, request)
	if err := hook(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if team != "team" || !json.Valid(event.Organization.Metadata) {
		t.Fatal("callback changed the invitation or organization sent to another caller")
	}
	event.Actor.CreatedAt = event.Actor.CreatedAt.Add(-time.Hour)
	if err := hook(t.Context(), event); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("callback received session fields for a different account generation", err)
	}
}

func TestInvitationHooksRequireGuardedStore(t *testing.T) {
	type basic struct{ Store }
	if _, err := New(Options{Store: basic{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Store: basic{}, AfterRejectInvitation: func(context.Context, InvitationDecisionEvent) error { return nil }}); err == nil {
		t.Fatal("unsupported hook accepted on the host store")
	}
	if _, err := New(Options{Store: basic{}, AfterAcceptInvitation: func(context.Context, InvitationDecisionEvent) error { return nil }}); err == nil {
		t.Fatal("acceptance hook accepted on a store without guarded admission")
	}
	sender := func(context.Context, InvitationDelivery) error { return nil }
	if _, err := New(Options{Store: basic{}, SendInvitationEmail: sender}); err == nil {
		t.Fatal("mail sender registered without a delivery store")
	}
	if _, err := New(Options{Store: basic{}, SendInvitationEmail: sender, SendInvitation: func(context.Context, Invitation) error { return nil }}); err == nil {
		t.Fatal("two invitation senders registered for the same grant")
	}
}
