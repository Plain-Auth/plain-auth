package sqlstore

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// With BackgroundTasks an invitation email is sent after the response and
// the AfterCreateInvitation hook, with a request copy that outlives the
// request.
func TestOrganizationInvitationInBackground(t *testing.T) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ddl, err := schema.Generate("sqlite", []string{"organization"})
	must(err)
	db, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
	must(err)
	defer db.Close()
	var mu sync.Mutex
	var events []string
	record := func(event string) { mu.Lock(); events = append(events, event); mu.Unlock() }
	var queue []func()
	organization, err := org.New(org.Options{Store: db,
		AfterCreateInvitation: func(context.Context, org.InvitationDecisionEvent) error {
			record("after-create")
			return nil
		},
		SendInvitationEmail: func(ctx context.Context, message org.InvitationDelivery) error {
			state := "live"
			if ctx.Err() != nil || message.Request == nil || message.Request.Context().Err() != nil {
				state = "cancelled"
			}
			record("sent:" + state + ":" + message.Email)
			return nil
		}})
	must(err)
	host, err := plainauth.New(plainauth.Options{Store: db, EmailAndPassword: true, Secret: strings.Repeat("k", 32), BaseURL: "https://orgs.example",
		RateLimit: new(bool), Plugins: []plainauth.Plugin{organization}, BackgroundTasks: func(task func()) { queue = append(queue, task) }})
	must(err)
	owner, err := client.New("https://orgs.example", &http.Client{Transport: guestTransport{host}})
	must(err)
	_, err = owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@example.test", Password: "an organization test password"})
	must(err)
	var group org.Organization
	must(owner.Do(ctx, "POST", "/organization/create", map[string]any{"name": "Engineering", "slug": "engineering"}, &group))
	var invitation org.Invitation
	must(owner.Do(ctx, "POST", "/organization/invite-member", map[string]any{"email": "Invitee@Example.test", "role": "member", "organizationId": group.ID}, &invitation))
	mu.Lock()
	before := strings.Join(events, ",")
	mu.Unlock()
	if before != "after-create" || len(queue) != 1 {
		t.Fatalf("before the queue ran: %q with %d tasks", before, len(queue))
	}
	queue[0]()
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(events, ","); got != "after-create,sent:live:invitee@example.test" {
		t.Fatalf("after the queue ran: %q", got)
	}
}
