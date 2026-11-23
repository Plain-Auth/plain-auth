package organization_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

type handlerTransport struct{ http.Handler }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func TestMemberScopedOrganizationLifecycle(t *testing.T) {
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"organization"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(ctx, "sqlite", filepath.Join(t.TempDir(), "org.db"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var delivered []string
	var observed []string
	var deliveryError error
	plugin, err := organization.New(organization.Options{Store: store, SendInvitation: func(_ context.Context, inv organization.Invitation) error {
		delivered = append(delivered, inv.ID)
		return deliveryError
	}, AfterCreateInvitation: func(_ context.Context, event organization.InvitationDecisionEvent) error {
		observed = append(observed, event.Invitation.ID)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://org.example.test"
	limit := false
	auth, err := authn.New(authn.Options{Secret: "test-organization-0123456789-abcdefgh", Store: store, BaseURL: origin, EmailAndPassword: true, RateLimit: &limit, Plugins: []authn.Plugin{plugin}})
	if err != nil {
		t.Fatal(err)
	}
	login := func(email string) *client.Client {
		t.Helper()
		c, err := client.New(origin, &http.Client{Transport: handlerTransport{auth}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.SignUpEmail(ctx, client.SignUpRequest{Email: email, Password: "test-password-local", Name: email}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	owner := login("owner@example.test")
	member := login("member@example.test")
	outsider := login("outsider@example.test")
	admin := login("admin@example.test")
	request := func(c *client.Client, method, path string, body, out any) error {
		return c.Do(ctx, method, "/organization/"+path, body, out)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	denied := func(err error, code string) {
		t.Helper()
		var e *authn.APIError
		if !errors.As(err, &e) || e.Code != code {
			t.Fatalf("got %v, expected %s", err, code)
		}
	}
	var created struct {
		organization.Organization
		Members []organization.Member `json:"members"`
	}
	must(request(owner, "POST", "create", map[string]any{"name": "Engineering", "slug": "eng", "metadata": map[string]string{"region": "west"}}, &created))
	if len(created.Members) != 1 || created.Members[0].Role != "owner" || created.ID == "" {
		t.Fatalf("invalid owner membership: %+v", created)
	}
	var active organization.Organization
	must(request(owner, "GET", "get-organization", nil, &active))
	if active.ID != created.ID {
		t.Fatal("created organization missing as active")
	}
	session, err := owner.GetSession(ctx)
	must(err)
	if session.Session.ActiveOrganizationID == nil || *session.Session.ActiveOrganizationID != created.ID {
		t.Fatal("session omits active organization")
	}
	denied(request(owner, "POST", "create", map[string]any{"name": "Duplicate", "slug": "eng"}, nil), "ORGANIZATION_ALREADY_EXISTS")
	var orgs []organization.Organization
	must(request(outsider, "GET", "list", nil, &orgs))
	if len(orgs) != 0 {
		t.Fatal("unrelated organization was listed")
	}
	denied(request(outsider, "GET", "get-organization?organizationSlug=eng", nil, nil), "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	denied(request(outsider, "POST", "set-active", map[string]string{"organizationId": created.ID}, nil), "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	invite := func(c *client.Client, email, role string, resend bool) (organization.Invitation, error) {
		var i organization.Invitation
		err := request(c, "POST", "invite-member", map[string]any{"organizationId": created.ID, "email": email, "role": role, "resend": resend}, &i)
		return i, err
	}
	accept := func(c *client.Client, id string) error {
		_, err := c.AcceptOrganizationInvitation(ctx, id)
		return err
	}
	deliveryError = &authn.APIError{Status: 502, Code: "MAIL_PROVIDER", Message: "private mail provider diagnostics"}
	_, err = invite(owner, "member@example.test", "member", false)
	denied(err, "INTERNAL_SERVER_ERROR")
	deliveryError = nil
	i, err := invite(owner, "MEMBER@example.test", "member", true)
	must(err)
	if len(delivered) != 2 || delivered[0] != i.ID || delivered[1] != i.ID {
		t.Fatal("resend lost the original invitation")
	}
	if len(observed) != 0 {
		t.Fatal("a failed simple sender or its renewal fired the creation callback")
	}
	denied(accept(outsider, i.ID), "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")
	foreign, err := outsider.GetSession(ctx)
	must(err)
	raw := httptest.NewRequest("POST", origin+"/api/auth/organization/accept-invitation", strings.NewReader(`{"invitationId":"`+i.ID+`"}`))
	raw.Header.Set("Content-Type", "application/json")
	raw.Header.Set("Origin", origin)
	raw.AddCookie(auth.SessionCookie(foreign.Session.Token, true))
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, raw)
	var public map[string]string
	must(json.Unmarshal(w.Body.Bytes(), &public))
	if w.Code != 403 || !maps.Equal(public, map[string]string{"code": organization.ErrRecipient.Code, "message": organization.ErrRecipient.Message}) {
		t.Fatalf("foreign recipient received invitation details: %d %s", w.Code, w.Body.String())
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- accept(member, i.ID) }()
	}
	first, second := <-results, <-results
	if first != nil && second == nil {
		first, second = second, first
	}
	must(first)
	denied(second, "INVITATION_NOT_FOUND")
	must(request(member, "GET", "list", nil, &orgs))
	if len(orgs) != 1 || orgs[0].ID != created.ID {
		t.Fatal("accepted membership missing")
	}
	if _, err := invite(member, "outsider@example.test", "member", false); err == nil {
		t.Fatal("member invited another user")
	}
	adminInvite, err := invite(owner, "admin@example.test", "admin", false)
	must(err)
	if len(observed) != 1 || observed[0] != adminInvite.ID {
		t.Fatal("successful simple sender did not precede the creation callback")
	}
	joined, err := admin.AcceptOrganizationInvitation(ctx, adminInvite.ID)
	must(err)
	if joined.Member.ID == "" || joined.Member.Role != "admin" || joined.Member.OrganizationID != created.ID || joined.Invitation.ID != adminInvite.ID || joined.Invitation.Status != "accepted" {
		t.Fatal("native client lost the invitation or granted membership", joined)
	}
	_, err = invite(admin, "outsider@example.test", "owner", false)
	denied(err, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE")
	allowed, err := invite(admin, "outsider@example.test", "member", false)
	must(err)
	if allowed.ID == "" {
		t.Fatal("admin member invitation missing")
	}
	must(request(owner, "POST", "set-active", map[string]any{"organizationId": nil}, nil))
	session, err = owner.GetSession(ctx)
	must(err)
	if session.Session.ActiveOrganizationID != nil {
		t.Fatal("cleared organization still active")
	}
	must(request(owner, "POST", "set-active", map[string]string{"organizationSlug": "eng"}, &active))
	if active.ID != created.ID {
		t.Fatal("failed to select by slug")
	}
	outsideSession, err := outsider.GetSession(ctx)
	must(err)
	_, _, err = store.AcceptOrganizationInvitation(ctx, allowed.ID, outsideSession.Session.ID, outsideSession.User, time.Now(), true)
	denied(err, "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION")
	_, _, err = store.AcceptOrganizationInvitation(ctx, allowed.ID, outsideSession.Session.ID, outsideSession.User, allowed.ExpiresAt.Add(time.Minute), false)
	denied(err, "INVITATION_NOT_FOUND")
}
