package sqlstore

import (
	"errors"
	"strings"
	"testing"
	"time"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func TestInvitationDeliverySnapshot(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, peer, owner, admin, group := invitationWriterFixture(t, dialect)
			inv := org.Invitation{ID: "first", Email: "guest@example.test", Role: "member", InviterID: owner.UserID, OrganizationID: group.ID, CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour), Status: "pending"}
			created, err := store.IssueInvitationForDelivery(ctx, inv, owner, false, false)
			if err != nil || created.Invitation.ID != inv.ID || created.Inviter.ID != "owner" || created.Inviter.User.ID != owner.UserID {
				t.Fatal("issue did not capture its original sender", err)
			}
			if _, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "organization" SET "name"=? WHERE "id"=?`), "Renamed", group.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "invitation" SET "email"=? WHERE "id"=?`), strings.ToUpper(inv.Email), inv.ID); err != nil {
				t.Fatal(err)
			}
			inv.ID, inv.InviterID, inv.Role = "fresh", admin.UserID, "admin"
			stale := admin
			stale.CreatedAt = stale.CreatedAt.Add(-time.Second)
			if sent, err := store.IssueInvitationForDelivery(ctx, inv, stale, true, false); sent != nil || !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("inactive issuing session produced a delivery", err)
			}
			renewed, err := store.IssueInvitationForDelivery(ctx, inv, admin, true, true)
			if err != nil || renewed.Invitation.ID != "first" || renewed.Invitation.Role != "member" || renewed.Invitation.InviterID != owner.UserID || renewed.Inviter.ID != "admin" || renewed.Inviter.User.ID != admin.UserID || renewed.Organization.Name != "Renamed" || renewed.Email != inv.Email || renewed.Invitation.Email != strings.ToUpper(inv.Email) {
				t.Fatal("resend lost the stored grant or current delivery sender", err)
			}
			replaced, err := store.IssueInvitationForDelivery(ctx, inv, admin, false, true)
			if err != nil || replaced.Invitation.ID != inv.ID || replaced.Invitation.InviterID != admin.UserID || replaced.Invitation.Role != "admin" {
				t.Fatal("replacement did not snapshot the newly issued grant", err)
			}
			var status string
			if err := peer.db.QueryRowContext(ctx, peer.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), created.Invitation.ID).Scan(&status); err != nil || status != "canceled" {
				t.Fatal("delivery returned before replacement committed", err)
			}
		})
	}
}
