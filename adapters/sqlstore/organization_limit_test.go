package sqlstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationAdmissionPolicy(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization-teams", "sso"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			now := time.Now().UTC().Truncate(time.Millisecond)
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n))
				return n
			}
			users := map[string]auth.User{}
			for _, id := range []string{"Host", "Pending", "Direct", "Other"} {
				u := auth.User{ID: id, Name: id, Email: strings.ToLower(id) + "@example.test", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
				users[id] = u
				must(store.CreateUser(ctx, u, "", &auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
			}
			group := org.Organization{ID: "tenant", Name: "Studio", Slug: "studio", CreatedAt: now, Metadata: []byte(`{"plan":"basic"}`)}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "host-membership", UserID: "Host", OrganizationID: group.ID, Role: "owner", CreatedAt: now}, "Host-s", false))
			inv, err := store.InviteOrganizationMember(ctx, org.Invitation{ID: "first", OrganizationID: group.ID, InviterID: "Host", Email: users["Pending"].Email, Role: "member", Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, "Host-s", false)
			must(err)
			for _, policy := range []org.MembershipLimit{
				{Maximum: -1},
				{Maximum: 1, Resolve: func(context.Context, auth.User, org.Organization) (int, error) { return 2, nil }},
			} {
				if _, err := org.NewService(org.Options{Store: store, MembershipLimit: policy}); err == nil {
					t.Fatal("accepted invalid membership limit")
				}
			}
			var calls int
			var evaluate func(auth.User, org.Organization) (int, error)
			service, err := org.NewService(org.Options{Store: store, Teams: &org.TeamOptions{}, MembershipLimit: org.MembershipLimit{Resolve: func(ctx context.Context, u auth.User, g org.Organization) (int, error) {
				calls++
				// The callback can use even SQLite's single connection.
				var seats int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=?`), g.ID).Scan(&seats); err != nil {
					return 0, err
				}
				if seats < 1 || u.Name != u.ID || !u.EmailVerified || u.Email != strings.ToLower(u.ID)+"@example.test" || g.Name != "Studio" || g.ID != group.ID || u.CreatedAt.IsZero() || len(g.Metadata) == 0 {
					t.Errorf("incomplete membership resolver input %+v %+v", u, g)
				}
				g.Metadata[0] = 'X'
				return evaluate(u, g)
			}}})
			must(err)
			configured := service.Store()
			accept := func() error {
				_, _, err := configured.AcceptOrganizationInvitation(ctx, inv.ID, "Pending-s", users["Pending"], now, true)
				return err
			}
			pending := func() {
				t.Helper()
				if count(`SELECT COUNT(*) FROM "invitation" WHERE "id"='first' AND "status"='pending'`) != 1 || count(`SELECT COUNT(*) FROM "member" WHERE "userId"='Pending'`) != 0 || count(`SELECT COUNT(*) FROM "session" WHERE "id"='Pending-s' AND "activeOrganizationId" IS NOT NULL`) != 0 {
					t.Fatal("unsuccessful admission changed invitation, membership or session")
				}
			}
			if _, _, err := configured.AcceptOrganizationInvitation(ctx, inv.ID, "pending-s", users["Pending"], now, true); !errors.Is(err, org.ErrUnauthenticated) || calls != 0 {
				t.Fatal("incorrect session reached the admission policy", err)
			}
			failed := errors.New("billing lookup unavailable")
			evaluate = func(u auth.User, _ org.Organization) (int, error) {
				if u.ID != "Pending" {
					t.Errorf("resolver received inviter")
				}
				return 0, failed
			}
			if err := accept(); !errors.Is(err, failed) {
				t.Fatal("lost resolver error", err)
			}
			pending()
			evaluate = func(auth.User, org.Organization) (int, error) { return 0, nil }
			if err := accept(); !errors.Is(err, org.ErrMemberLimit) {
				t.Fatal("zero resolver limit admitted candidate", err)
			}
			pending()
			evaluate = func(auth.User, org.Organization) (int, error) {
				exec(`UPDATE "organization" SET "metadata"=? WHERE "id"=?`, `{"plan":"changed"}`, group.ID)
				return 5, nil
			}
			if err := accept(); !errors.Is(err, org.ErrMembershipPolicyChanged) {
				t.Fatal("accepted a decision for stale organization data", err)
			}
			pending()
			evaluate = func(auth.User, org.Organization) (int, error) {
				exec(`UPDATE "user" SET "name"='Renamed' WHERE "id"='Pending'`)
				return 5, nil
			}
			if err := accept(); !errors.Is(err, org.ErrMembershipPolicyChanged) {
				t.Fatal("accepted a decision for stale candidate data", err)
			}
			pending()
			exec(`UPDATE "user" SET "name"='Pending' WHERE "id"='Pending'`)
			evaluate = func(auth.User, org.Organization) (int, error) {
				exec(`UPDATE "invitation" SET "expiresAt"=? WHERE "id"='first'`, store.date(now.Add(-time.Second)))
				return 5, nil
			}
			if err := accept(); !errors.Is(err, org.ErrInvitation) {
				t.Fatal("consumed invitation after expiry", err)
			}
			pending()
			exec(`UPDATE "invitation" SET "expiresAt"=? WHERE "id"='first'`, store.date(inv.ExpiresAt))
			if calls != 5 {
				t.Fatalf("resolver called %d times for five attempts", calls)
			}
			evaluate = func(auth.User, org.Organization) (int, error) { return 2, nil }
			must(accept())
			if calls != 6 || count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"='tenant'`) != 2 {
				t.Fatal("retry did not use exactly one fresh decision")
			}
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: group.ID, UserID: "Direct", Roles: []string{"member"}})
			if !errors.Is(err, org.ErrMemberLimit) {
				t.Fatal("direct grant ignored capacity", err)
			}
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: group.ID, UserID: "Pending", Roles: []string{"member"}})
			if !errors.Is(err, org.ErrAlreadyMember) || calls != 7 {
				t.Fatal("duplicate grant invoked the resolver", err, calls)
			}
			if _, err := service.AddMember(ctx, org.AddMemberRequest{OrganizationID: group.ID, UserID: "Other", TeamID: "unknown", Roles: []string{"member"}}); !errors.Is(err, org.ErrTeamNotFound) || calls != 7 {
				t.Fatal("ineligible team reached resolver", err)
			}
			// Both contenders finish their host policy checks before either can take the last seat.
			arrived := make(chan struct{}, 2)
			release := make(chan struct{})
			policy := org.MembershipLimit{Resolve: func(context.Context, auth.User, org.Organization) (int, error) {
				arrived <- struct{}{}
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				case <-release:
					return 3, nil
				}
			}}
			a, err := store.WithMembershipLimit(policy)
			must(err)
			b, err := peer.WithMembershipLimit(policy)
			must(err)
			last, err := a.InviteOrganizationMember(ctx, org.Invitation{ID: "last", OrganizationID: group.ID, InviterID: "Host", Email: users["Other"].Email, Role: "member", Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, "Host-s", false)
			must(err)
			results := make(chan error, 2)
			go func() {
				results <- a.AddOrganizationMember(ctx, org.Member{ID: "direct", OrganizationID: group.ID, UserID: "Direct", Role: "member", CreatedAt: now}, "")
			}()
			go func() {
				_, _, e := b.AcceptOrganizationInvitation(ctx, last.ID, "Other-s", users["Other"], now, true)
				results <- e
			}()
			for range 2 {
				select {
				case <-arrived:
				case <-ctx.Done():
					t.Fatal("admission callback retained database locks")
				}
			}
			close(release)
			first, second := <-results, <-results
			if first != nil {
				first, second = second, first
			}
			if first != nil || !errors.Is(second, org.ErrMemberLimit) || count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"='tenant'`) != 3 {
				t.Fatal("competing admissions failed to serialize at the configured limit", first, second)
			}
			// An enterprise login has an uncommitted account and session during its first policy pass.
			exec(`INSERT INTO "ssoProvider" ("id","providerId","userId","organizationId","issuer","domain","oidcConfig") VALUES ('corp-provider','corp','Host','tenant','https://idp.example','example.test',?)`, `{"clientId":"app","clientSecret":"test","issuer":"https://idp.example"}`)
			provider, err := store.FindBrowserProvider(ctx, sso.Selector{ProviderID: "corp"})
			must(err)
			var allow bool
			var enterpriseCalls int
			enterprise, err := store.WithMembershipLimit(org.MembershipLimit{Resolve: func(_ context.Context, u auth.User, g org.Organization) (int, error) {
				enterpriseCalls++
				if u.ID != "Federated" || g.ID != group.ID || count(`SELECT COUNT(*) FROM "user" WHERE "id"='Federated'`) != 0 {
					t.Error("provisional account visible during enterprise policy")
				}
				if allow {
					return 4, nil
				}
				return 0, nil
			}})
			must(err)
			candidate := auth.User{ID: "Federated", Email: "federated@example.test", Name: "Federated", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
			login := func(sid string) error {
				session := auth.StoredSession{Session: auth.Session{ID: sid, Token: sid + "-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				_, _, err := enterprise.CompleteEnterpriseLogin(ctx, provider.Reference, "member", "corp", "remote-subject", auth.OAuthTokens{}, candidate, session, auth.OAuthLoginOptions{})
				return err
			}
			if err := login("enterprise-one"); !errors.Is(err, org.ErrMemberLimit) {
				t.Fatal("enterprise cap was not applied", err)
			}
			if count(`SELECT COUNT(*) FROM "user" WHERE "id"='Federated'`)+count(`SELECT COUNT(*) FROM "session" WHERE "id"='enterprise-one'`)+count(`SELECT COUNT(*) FROM "account" WHERE "userId"='Federated'`) != 0 {
				t.Fatal("declined enterprise provisioning left an identity or session")
			}
			allow = true
			must(login("enterprise-two"))
			must(login("enterprise-three"))
			if enterpriseCalls != 2 || count(`SELECT COUNT(*) FROM "member" WHERE "userId"='Federated'`) != 1 {
				t.Fatal("returning enterprise member consumed another seat")
			}
			// Receipt consumption and seat allocation share the same commit.
			const identityProvider = "https://saml.example/idp"
			exec(`INSERT INTO "ssoProvider" ("id","providerId","userId","organizationId","issuer","domain","samlConfig") VALUES ('saml-record','saml-corp','Host','tenant','https://saml.example/sp','example.test',?)`, `{"entryPoint":"https://saml.example/login","idpMetadata":{"entityID":"https://saml.example/idp"}}`)
			directory, err := store.FindBrowserProvider(ctx, sso.Selector{ProviderID: "saml-corp"})
			must(err)
			seats := 4
			samlStore, err := store.WithMembershipLimit(org.MembershipLimit{Resolve: func(context.Context, auth.User, org.Organization) (int, error) { return seats, nil }})
			must(err)
			samlLogin := func(sid string) error {
				account := auth.User{ID: "directory-user", Name: "Staff", Email: "staff@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: sid, Token: sid, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				_, _, err := samlStore.CompleteSAMLLogin(ctx, directory.Reference, "member", false, directory.ProviderID, "staff", sso.AssertionReceipt{Issuer: identityProvider, ID: "seat-claim"}, account, session, auth.OAuthLoginOptions{})
				return err
			}
			if err := samlLogin("at-capacity"); !errors.Is(err, org.ErrMemberLimit) || count(`SELECT COUNT(*) FROM "user" WHERE "id"='directory-user'`) != 0 {
				t.Fatal("failed SAML admission left an account", err)
			}
			seats++
			must(samlLogin("saml-accepted"))
			if err := samlLogin("saml-again"); !errors.Is(err, sso.ErrAssertionUsed) || count(`SELECT COUNT(*) FROM "session" WHERE "userId"='directory-user'`) != 1 {
				t.Fatal("SAML receipt consumption did not match the successful seat allocation", err)
			}

		})
	}
}
