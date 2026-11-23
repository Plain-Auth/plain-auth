package sqlstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/authtest"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationProfileHookBoundary(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization", "admin"})
			must(err)
			one, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer one.Close()
			two, err := Open(ctx, dialect, dsn)
			must(err)
			defer two.Close()
			app, err := authtest.New(auth.Options{Store: one, BaseURL: "https://org.example.test", Secret: strings.Repeat("e", 40)})
			must(err)
			for _, mode := range []string{"merge", "explicit-switch", "implicit-switch", "replace-membership", "demote", "replace-organization", "replace-session", "revoke", "expire", "delegate", "ban", "slug-race", "before-failure", "after-failure", "initial-slug", "invalid-override"} {
				t.Run(mode, func(t *testing.T) {
					must := func(err error) {
						t.Helper()
						if err != nil {
							t.Fatal(err)
						}
					}
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					user, err := app.SaveUser(ctx, authtest.NewUser())
					must(err)
					session, err := app.Login(ctx, user.ID)
					must(err)
					group := authtest.NewOrganization("Original")
					member := org.Member{ID: group.ID, OrganizationID: group.ID, UserID: user.ID, Role: "owner", CreatedAt: user.CreatedAt}
					must(one.CreateOrganization(ctx, group, member, session.Session.ID, false))
					peerGroup := authtest.NewOrganization("Second")
					peerMember := org.Member{ID: peerGroup.ID, OrganizationID: peerGroup.ID, UserID: user.ID, Role: "owner", CreatedAt: user.CreatedAt}
					must(one.CreateOrganization(ctx, peerGroup, peerMember, session.Session.ID, true))
					requestID := group.ID
					if mode == "implicit-switch" {
						requestID = ""
					}
					changeName, slug := "proposed", "n-"+group.ID
					if mode == "initial-slug" {
						slug = peerGroup.Slug
					}
					change := org.ProfileUpdate{Name: &changeName, Slug: &slug, Metadata: map[string]any{"n": 1}}
					write := func(q string, args ...any) {
						t.Helper()
						_, err := two.db.ExecContext(ctx, two.bind(q), args...)
						must(err)
					}
					beforeCalls, afterCalls := 0, 0
					hookError := errors.New("observer rejection")
					service, err := org.NewService(org.Options{Store: one,
						BeforeUpdateOrganization: func(_ context.Context, event org.BeforeProfileUpdate) (*org.ProfileUpdate, error) {
							beforeCalls++
							if event.Organization.Name == nil || *event.Organization.Name != "proposed" || event.Organization.Logo != nil || event.Organization.ClearLogo || event.Member.ID != member.ID || event.User.ID != user.ID || event.User.Email != user.Email {
								t.Fatal("before received different input or actor")
							}
							switch mode {
							case "merge":
								// A second transaction can take the same lock while the host runs.
								logo := "/parallel"
								_, err := two.UpdateOrganizationProfile(ctx, user.ID, session.Token, group.ID, org.ProfileUpdate{Logo: &logo})
								must(err)
								event.Organization.Metadata["n"] = "ignored"
								override := "from hook"
								return &org.ProfileUpdate{Name: &override}, nil
							case "explicit-switch", "implicit-switch":
								must(two.SetActiveOrganization(ctx, session.Session.ID, user.ID, &peerGroup.ID))
							case "replace-membership":
								write(`UPDATE "member" SET "id"=? WHERE "id"=?`, "new-"+member.ID, member.ID)
							case "demote":
								write(`UPDATE "member" SET "role"=? WHERE "id"=?`, "member", member.ID)
							case "replace-organization":
								write(`UPDATE "organization" SET "createdAt"=? WHERE "id"=?`, two.date(group.CreatedAt.Add(time.Hour)), group.ID)
							case "replace-session":
								write(`UPDATE "session" SET "createdAt"=? WHERE "id"=?`, two.date(session.Session.CreatedAt.Add(-time.Hour)), session.Session.ID)
							case "revoke":
								must(two.DeleteSession(ctx, session.Token))
							case "expire":
								write(`UPDATE "session" SET "expiresAt"=? WHERE "id"=?`, two.date(time.Now().Add(-time.Minute)), session.Session.ID)
							case "delegate":
								write(`UPDATE "session" SET "impersonatedBy"=? WHERE "id"=?`, "operator", session.Session.ID)
							case "ban":
								write(`UPDATE "user" SET "banned"=? WHERE "id"=?`, true, user.ID)
							case "slug-race":
								_, err := two.UpdateOrganizationProfile(ctx, user.ID, session.Token, peerGroup.ID, org.ProfileUpdate{Slug: &slug})
								must(err)
							case "before-failure":
								return nil, hookError
							case "invalid-override":
								empty := ""
								return &org.ProfileUpdate{Slug: &empty}, nil
							}
							return nil, nil
						},
						AfterUpdateOrganization: func(_ context.Context, event org.AfterProfileUpdate) error {
							afterCalls++
							if event.Organization == nil || event.Organization.ID != group.ID || event.User.ID != user.ID || event.Member.ID != member.ID {
								t.Fatal("after received different actor or tenant")
							}
							var name string
							must(two.db.QueryRowContext(ctx, two.bind(`SELECT "name" FROM "organization" WHERE "id"=?`), group.ID).Scan(&name))
							if name != event.Organization.Name {
								t.Fatal("after callback could not read committed row")
							}
							event.Organization.Name = "ignored"
							if mode == "after-failure" {
								return hookError
							}
							return nil
						},
					})
					must(err)
					got, err := service.UpdateOrganization(ctx, session.Session, requestID, change)
					var actual, peer string
					must(two.db.QueryRowContext(ctx, two.bind(`SELECT "name" FROM "organization" WHERE "id"=?`), group.ID).Scan(&actual))
					must(two.db.QueryRowContext(ctx, two.bind(`SELECT "name" FROM "organization" WHERE "id"=?`), peerGroup.ID).Scan(&peer))
					if peer != peerGroup.Name {
						t.Fatal("callback retargeted the active tenant")
					}
					switch mode {
					case "merge":
						if err != nil || got.Name != "from hook" || got.Logo == nil || *got.Logo != "/parallel" || !strings.Contains(string(got.Metadata), `"n":1`) && !strings.Contains(string(got.Metadata), `"n": 1`) || actual != got.Name || got.Slug != slug {
							t.Fatal("selective merge lost committed data", got, err)
						}
					case "explicit-switch":
						if err != nil || got.Name != changeName || actual != changeName {
							t.Fatal("explicit target changed", got, err)
						}
					case "after-failure":
						if !errors.Is(err, hookError) || actual != changeName {
							t.Fatal("after error rolled back committed change", err)
						}
					default:
						if err == nil || actual != group.Name {
							t.Fatal("invalidated profile committed", mode, actual, err)
						}
					}
					wantBefore, wantAfter := 1, 0
					if mode == "initial-slug" {
						wantBefore = 0
					}
					if mode == "merge" || mode == "explicit-switch" || mode == "after-failure" {
						wantAfter = 1
					}
					if beforeCalls != wantBefore || afterCalls != wantAfter {
						t.Fatal("callback count", beforeCalls, afterCalls)
					}
				})
			}
		})
	}
}

func TestOrganizationProfileHooksRequireGuardedStore(t *testing.T) {
	type legacy struct {
		org.Store
		org.ProfileStore
	}
	plain := org.Options{Store: legacy{}}
	if _, err := org.NewService(plain); err != nil {
		t.Fatal(err)
	}
	plain.AfterUpdateOrganization = func(context.Context, org.AfterProfileUpdate) error { return nil }
	if _, err := org.NewService(plain); err == nil {
		t.Fatal("unguarded custom store accepted host callbacks")
	}
}
