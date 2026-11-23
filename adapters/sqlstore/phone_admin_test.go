package sqlstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/phonenumber"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestAdminPhoneAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"admin", "phone-number", "organization"})
			must(err)
			s, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer s.Close()
			var delivery phonenumber.Message
			send := func(_ context.Context, m phonenumber.Message) error { delivery = m; return nil }
			phone, err := phonenumber.New(phonenumber.Options{SendOTP: send, SendPasswordResetOTP: send, RequireVerification: true})
			must(err)
			org, err := organization.New(organization.Options{Store: s})
			must(err)
			admin, err := auth.NewAdmin(auth.AdminOptions{Roles: map[string]auth.AdminPermissions{"admin": {"user": {"create", "list", "get", "update", "set-phone", "set-role", "impersonate"}, "session": {"revoke"}}, "user": {}, "profile": {"user": {"create", "update"}}, "phone": {"user": {"update", "set-phone"}}}})
			must(err)
			srv := httptest.NewUnstartedServer(nil)
			off := false
			a, err := auth.New(auth.Options{BaseURL: "http://" + srv.Listener.Addr().String(), Secret: strings.Repeat("x", 40), Store: s, EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{phone, admin, org}})
			must(err)
			srv.Config.Handler = a
			srv.Start()
			defer srv.Close()
			const password = "the-admin-fixture-password"
			signup := func(name, role string) (*client.Client, *auth.User) {
				t.Helper()
				c, err := client.New(srv.URL, nil)
				must(err)
				registration, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: password})
				must(err)
				if role != "user" {
					_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "role"=? WHERE "id"=?`), role, registration.User.ID)
					must(err)
				}
				return c, &registration.User
			}
			operator, root := signup("central", "admin")
			second, _ := signup("backup", "admin")
			editor, _ := signup("editor", "profile")
			delegated, agent := signup("helpdesk", "phone")
			tenant, _ := signup("tenant", "user")
			must(tenant.Do(ctx, http.MethodPost, "/organization/create", map[string]any{"name": "East", "slug": "east"}, nil))
			member, one := signup("one", "user")
			must(member.Do(ctx, http.MethodPost, "/organization/create", map[string]any{"name": "West", "slug": "west"}, nil))
			_, two := signup("two", "user")
			const n = "+12025550026"
			const newNumber = "+12025550027"
			const deny = "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PHONE_NUMBER"
			for _, f := range []map[string]any{{"phoneNumber": n}, {"phoneNumberVerified": true}} {
				_, err = editor.AdminUpdateUser(ctx, one.ID, f)
				phoneError(t, err, 403, deny)
			}
			_, err = editor.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Rejected", Email: "uncreated@example.test", Data: map[string]any{"phoneNumber": n, "phoneNumberVerified": true}})
			phoneError(t, err, 403, deny)
			_, err = tenant.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": n})
			phoneError(t, err, 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS")
			_, err = delegated.AdminUpdateUser(ctx, root.ID, map[string]any{"phoneNumber": n, "phoneNumberVerified": true})
			phoneError(t, err, 403, deny)
			updated, err := delegated.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": n})
			must(err)
			if updated.PhoneNumberFields == nil || *updated.PhoneNumber != n || updated.PhoneNumberVerified != nil {
				t.Fatal("initial assignment gained verification")
			}
			updated, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumberVerified": true})
			must(err)
			if !*updated.PhoneNumberVerified {
				t.Fatal("authorized verification flag missing")
			}
			read, err := operator.AdminGetUser(ctx, one.ID)
			must(err)
			if *read.PhoneNumber != n || !*read.PhoneNumberVerified {
				t.Fatal("admin user projection inconsistent")
			}
			page, err := operator.AdminListUsers(ctx, auth.AdminQuery{SearchField: "email", SearchOperator: "eq", SearchValue: one.Email})
			must(err)
			if len(page.Users) != 1 || *page.Users[0].PhoneNumber != n {
				t.Fatal("admin list phone fields missing")
			}
			must(a.SendPhoneNumberOTP(ctx, n))
			oldCheck := delivery.Code
			must(a.RequestPhonePasswordReset(ctx, n))
			oldReset := delivery.Code
			must(a.SendPhoneNumberOTP(ctx, newNumber))
			preclaim := delivery.Code
			updated, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": newNumber})
			must(err)
			if updated.PhoneNumberVerified == nil || *updated.PhoneNumberVerified {
				t.Fatal("replacement inherited the prior number's verification")
			}
			phoneError(t, a.ConsumePhoneNumberOTP(ctx, n, oldCheck), 400, "OTP_NOT_FOUND")
			phoneError(t, a.ConsumePhoneNumberOTP(ctx, newNumber, preclaim), 400, "OTP_NOT_FOUND")
			phoneError(t, a.ResetPhonePassword(ctx, n, oldReset, password), 400, "OTP_NOT_FOUND")
			_, err = delegated.AdminUpdateUser(ctx, two.ID, map[string]any{"name": "Partial", "phoneNumber": newNumber})
			phoneError(t, err, 400, "PHONE_NUMBER_EXIST")
			read, err = operator.AdminGetUser(ctx, two.ID)
			must(err)
			if read.Name == "Partial" || read.PhoneNumber != nil {
				t.Fatal("conflicting assignment committed unrelated changes")
			}
			updated, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": nil, "phoneNumberVerified": true})
			must(err)
			if updated.PhoneNumber != nil || updated.PhoneNumberVerified == nil || *updated.PhoneNumberVerified {
				t.Fatal("clear retained verification")
			}
			_, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumberVerified": true})
			if err == nil {
				t.Fatal("verified an absent number")
			}
			// Databases written by another runtime can contain a verified flag without a number.
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "phoneNumberVerified"=? WHERE "id"=?`), true, one.ID)
			must(err)
			corrected, err := operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": newNumber})
			must(err)
			if corrected.PhoneNumberVerified == nil || *corrected.PhoneNumberVerified {
				t.Fatal("an imported orphan flag verified a newly assigned number")
			}
			_, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": nil})
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "phoneNumber"=? WHERE "id"=?`), "", one.ID)
			must(err)
			_, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumberVerified": true})
			if err == nil {
				t.Fatal("an imported empty number gained verified status")
			}
			_, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": nil})
			must(err)
			// Two independent actors updating different target rows still contend on the same unique number.
			start := make(chan struct{})
			result := make(chan error, 2)
			assign := func(c *client.Client, id string) {
				<-start
				_, err := c.AdminUpdateUser(ctx, id, map[string]any{"phoneNumber": n})
				result <- err
			}
			go assign(operator, one.ID)
			go assign(second, two.ID)
			close(start)
			wins := 0
			for range 2 {
				if e := <-result; e == nil {
					wins++
				} else {
					phoneError(t, e, 400, "PHONE_NUMBER_EXIST")
				}
			}
			if wins != 1 {
				t.Fatal("concurrent phone assignment did not produce one owner")
			}
			// Direct sessions that have been demoted or revoked cannot retain a previous administrative grant.
			_, err = operator.AdminSetRole(ctx, agent.ID, "profile")
			must(err)
			_, err = delegated.AdminUpdateUser(ctx, two.ID, map[string]any{"phoneNumber": nil})
			phoneError(t, err, 403, deny)
			must(operator.AdminRevokeUserSessions(ctx, agent.ID))
			_, err = delegated.AdminUpdateUser(ctx, two.ID, map[string]any{"phoneNumber": nil})
			phoneError(t, err, 401, "UNAUTHORIZED")
			_, err = operator.AdminImpersonate(ctx, two.ID)
			must(err)
			_, err = operator.AdminUpdateUser(ctx, one.ID, map[string]any{"phoneNumber": nil})
			phoneError(t, err, 403, "FORBIDDEN")
			_, err = operator.AdminStopImpersonating(ctx)
			must(err)
			dropped, err := operator.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Created", Email: "created@example.test", Data: map[string]any{"phoneNumber": "+12025550088"}})
			must(err)
			if dropped.PhoneNumber != nil || dropped.PhoneNumberVerified == nil || *dropped.PhoneNumberVerified {
				t.Fatal("admin creation claimed an unproven number")
			}
			seeded, err := operator.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Verified", Email: "verified@example.test", Data: map[string]any{"phoneNumber": "+12025550089", "phoneNumberVerified": true}})
			must(err)
			if seeded.PhoneNumber == nil || !*seeded.PhoneNumberVerified {
				t.Fatal("verified administrative creation failed")
			}
		})
	}
}
