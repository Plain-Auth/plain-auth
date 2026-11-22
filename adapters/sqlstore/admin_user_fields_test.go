package sqlstore

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/admin"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestAdminCreateProfileFields(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			fields["internalLabel"] = auth.UserField{Type: auth.FieldString, ServerOnly: true, Hidden: true}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithAdditionalFields(ctx, dialect, dsn, []string{"admin"}, schema.AdditionalFields{User: fields})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			p, err := admin.New(admin.Options{Roles: map[string]auth.AdminPermissions{
				"user": {}, "creator": {"user": {"create"}}, "admin": {"user": {"create", "get", "list", "set-role", "set-email", "ban"}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://profiles.example.test"
			off := false
			host, err := auth.New(auth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("a", 40), EmailAndPassword: true, RateLimit: &off, UserAdditionalFields: fields, Plugins: []auth.Plugin{p}})
			if err != nil {
				t.Fatal(err)
			}
			makeClient := func() *client.Client {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			expectCode := func(err error, code string) {
				t.Helper()
				var api *auth.APIError
				if !errors.As(err, &api) || api.Code != code {
					t.Fatalf("got %v, want %s", err, code)
				}
			}
			absent := func(email string) {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "user" WHERE "email"=?`), email).Scan(&n); err != nil || n != 0 {
					t.Fatalf("rejected create left a row for %s: %v", email, err)
				}
			}
			const password = "local-admin-profile-credential"
			input := auth.AdminCreateUserRequest{Name: "Operator", Email: "operator@example.test", Password: password, Role: []string{"admin"}, Data: map[string]any{
				"name": "overridden", "email": "another@example.test", "role": "user", "locale": "host-locale", "score": 0, "activeFlag": false, "accountClass": "server-created", "secretNote": "private", "privateRank": 34,
			}}
			operator, err := host.AdminCreateUser(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if operator.Role != "admin" || operator.Name != "Operator" || operator.Email != input.Email {
				t.Fatal("host lost protected input precedence")
			}
			checkUserField(t, *operator, "accountClass", "server-created")
			checkUserField(t, *operator, "score", int64(0))
			checkUserField(t, *operator, "activeFlag", false)
			for _, k := range []string{"preferred_locale", "secretNote", "privateRank"} {
				if _, ok := operator.AdditionalField(k); ok {
					t.Fatal("host API exposed protected output", k)
				}
			}
			var note string
			var rank int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "secretNote","privateRank" FROM "user" WHERE "id"=?`), operator.ID).Scan(&note, &rank); err != nil || note != "private" || rank != 34 {
				t.Fatal("host fields did not commit with the account", err)
			}
			manager := makeClient()
			login, err := manager.SignInEmail(ctx, client.SignInRequest{Email: input.Email, Password: password})
			if err != nil {
				t.Fatal(err)
			}
			cookie := host.SessionCookie(*login.Token, true)
			actor := http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
			signed := auth.AdminRequest{Operation: "create-user", Name: "Creator", Email: "creator@example.test", Password: password, Data: map[string]any{"role": []string{"creator"}, "locale": "managed", "accountClass": "cannot-overwrite"}}
			if _, err = host.Admin(ctx, nil, signed); err == nil {
				t.Fatal("ambient request used host privileges")
			}
			created, err := host.Admin(ctx, actor, signed)
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, *created.User, "accountClass", "basic")
			creator := makeClient()
			if _, err := creator.SignInEmail(ctx, client.SignInRequest{Email: signed.Email, Password: password}); err != nil {
				t.Fatal(err)
			}
			browser := auth.AdminCreateUserRequest{Name: "Target", Email: "target@example.test", Data: map[string]any{"locale": "web", "secretNote": "hidden"}}
			if _, err = makeClient().AdminCreateUser(ctx, browser); err == nil {
				t.Fatal("anonymous administrative creation")
			}
			for key, value := range map[string]any{"role": "admin", "banned": true, "emailVerified": true} {
				browser.Data[key] = value
				_, err := creator.AdminCreateUser(ctx, browser)
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != 403 {
					t.Fatalf("protected %s: %v", key, err)
				}
				delete(browser.Data, key)
				absent(browser.Email)
			}
			browser.Data["internalLabel"] = "host-only"
			_, err = manager.AdminCreateUser(ctx, browser)
			expectCode(err, "FIELD_NOT_ALLOWED")
			absent(browser.Email)
			delete(browser.Data, "internalLabel")
			view, err := creator.AdminCreateUser(ctx, browser)
			if err != nil || view.Role != "user" {
				t.Fatal("creator could not provision a normal profile", err)
			}
			checkUserField(t, *view, "locale", "web")
			if err := host.UpdateTrustedUserFields(ctx, view.ID, map[string]any{"locale": "stored-new", "privateRank": 91}); err != nil {
				t.Fatal(err)
			}
			read, err := manager.AdminGetUser(ctx, view.ID)
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, *read, "locale", "stored-new")
			page, err := manager.AdminListUsers(ctx, auth.AdminQuery{SearchField: "email", SearchValue: browser.Email})
			if err != nil || len(page.Users) != 1 || page.Users[0].ID != view.ID {
				t.Fatal("inconsistent administrative list", err)
			}
			checkUserField(t, page.Users[0], "locale", "stored-new")
			if _, ok := page.Users[0].AdditionalField("privateRank"); ok {
				t.Fatal("administrative browse exposed hidden fields")
			}
			_, err = host.AdminCreateUser(ctx, input)
			expectCode(err, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
			_, err = host.AdminCreateUser(ctx, auth.AdminCreateUserRequest{Name: "Invalid", Email: "invalid@example.test", Data: map[string]any{"locale": "x", "score": 3.5}})
			expectCode(err, "VALIDATION_ERROR")
			absent("invalid@example.test")
			missing := auth.AdminCreateUserRequest{Name: "Missing", Email: "missing@example.test"}
			_, err = host.AdminCreateUser(ctx, missing)
			expectCode(err, "MISSING_FIELD")
			absent(missing.Email)
			// Two authorized paths race for the same unique account. The winning name,
			// profile and credential must all come from the same request.
			const competingEmail = "competing@example.test"
			start := make(chan struct{})
			results := make(chan error, 2)
			for _, source := range []string{"host", "operator"} {
				go func() {
					<-start
					in := auth.AdminCreateUserRequest{Name: source, Email: competingEmail, Password: password + source, Data: map[string]any{"locale": source}}
					var err error
					if source == "host" {
						_, err = host.AdminCreateUser(ctx, in)
					} else {
						_, err = manager.AdminCreateUser(ctx, in)
					}
					results <- err
				}()
			}
			close(start)
			winners := 0
			for range 2 {
				if err := <-results; err != nil {
					expectCode(err, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
				} else {
					winners++
				}
			}
			if winners != 1 {
				t.Fatalf("competing creates produced %d winners", winners)
			}
			page, err = manager.AdminListUsers(ctx, auth.AdminQuery{SearchField: "email", SearchValue: competingEmail})
			if err != nil || len(page.Users) != 1 {
				t.Fatal("missing unique account", err)
			}
			winner := page.Users[0].Name
			result, err := makeClient().SignInEmail(ctx, client.SignInRequest{Email: competingEmail, Password: password + winner})
			if err != nil {
				t.Fatal("winning credential could not sign in", err)
			}
			checkUserField(t, result.User, "locale", winner)
			// Existing browser cookies cannot retain permissions after a live role change.
			if _, err := manager.AdminSetRole(ctx, created.User.ID, "user"); err != nil {
				t.Fatal(err)
			}
			browser.Email = "demoted@example.test"
			_, err = creator.AdminCreateUser(ctx, browser)
			expectCode(err, "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS")
			absent(browser.Email)
			if dialect == "sqlite" {
				// The result must represent what the store actually persisted. A failed
				// readback must roll back both the profile and its optional credential.
				_, err := store.db.ExecContext(ctx, `CREATE TRIGGER adjust_after_admin_insert AFTER INSERT ON "user" WHEN NEW.email LIKE 'trigger-%' BEGIN
				UPDATE "user" SET score=(CASE WHEN NEW.email='trigger-ok@example.test' THEN 73 ELSE 2147483648 END) WHERE id=NEW.id; END`)
				if err != nil {
					t.Fatal(err)
				}
				input.Email = "trigger-ok@example.test"
				u, err := host.AdminCreateUser(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
				checkUserField(t, *u, "score", int64(73))
				input.Email = "trigger-invalid@example.test"
				if _, err = manager.AdminCreateUser(ctx, input); err == nil {
					t.Fatal("invalid stored profile was published")
				}
				absent(input.Email)
				var orphan int
				if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM "account" a LEFT JOIN "user" u ON a."userId"=u.id WHERE u.id IS NULL`).Scan(&orphan); err != nil || orphan != 0 {
					t.Fatal("uncommitted profile left an account", err)
				}
			}
		})
	}
}
