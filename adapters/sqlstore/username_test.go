package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
	"github.com/Plain-Org/plain-auth/plugins/username"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/pquerna/otp/totp"
)

func TestUsernameLifecycleAcrossStores(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			var store plainauth.Store
			if kind == "memory" {
				store = memory.New()
			} else {
				dsn := organizationTestDSN(t, kind)
				base, err := Open(ctx, kind, dsn)
				if err != nil {
					t.Fatal(err)
				}
				existing := testUser("existing")
				if err = base.CreateUser(ctx, existing, "unused", nil); err != nil {
					t.Fatal(err)
				}
				if err = base.Close(); err != nil {
					t.Fatal(err)
				}
				ddl, err := schema.Generate(kind, []string{"username"})
				if err != nil {
					t.Fatal(err)
				}
				migrated, err := OpenWithSchema(ctx, kind, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				if err = migrated.Close(); err != nil {
					t.Fatal(err)
				}
				migrated, err = OpenWithSchema(ctx, kind, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				defer migrated.Close()
				f, err := migrated.ReadUsername(ctx, existing.ID, true)
				if err != nil || f.Username != nil || f.DisplayUsername != nil {
					t.Fatal("additive migration changed existing identity", err)
				}
				store = migrated
			}
			p, err := username.New(username.Options{})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(nil)
			origin := "http://" + server.Listener.Addr().String()
			disabled := false
			service, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, DeleteUserEnabled: true, RateLimit: &disabled, Plugins: []plainauth.Plugin{p}})
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = service
			server.Start()
			defer server.Close()
			browser := func() *client.Client {
				c, err := client.New(origin, nil)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			owner := browser()
			const pwd = "username-test-credential"
			initial := "Initial_Name.1"
			signup := func(c *client.Client, email string, handle *string) (*client.EmailResult, error) {
				return c.SignUpEmail(ctx, client.SignUpRequest{Email: email, Password: pwd, Name: "Member", Username: handle})
			}
			checkCode := func(err error, want string) {
				t.Helper()
				var api *plainauth.APIError
				if !errors.As(err, &api) || api.Code != want {
					t.Fatalf("wanted %s, received %v", want, err)
				}
			}
			reg, err := signup(owner, "user@example.test", &initial)
			if err != nil || reg.User.UsernameFields == nil || *reg.User.Username != "initial_name.1" || *reg.User.DisplayUsername != initial {
				t.Fatal("sign-up did not preserve normalized and display forms", err)
			}
			_, err = signup(browser(), "other@example.test", &initial)
			checkCode(err, "USERNAME_IS_ALREADY_TAKEN")
			available, err := owner.IsUsernameAvailable(ctx, strings.ToUpper(initial))
			if err != nil || available {
				t.Fatal("normalized availability ignored an existing name", err)
			}
			first, err := owner.GetSession(ctx)
			if err != nil || first == nil || *first.User.Username != "initial_name.1" {
				t.Fatal("username absent from session", err)
			}
			changed := "Renamed.Member"
			if err = owner.UpdateUser(ctx, plainauth.ProfileUpdate{Username: &changed}); err != nil {
				t.Fatal(err)
			}
			next, err := owner.GetSession(ctx)
			if err != nil || *next.User.Username != "renamed.member" || *next.User.DisplayUsername != initial {
				t.Fatal("username-only updates changed display spelling", err)
			}
			pretty := "A public display name"
			if err = owner.UpdateUser(ctx, plainauth.ProfileUpdate{DisplayUsername: &pretty}); err != nil {
				t.Fatal(err)
			}
			available, err = owner.IsUsernameAvailable(ctx, initial)
			if err != nil || !available {
				t.Fatal("renaming did not release the old username", err)
			}
			signin := browser()
			remember := false
			res, err := signin.SignInUsername(ctx, client.UsernameSignInRequest{Username: strings.ToUpper(changed), Password: pwd, RememberMe: &remember, CallbackURL: "/welcome"})
			if err != nil || res.Token == nil || !res.Redirect || res.URL != "/welcome" || *res.User.DisplayUsername != pretty {
				t.Fatal("username login result", err)
			}
			short, err := signin.GetSession(ctx)
			if err != nil || short.Session.ExpiresAt.Sub(short.Session.CreatedAt) > 24*time.Hour {
				t.Fatal("short login preference lost", err)
			}
			_, err = signin.SignInUsername(ctx, client.UsernameSignInRequest{Username: changed, Password: "bad-password"})
			checkCode(err, "INVALID_USERNAME_OR_PASSWORD")
			_, err = signin.SignInUsername(ctx, client.UsernameSignInRequest{Username: "missing.handle", Password: pwd})
			checkCode(err, "INVALID_USERNAME_OR_PASSWORD")
			_, err = signin.SignInUsername(ctx, client.UsernameSignInRequest{Username: "a", Password: pwd})
			checkCode(err, "USERNAME_TOO_SHORT")
			_, err = signin.SignInUsername(ctx, client.UsernameSignInRequest{Username: changed, Password: pwd, CallbackURL: "https://untrusted.example"})
			checkCode(err, "INVALID_CALLBACK_URL")
			contested := "Shared.Handle"
			var group sync.WaitGroup
			results := make(chan error, 2)
			for _, email := range []string{"a@example.test", "b@example.test"} {
				c := browser()
				group.Go(func() { _, err := signup(c, email, &contested); results <- err })
			}
			group.Wait()
			close(results)
			wins := 0
			for err := range results {
				if err == nil {
					wins++
				} else {
					checkCode(err, "USERNAME_IS_ALREADY_TAKEN")
				}
			}
			if wins != 1 {
				t.Fatalf("concurrent registration produced %d owners", wins)
			}
			unwanted := "Uncommitted name"
			err = owner.UpdateUser(ctx, plainauth.ProfileUpdate{Name: &unwanted, Username: &contested})
			checkCode(err, "USERNAME_IS_ALREADY_TAKEN")
			after, err := owner.GetSession(ctx)
			if err != nil || after.User.Name != reg.User.Name || *after.User.Username != "renamed.member" {
				t.Fatal("conflicting rename partially updated the profile", err)
			}
			if err = owner.UpdateUser(ctx, plainauth.ProfileUpdate{ClearUsername: true}); err != nil {
				t.Fatal(err)
			}
			cleared, err := owner.GetSession(ctx)
			if err != nil || cleared.User.Username != nil || *cleared.User.DisplayUsername != pretty {
				t.Fatal("clearing the login name changed the omitted display field", err)
			}
			if free, err := owner.IsUsernameAvailable(ctx, changed); err != nil || !free {
				t.Fatal("cleared username remained claimed", err)
			}
			_, err = signin.SignInUsername(ctx, client.UsernameSignInRequest{Username: changed, Password: pwd})
			checkCode(err, "INVALID_USERNAME_OR_PASSWORD")
			if err = owner.UpdateUser(ctx, plainauth.ProfileUpdate{Username: &changed, ClearDisplayUsername: true}); err != nil {
				t.Fatal(err)
			}
			cleared, err = owner.GetSession(ctx)
			if err != nil || *cleared.User.Username != "renamed.member" || cleared.User.DisplayUsername != nil {
				t.Fatal("clearing display field removed the login name", err)
			}
			if err = owner.UpdateUser(ctx, plainauth.ProfileUpdate{DisplayUsername: &pretty}); err != nil {
				t.Fatal(err)
			}
			err = owner.UpdateUser(ctx, plainauth.ProfileUpdate{Username: &contested, ClearDisplayUsername: true})
			checkCode(err, "USERNAME_IS_ALREADY_TAKEN")
			cleared, err = owner.GetSession(ctx)
			if err != nil || *cleared.User.DisplayUsername != pretty {
				t.Fatal("conflicting update committed a partial clear", err)
			}
			if _, err = owner.DeleteAccount(ctx, plainauth.DeleteUserInput{Password: pwd}); err != nil {
				t.Fatal(err)
			}
			available, err = signin.IsUsernameAvailable(ctx, changed)
			if err != nil || !available {
				t.Fatal("account deletion retained its username", err)
			}
			// A pair of concurrent first assignments must obey immutability inside the store.
			immutable, _ := username.New(username.Options{Immutable: true})
			fixed, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Plugins: []plainauth.Plugin{immutable}})
			if err != nil {
				t.Fatal(err)
			}
			newUser, err := fixed.SignUpEmail(ctx, plainauth.SignUpInput{Name: "Immutable", Email: "fixed@example.test", Password: pwd}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			cookie := fixed.SessionCookie(newUser.Token, true)
			h := http.Header{"Cookie": []string{cookie.Name + "=" + cookie.Value}}
			responses := make(chan error, 2)
			for _, name := range []string{"FirstHandle", "AnotherHandle"} {
				group.Go(func() { responses <- fixed.UpdateUser(ctx, h, plainauth.ProfileUpdate{Username: &name}) })
			}
			group.Wait()
			close(responses)
			wins = 0
			for err := range responses {
				if err == nil {
					wins++
				} else {
					checkCode(err, "USERNAME_IS_IMMUTABLE")
				}
			}
			if wins != 1 {
				t.Fatal("immutable first assignments raced")
			}
			err = fixed.UpdateUser(ctx, h, plainauth.ProfileUpdate{ClearUsername: true})
			checkCode(err, "USERNAME_IS_IMMUTABLE")
			if err = fixed.UpdateUser(ctx, h, plainauth.ProfileUpdate{ClearDisplayUsername: true}); err != nil {
				t.Fatal(err)
			}
			if err = fixed.SignOut(ctx, h); err != nil {
				t.Fatal(err)
			}
			err = store.(plainauth.UsernameStore).UpdateUsernameProfile(ctx, newUser.User.ID, newUser.Token, plainauth.ProfileUpdate{ClearDisplayUsername: true}, time.Now(), true)
			if !errors.Is(err, plainauth.ErrNotFound) {
				t.Fatal("revoked owner session changed a username profile", err)
			}

		})
	}
}

func TestUsernameValidationAndOptionalDisplay(t *testing.T) {
	ctx := t.Context()
	p, err := username.New(username.Options{Normalize: func(s string) string { return strings.ToLower(strings.ReplaceAll(s, " ", "")) }, ValidateAfterNormalization: true,
		NormalizeDisplay: strings.TrimSpace, ValidateDisplayAfterNormalization: true, ValidateDisplay: func(_ context.Context, s string) bool { return s == "Display" },
		Validate: func(_ context.Context, s string) bool { return !strings.Contains(s, "reserved") }, MinLength: 3, MaxLength: 8})
	if err != nil {
		t.Fatal(err)
	}
	makeService := func(p plainauth.Plugin) *plainauth.Auth {
		a, err := plainauth.New(plainauth.Options{Store: memory.New(), EmailAndPassword: true, Secret: strings.Repeat("s", 32), BaseURL: "http://localhost", Plugins: []plainauth.Plugin{p}})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	service := makeService(p)
	name, display := "A b c", " Display "
	user, err := service.SignUpEmail(ctx, plainauth.SignUpInput{Name: "Example", Email: "test@example.test", Password: "test-password", Username: &name, DisplayUsername: &display}, plainauth.RequestMeta{})
	if err != nil || *user.User.Username != "abc" || *user.User.DisplayUsername != "Display" {
		t.Fatal("post-normalization validators", err)
	}
	for _, test := range []struct{ s, code string }{{"ab", "USERNAME_TOO_SHORT"}, {"Long Word 99", "USERNAME_TOO_LONG"}, {"Reserved", "INVALID_USERNAME"}} {
		_, err := service.IsUsernameAvailable(ctx, test.s)
		var api *plainauth.APIError
		if !errors.As(err, &api) || api.Code != test.code {
			t.Fatalf("unexpected validation for %q: %v", test.s, err)
		}
	}
	implicit := "Free"
	implicitUser, err := service.SignUpEmail(ctx, plainauth.SignUpInput{Name: "Implicit", Email: "implicit@example.test", Password: "test-password", Username: &implicit}, plainauth.RequestMeta{})
	if err != nil || *implicitUser.User.DisplayUsername != implicit {
		t.Fatal("implicit display spelling validated as explicit input", err)
	}
	display = "Bad"
	_, err = service.SignUpEmail(ctx, plainauth.SignUpInput{Name: "Example", Email: "other@example.test", Password: "test-password", Username: &name, DisplayUsername: &display}, plainauth.RequestMeta{})
	var api *plainauth.APIError
	if !errors.As(err, &api) || api.Code != "INVALID_DISPLAY_USERNAME" {
		t.Fatal("display validator ignored", err)
	}
	p, err = username.New(username.Options{DisableDisplay: true, DisableNormalization: true, DisableAvailability: true})
	if err != nil {
		t.Fatal(err)
	}
	service = makeService(p)
	r := httptest.NewRequest(http.MethodPost, "http://localhost/api/auth/is-username-available", strings.NewReader(`{"username":"valid"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	service.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatal("disabled public availability endpoint remained reachable")
	}
	name = "CaseSensitive"
	user, err = service.SignUpEmail(ctx, plainauth.SignUpInput{Name: "Case", Email: "case@example.test", Password: "test-password", DisplayUsername: &name}, plainauth.RequestMeta{})
	if err != nil || *user.User.Username != name || user.User.DisplayUsernameFields != nil {
		t.Fatal("no-display mode failed display-only signup fallback", err)
	}
	if available, err := service.IsUsernameAvailable(ctx, strings.ToLower(name)); err != nil || !available {
		t.Fatal("disabled normalization collapsed different names", err)
	}
}

func TestUsernameVerificationAndFactorChallenge(t *testing.T) {
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"username", "admin", "two-factor"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenWithSchema(ctx, "sqlite", ":memory:", ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := username.New(username.Options{})
	if err != nil {
		t.Fatal(err)
	}
	adminPlugin, err := plainauth.NewAdmin(plainauth.AdminOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	rate := false
	var mail plainauth.MailLink
	a, err := plainauth.New(plainauth.Options{Store: db, BaseURL: origin, EmailAndPassword: true, RequireEmailVerification: true, SendVerificationOnSignIn: true,
		SendVerificationEmail: func(_ context.Context, m plainauth.MailLink) error { mail = m; return nil }, Secret: strings.Repeat("s", 32), RateLimit: &rate, Plugins: []plainauth.Plugin{p, twofactor.New(twofactor.Options{}), adminPlugin}})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = a
	server.Start()
	defer server.Close()
	browser, err := client.New(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func(err error, code string) {
		t.Helper()
		var e *plainauth.APIError
		if !errors.As(err, &e) || e.Code != code {
			t.Fatal("expected", code, "got", err)
		}
	}
	const pwd = "protected-username-password"
	name := "protected"
	reg, err := browser.SignUpEmail(ctx, client.SignUpRequest{Name: "Protected", Email: "protected@example.test", Username: &name, Password: pwd})
	if err != nil || reg.Token != nil {
		t.Fatal("unverified registration issued a session", err)
	}
	mail = plainauth.MailLink{}
	request := client.UsernameSignInRequest{Username: name, Password: "incorrect-password", CallbackURL: "/complete?code=42&complete=1"}
	_, err = browser.SignInUsername(ctx, request)
	check(err, "INVALID_USERNAME_OR_PASSWORD")
	if mail.Token != "" {
		t.Fatal("wrong password sent verification mail")
	}
	request.Password = pwd
	_, err = browser.SignInUsername(ctx, request)
	check(err, "EMAIL_NOT_VERIFIED")
	link, err := url.Parse(mail.URL)
	if err != nil || link.Query().Get("callbackURL") != request.CallbackURL {
		t.Fatal("verification callback not preserved", err)
	}
	if err = browser.VerifyEmail(ctx, mail.Token); err != nil {
		t.Fatal(err)
	}
	login, err := browser.SignInUsername(ctx, request)
	if err != nil || *login.User.Username != name {
		t.Fatal("verified username credential failed", err)
	}
	enrolled, err := browser.EnableTOTP(ctx, pwd, "Username Fixture")
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(enrolled.URI)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := totp.GenerateCode(uri.Query().Get("secret"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = browser.VerifyTOTP(ctx, proof); err != nil {
		t.Fatal(err)
	}
	if err = browser.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err := browser.SignInUsername(ctx, request)
	if err != nil || !pending.TwoFactorRedirect || pending.Token != nil {
		t.Fatal("username login failed to require enrolled second factor", err)
	}
	if s, err := browser.GetSession(ctx); s != nil || err != nil {
		t.Fatal("pending username proof authenticated", err)
	}
	if _, err = browser.VerifyBackupCode(ctx, enrolled.BackupCodes[0], false); err != nil {
		t.Fatal(err)
	}
	if s, err := browser.GetSession(ctx); err != nil || s == nil || *s.User.Username != name {
		t.Fatal("completed factor lost username", err)
	}
	// Administrative create and update use the same normalization and constraints.
	if _, err = db.db.ExecContext(ctx, `UPDATE "user" SET "role"='admin' WHERE "id"=?`, reg.User.ID); err != nil {
		t.Fatal(err)
	}
	added, err := browser.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Created", Email: "created@example.test", Password: pwd, Data: map[string]any{"username": "From_Admin"}})
	if err != nil || *added.Username != "from_admin" || *added.DisplayUsername != "From_Admin" {
		t.Fatal("administrative creation lost username fields", err)
	}
	_, err = browser.AdminUpdateUser(ctx, added.ID, map[string]any{"name": "Rejected", "username": name})
	check(err, "USERNAME_IS_ALREADY_TAKEN")
	profile, err := browser.AdminGetUser(ctx, added.ID)
	if err != nil || profile.Name != "Created" || *profile.Username != "from_admin" {
		t.Fatal("administrative rename failed to roll back", err)
	}
	profile, err = browser.AdminUpdateUser(ctx, added.ID, map[string]any{"username": "Reassigned"})
	if err != nil || *profile.Username != "reassigned" || *profile.DisplayUsername != "From_Admin" {
		t.Fatal("administrative username update lost display spelling", err)
	}
	cache, err := browser.AdminListUsers(ctx, plainauth.AdminQuery{SearchValue: "created@example.test"})
	if err != nil || len(cache.Users) != 1 || *cache.Users[0].Username != "reassigned" {
		t.Fatal("administrative listing omitted username", err)
	}
	profile, err = browser.AdminUpdateUser(ctx, added.ID, map[string]any{"username": nil})
	if err != nil || profile.Username != nil || *profile.DisplayUsername != "From_Admin" {
		t.Fatal("administrator could not clear only the login name", err)
	}
	profile, err = browser.AdminUpdateUser(ctx, added.ID, map[string]any{"displayUsername": nil})
	if err != nil || profile.DisplayUsername != nil {
		t.Fatal("administrator could not clear display name", err)
	}
	profile, err = browser.AdminGetUser(ctx, added.ID)
	if err != nil || profile.Username != nil || profile.DisplayUsername != nil {
		t.Fatal("administrator clear did not persist", err)
	}
	if _, err = db.db.ExecContext(ctx, `UPDATE "user" SET "banned"=1 WHERE "id"=?`, reg.User.ID); err != nil {
		t.Fatal(err)
	}
	_, err = browser.SignInUsername(ctx, request)
	check(err, "BANNED_USER")
}

func TestUsernameRequiresDatabaseUniqueness(t *testing.T) {
	ctx := t.Context()
	db, err := Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.db.ExecContext(ctx, `ALTER TABLE "user" ADD COLUMN "username" text`); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckUsernameSchema(ctx, false); err == nil {
		t.Fatal("username schema accepted without unique index")
	}
	if _, err = db.db.ExecContext(ctx, `CREATE UNIQUE INDEX incomplete ON "user"("username") WHERE "emailVerified"=1`); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckUsernameSchema(ctx, false); err == nil {
		t.Fatal("partial username uniqueness accepted")
	}
	if _, err = db.db.ExecContext(ctx, `CREATE UNIQUE INDEX complete_name ON "user"("username")`); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckUsernameSchema(ctx, false); err != nil {
		t.Fatal(err)
	}
}
