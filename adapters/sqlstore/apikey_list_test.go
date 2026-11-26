package sqlstore

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Key listings page, sort and merge configurations the same way on every
// database, with missing values first in ascending order.
func TestAPIKeyListPaging(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key", "organization"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			keys, err := ak.New(ak.Options{Store: store})
			must(err)
			extra, err := ak.New(ak.Options{Store: store, ConfigID: "extra"})
			must(err)
			teams, err := ak.New(ak.Options{Store: store, ConfigID: "teams", Organization: &ak.OrganizationOptions{}})
			must(err)
			plugin, err := ak.NewPlugin(keys, extra, teams)
			must(err)
			orgs, err := org.New(org.Options{Store: store})
			must(err)
			const origin = "https://lists.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("l", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin, orgs}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			account, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Lister", Email: "lister@example.test", Password: "list-password"})
			must(err)
			uid := account.User.ID
			base := time.Now().Add(-time.Hour)
			made := func(s *ak.Service, name string, expires time.Duration, minutes int) {
				t.Helper()
				k, err := s.Create(ctx, uid, ak.CreateInput{Name: name, ExpiresIn: expires})
				must(err)
				_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "createdAt"=? WHERE "id"=?`), store.date(base.Add(time.Duration(minutes)*time.Minute)), k.ID)
				must(err)
			}
			made(keys, "delta", 72*time.Hour, 1)
			made(keys, "alpha", 0, 2)
			made(keys, "echo", 48*time.Hour, 3)
			made(extra, "charlie", 120*time.Hour, 4)
			made(extra, "bravo", 96*time.Hour, 5)
			var group struct{ ID string }
			must(member.Do(ctx, "POST", "/organization/create", map[string]any{"name": "Listers", "slug": "listers"}, &group))
			_, err = member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID, Name: "team"})
			must(err)
			n := func(v int) *int { return &v }
			list := func(config string, o ak.PageOptions) *ak.Page {
				t.Helper()
				p, err := member.ListAPIKeys(ctx, config, o)
				must(err)
				return p
			}
			order := func(p *ak.Page) string {
				var names []string
				for _, k := range p.Keys {
					names = append(names, *k.Name)
				}
				return strings.Join(names, ",")
			}
			if p := list("default", ak.PageOptions{}); order(p) != "delta,alpha,echo" || p.Total != 3 {
				t.Fatal("the default order was not the creation time", order(p))
			}
			if p := list("default", ak.PageOptions{Limit: n(2)}); order(p) != "delta,alpha" || p.Total != 3 || p.Limit == nil || *p.Limit != 2 {
				t.Fatal("a limit did not truncate the page", order(p))
			}
			if p := list("default", ak.PageOptions{Limit: n(0)}); order(p) != "" || p.Total != 3 {
				t.Fatal("a zero limit returned keys", order(p))
			}
			if p := list("default", ak.PageOptions{Limit: n(2), Offset: n(2)}); order(p) != "echo" || p.Offset == nil || *p.Offset != 2 {
				t.Fatal("an offset did not skip keys", order(p))
			}
			if p := list("default", ak.PageOptions{Offset: n(5)}); order(p) != "" || p.Total != 3 {
				t.Fatal("an offset past the end returned keys", order(p))
			}
			if p := list("default", ak.PageOptions{SortBy: "expiresAt"}); order(p) != "alpha,echo,delta" {
				t.Fatal("a key without an expiry did not sort first", order(p))
			}
			if p := list("default", ak.PageOptions{SortBy: "createdAt", SortDirection: "desc"}); order(p) != "echo,alpha,delta" {
				t.Fatal("a sort field did not order the keys", order(p))
			}
			if p := list("default", ak.PageOptions{SortBy: "name", SortDirection: "desc"}); order(p) != "echo,delta,alpha" {
				t.Fatal("a descending sort did not reverse the order", order(p))
			}
			if p := list("default", ak.PageOptions{SortBy: "expiresAt", SortDirection: "desc"}); order(p) != "delta,echo,alpha" {
				t.Fatal("a key without an expiry did not sort last in descending order", order(p))
			}
			if a, b := list("", ak.PageOptions{SortBy: "createdAt", SortDirection: "desc"}), list("", ak.PageOptions{SortBy: "expiresAt"}); order(a) != "bravo,charlie,echo,alpha,delta" || order(b) != "alpha,echo,delta,bravo,charlie" {
				t.Fatal("merged keys were not sorted by the requested field", order(a), order(b))
			}
			if p := list("", ak.PageOptions{SortBy: "expiresAt", SortDirection: "desc"}); order(p) != "charlie,bravo,delta,echo,alpha" {
				t.Fatal("merged keys were not reversed by a descending sort", order(p))
			}
			a := list("", ak.PageOptions{SortBy: "name", Limit: n(2)})
			b := list("", ak.PageOptions{SortBy: "name", SortDirection: "asc", Limit: n(2), Offset: n(2)})
			c := list("", ak.PageOptions{SortBy: "name", Limit: n(2), Offset: n(4)})
			if order(a) != "alpha,bravo" || a.Total != 5 || order(b) != "charlie,delta" || order(c) != "echo" {
				t.Fatal("merged pages from several configurations were not sorted and paged together", order(a), order(b), order(c))
			}
			for _, config := range []string{"", "teams"} {
				if p := list(config, ak.PageOptions{OrganizationID: group.ID}); order(p) != "team" || p.Total != 1 {
					t.Fatal("organization listing named by configuration lost key", config, order(p))
				}
			}
			column := func(name, field string, value any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "`+field+`"=? WHERE "name"=?`), value, name)
				must(err)
			}
			for name, max := range map[string]any{"alpha": nil, "bravo": 15, "echo": 20, "charlie": 25, "delta": 30} {
				column(name, "rateLimitMax", max)
			}
			column("delta", "lastRefillAt", store.date(base.Add(time.Minute)))
			column("echo", "lastRefillAt", store.date(base.Add(2*time.Minute)))
			if p := list("", ak.PageOptions{SortBy: "rateLimitMax"}); order(p) != "alpha,bravo,echo,charlie,delta" {
				t.Fatal("merged keys were not sorted by their rate maximum", order(p))
			}
			if p, q := list("default", ak.PageOptions{SortBy: "lastRefillAt"}), list("default", ak.PageOptions{SortBy: "lastRefillAt", SortDirection: "desc"}); order(p) != "alpha,delta,echo" || order(q) != "echo,delta,alpha" {
				t.Fatal("keys were not sorted by their last refill", order(p), order(q))
			}
			for _, path := range []string{"/api-key/list?", "/api-key/list?configId=default&"} {
				for _, query := range []string{"sortBy=key", "sortBy=permissions", "sortDirection=sideways", "limit=-1", "limit=ten", "offset=-1", "offset=ten"} {
					var api *plainauth.APIError
					if err := member.Do(ctx, http.MethodGet, path+query, nil, nil); !errors.As(err, &api) || api.Code != "VALIDATION_ERROR" {
						t.Fatal("an invalid listing query was not refused", path+query, err)
					}
				}
			}

			// A single configuration lists in the database's order with or
			// without configId, mixed-case names included.
			solo, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("l", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{keys.Plugin(), orgs}})
			must(err)
			alone, err := client.New(origin, &http.Client{Transport: guestTransport{solo}})
			must(err)
			_, err = alone.SignInEmail(ctx, client.SignInRequest{Email: "lister@example.test", Password: "list-password"})
			must(err)
			made(keys, "Bravo", 0, 6)
			for _, o := range []ak.PageOptions{{SortBy: "name"}, {SortBy: "name", Limit: n(1), Offset: n(1)}, {SortBy: "name", SortDirection: "desc", Limit: n(2)}} {
				named, err := alone.ListAPIKeys(ctx, "default", o)
				must(err)
				merged, err := alone.ListAPIKeys(ctx, "", o)
				must(err)
				if order(named) != order(merged) || named.Total != merged.Total || named.Total != 4 {
					t.Fatal("a single configuration listed in two orders", order(named), order(merged))
				}
			}
			for _, path := range []string{"/api-key/list?", "/api-key/list?configId=default&"} {
				var api *plainauth.APIError
				if err := alone.Do(ctx, http.MethodGet, path+"organizationId="+group.ID, nil, nil); !errors.As(err, &api) || api.Status != 400 || api.Code != "VALIDATION_ERROR" {
					t.Fatal("an organization filter without an organization configuration was not refused", path, err)
				}
			}

			// A merged listing reads every configuration before it sweeps.
			var expired []string
			for _, s := range []*ak.Service{keys, extra} {
				k, err := s.Create(ctx, uid, ak.CreateInput{Name: "stale"})
				must(err)
				_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Minute)), k.ID)
				must(err)
				expired = append(expired, k.ID)
			}
			again, err := ak.New(ak.Options{Store: store})
			must(err)
			extraAgain, err := ak.New(ak.Options{Store: store, ConfigID: "extra"})
			must(err)
			fresh, err := ak.NewPlugin(again, extraAgain)
			must(err)
			sweeping, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("l", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{fresh}})
			must(err)
			sweeper, err := client.New(origin, &http.Client{Transport: guestTransport{sweeping}})
			must(err)
			_, err = sweeper.SignInEmail(ctx, client.SignInRequest{Email: "lister@example.test", Password: "list-password"})
			must(err)
			page, err := sweeper.ListAPIKeys(ctx, "", ak.PageOptions{})
			must(err)
			shown := 0
			for _, k := range page.Keys {
				if k.ID == expired[0] || k.ID == expired[1] {
					shown++
				}
			}
			var left int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT count(*) FROM "apikey" WHERE "id" IN (?,?)`), expired[0], expired[1]).Scan(&left))
			if shown != 2 || page.Total != len(page.Keys) || left != 0 {
				t.Fatal("a merged listing swept between its configurations", shown, page.Total, len(page.Keys), left)
			}
		})
	}
}
