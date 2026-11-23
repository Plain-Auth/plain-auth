package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOAuthResourceSeedModes(t *testing.T) {
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
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			defer s.Close()
			peer, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			defer peer.Close()
			var logs bytes.Buffer
			host, err := auth.New(auth.Options{BaseURL: "https://issuer.example.test", Secret: strings.Repeat("s", 32), Store: s, EmailAndPassword: true,
				Logger: slog.New(slog.NewTextHandler(&logs, nil))})
			must(err)
			u, err := host.SignUpEmail(ctx, auth.SignUpInput{Name: "Operator", Email: "seeds@example.test", Password: "a long fixture password"}, auth.RequestMeta{})
			must(err)
			h := http.Header{"Cookie": {host.SessionCookie(u.Token, true).String()}}
			makeManager := func(store op.ResourceStore, mode op.ResourceSeedMode, cache *op.ResourceSeedCache, defs ...op.ResourceDefinition) *op.ResourceManager {
				t.Helper()
				m, e := op.NewResourceManager(host, store, op.ResourceManagerOptions{Resources: defs, SeedMode: mode, SharedSeeds: cache})
				must(e)
				return m
			}
			manager := makeManager(s, "", nil)
			const id = "urn:example:reports"
			var configured []op.ResourceDefinition
			must(json.Unmarshal([]byte(`["urn:example:status",{"identifier":"urn:example:reports","name":"Reports","refreshTokenTtl":1400,"allowedScopes":["read"],"customClaims":{"edition":"old"},"metadata":{"v":1},"disabled":true,"dpopBoundAccessTokensRequired":true,"signingAlgorithm":"PS256","signingKeyId":"first"}]`), &configured))
			initial := makeManager(s, "", nil, configured...)
			configured[1].Policy.Name = op.Set("mutated config")
			before, err := initial.Get(ctx, h, id)
			must(err)
			if before.Name != "Reports" || before.RefreshTokenTTL == nil || *before.RefreshTokenTTL != 1400 || before.SigningAlgorithm == nil || *before.SigningAlgorithm != "PS256" {
				t.Fatal("lazy startup seeding lost input", before)
			}
			_, err = manager.Update(ctx, h, id, op.ResourcePatch{Name: op.Set("Edited")})
			must(err)
			must(makeManager(peer, op.SeedInsertOnly, nil, configured...).Seed(ctx))
			retained, err := peer.OAuthResource(ctx, id)
			must(err)
			if retained.Name != "Edited" {
				t.Fatal("insertOnly reverted administrative edit")
			}
			def := op.ResourceDefinition{Identifier: id, Policy: op.ResourcePatch{AccessTokenTTL: op.Set(int64(120)), Disabled: op.Set(false)}}
			merge := makeManager(peer, op.SeedMerge, nil, def)
			must(merge.Seed(ctx))
			merged, err := s.OAuthResource(ctx, id)
			must(err)
			if merged.Name != "Edited" || merged.AccessTokenTTL == nil || *merged.AccessTokenTTL != 120 || merged.Disabled || len(merged.CustomClaims) != 1 || len(merged.AllowedScopes) != 1 {
				t.Fatal("merge lost an unspecified field", merged)
			}
			_, err = manager.Update(ctx, h, id, op.ResourcePatch{AccessTokenTTL: op.Set(int64(45))})
			must(err)
			must(merge.Seed(ctx))
			merged, err = s.OAuthResource(ctx, id)
			must(err)
			if *merged.AccessTokenTTL != 45 {
				t.Fatal("completed seed rewrote an admin edit")
			}

			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthResource" SET "policyVersion"=4 WHERE "identifier"=?`), id)
			must(err)
			must(makeManager(s, op.SeedOverwrite, nil, op.ResourceDefinition{Identifier: id}).Seed(ctx))
			replaced, err := s.OAuthResource(ctx, id)
			must(err)
			if replaced.ID != before.ID || !replaced.CreatedAt.Equal(before.CreatedAt) || replaced.Name != id ||
				replaced.PolicyVersion != 1 || replaced.RefreshTokenTTL != nil || replaced.AccessTokenTTL != nil || replaced.SigningKeyID != nil ||
				replaced.SigningAlgorithm != nil || replaced.Disabled || replaced.DPoPBoundAccessTokensRequired || replaced.CustomClaims != nil || replaced.Metadata != nil || replaced.AllowedScopes != nil {
				t.Fatal("overwrite did not replace only the policy", replaced)
			}

			shared := new(op.ResourceSeedCache)
			a, b := makeManager(s, op.SeedMerge, shared, def), makeManager(peer, op.SeedMerge, shared, def)
			must(a.Seed(ctx))
			_, err = manager.Update(ctx, h, id, op.ResourcePatch{AccessTokenTTL: op.Set(int64(60))})
			must(err)
			must(b.Seed(ctx))
			after, err := peer.OAuthResource(ctx, id)
			must(err)
			if *after.AccessTokenTTL != 60 {
				t.Fatal("shared process seed reverted an admin edit")
			}
			changed := op.ResourceDefinition{Identifier: id, Policy: op.ResourcePatch{AccessTokenTTL: op.Set(int64(75))}}
			must(makeManager(peer, op.SeedMerge, shared, changed).Seed(ctx))
			after, err = s.OAuthResource(ctx, id)
			must(err)
			if *after.AccessTokenTTL != 75 {
				t.Fatal("shared process cache ignored new configuration")
			}

			_, err = manager.Update(ctx, h, id, op.ResourcePatch{SigningAlgorithm: op.Set("RS256")})
			must(err)
			must(makeManager(s, op.SeedMerge, nil,
				op.ResourceDefinition{Identifier: "plain-name"},
				op.ResourceDefinition{Identifier: id, Policy: op.ResourcePatch{SigningAlgorithm: op.Set("unsupported"), Name: op.Set("sanitized")}},
			).Seed(ctx))
			after, err = peer.OAuthResource(ctx, id)
			must(err)
			if after.SigningAlgorithm == nil || *after.SigningAlgorithm != "RS256" || after.Name != "sanitized" || !strings.Contains(logs.String(), "Skipping invalid OAuth resource identifier") || !strings.Contains(logs.String(), "Ignoring unsupported OAuth resource signing algorithm") {
				t.Fatal("invalid seed diagnostics or retained fields", after)
			}

			// Race separate connections after both readers have observed a missing row.
			const concurrent = "urn:example:concurrent"
			ready := make(chan struct{}, 2)
			release := make(chan struct{})
			stores := []*seedRaceStore{{Store: s, id: concurrent, ready: ready, release: release}, {Store: peer, id: concurrent, ready: ready, release: release}}
			first := makeManager(stores[0], op.SeedMerge, nil, op.ResourceDefinition{Identifier: concurrent, Policy: op.ResourcePatch{Name: op.Set("concurrent name")}})
			second := makeManager(stores[1], op.SeedMerge, nil, op.ResourceDefinition{Identifier: concurrent, Policy: op.ResourcePatch{AccessTokenTTL: op.Set(int64(81))}})
			errs := make(chan error, 2)
			raceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			go func() { errs <- first.Seed(raceCtx) }()
			go func() { errs <- second.Seed(raceCtx) }()
			for range 2 {
				select {
				case <-ready:
				case err := <-errs:
					t.Fatalf("seed returned before both connections read the row: %v", err)
				case <-raceCtx.Done():
					t.Fatal(raceCtx.Err())
				}
			}
			close(release)
			must(<-errs)
			must(<-errs)
			final, err := s.OAuthResource(ctx, concurrent)
			must(err)
			if final.Name != "concurrent name" || final.AccessTokenTTL == nil || *final.AccessTokenTTL != 81 {
				t.Fatal("concurrent seed lost a policy", final)
			}

			var attempts atomic.Int32
			custom := func(allowed bool) *op.ResourceManager {
				m, e := op.NewResourceManager(host, s, op.ResourceManagerOptions{SharedSeeds: shared, Resources: []op.ResourceDefinition{{Identifier: "custom-api"}},
					IdentifierValidator: func(context.Context, string) (bool, error) { attempts.Add(1); return allowed, nil }})
				must(e)
				return m
			}
			must(custom(false).Seed(ctx))
			must(custom(true).Seed(ctx))
			if _, e := peer.OAuthResource(ctx, "custom-api"); e != nil || attempts.Load() != 2 {
				t.Fatal("rejected entry suppressed another validator", e)
			}
		})
	}
}

type seedRaceStore struct {
	*Store
	id      string
	ready   chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *seedRaceStore) OAuthResource(ctx context.Context, id string) (op.Resource, error) {
	r, err := s.Store.OAuthResource(ctx, id)
	if id == s.id && errors.Is(err, auth.ErrNotFound) {
		s.once.Do(func() {
			s.ready <- struct{}{}
			select {
			case <-s.release:
			case <-ctx.Done():
			}
		})
	}
	return r, err
}

type transientSeedStore struct {
	*Store
	failed atomic.Bool
}

func (s *transientSeedStore) OAuthResource(ctx context.Context, id string) (op.Resource, error) {
	if id == "urn:retry:second" && s.failed.CompareAndSwap(false, true) {
		return op.Resource{}, errors.New("temporary resource read failure")
	}
	return s.Store.OAuthResource(ctx, id)
}

func TestOAuthResourceSeedRecovery(t *testing.T) {
	ctx := t.Context()
	dsn := organizationTestDSN(t, "sqlite")
	s, err := OpenWithOptions(ctx, "sqlite", dsn, nil, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	host, err := auth.New(auth.Options{BaseURL: "https://issuer.example.test", Secret: strings.Repeat("s", 32), Store: s, EmailAndPassword: true})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &transientSeedStore{Store: s}
	const first = "urn:retry:first"
	const second = "urn:retry:second"
	m, err := op.NewResourceManager(host, adapter, op.ResourceManagerOptions{SeedMode: op.SeedMerge, Resources: []op.ResourceDefinition{
		{Identifier: first, Policy: op.ResourcePatch{Name: op.Set("Declared")}}, {Identifier: second},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Seed(ctx); err == nil {
		t.Fatal("seeding before migration succeeded")
	}
	migrated, err := OpenWithOptions(ctx, "sqlite", dsn, []string{"oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if err := m.Seed(ctx); err == nil || err.Error() != "temporary resource read failure" {
		t.Fatalf("unexpected partial seed error: %v", err)
	}
	before, err := migrated.OAuthResource(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrated.UpdateOAuthResource(ctx, first, op.ResourcePatch{Name: op.Set("Operator edit")}, before.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	u, err := host.SignUpEmail(ctx, auth.SignUpInput{Name: "Operator", Email: "retry@example.test", Password: "a local operator password"}, auth.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Cookie": {host.SessionCookie(u.Token, true).String()}}
	if _, err := m.Get(ctx, h, second); err != nil {
		t.Fatal("first access failed to retry seed", err)
	}
	after, err := migrated.OAuthResource(ctx, first)
	if err != nil || after.ID != before.ID || after.Name != "Operator edit" {
		t.Fatal("retry reverted an edit on a completed entry", after, err)
	}
}
