package main

import (
	"encoding/json"
	"net/http"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

func mountResourceSeedFixture(mux *http.ServeMux, a *auth.Auth, store op.ResourceStore) {
	var shared op.ResourceSeedCache
	mux.HandleFunc("POST /__fixture/seed-resources", func(w http.ResponseWriter, r *http.Request) {
		var boot struct {
			Resources         []op.ResourceDefinition
			ResourceSeedMode  op.ResourceSeedMode
			ResourceSeedScope string
		}
		if err := json.NewDecoder(r.Body).Decode(&boot); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		opts := op.ResourceManagerOptions{Resources: boot.Resources, SeedMode: boot.ResourceSeedMode}
		if boot.ResourceSeedScope == "process" {
			opts.SharedSeeds = &shared
		}
		registry, err := op.NewResourceManager(a, store, opts)
		if err == nil {
			err = registry.Seed(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
