package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// The comparison harness invokes host-side methods here. Production auth handlers
// never mount the registry or these test-only routes.
func resourceRegistryFixture(a *auth.Auth, store op.ResourceStore, fallback http.Handler) http.Handler {
	m, err := op.NewResourceManager(a, store, op.ResourceManagerOptions{
		Privileges: func(_ context.Context, actor op.ResourceAccess) (bool, error) {
			return actor.Headers.Get("X-Fixture-Resource-Access") != "deny", nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mountResourceSeedFixture(mux, a, store)
	mux.HandleFunc("POST /__fixture/resource-registry", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action, Identifier, ClientID string
			Fields                       op.ResourcePatch
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		status := http.StatusOK
		var result any
		var err error
		switch req.Action {
		case "create":
			result, err = m.Create(r.Context(), r.Header, req.Identifier, req.Fields)
			status = http.StatusCreated
		case "list":
			result, err = m.List(r.Context(), r.Header)
		case "read":
			result, err = m.Get(r.Context(), r.Header, req.Identifier)
		case "update":
			result, err = m.Update(r.Context(), r.Header, req.Identifier, req.Fields)
		case "delete":
			err = m.Delete(r.Context(), r.Header, req.Identifier)
			result = map[string]bool{"deleted": true}
		case "link":
			result, err = m.Link(r.Context(), r.Header, req.Identifier, req.ClientID)
		case "unlink":
			err = m.Unlink(r.Context(), r.Header, req.Identifier, req.ClientID)
			result = map[string]bool{"unlinked": true}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			var api *auth.APIError
			if !errors.As(err, &api) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			status, result = api.Status, map[string]string{"error": api.Code}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(result)
	})
	mux.Handle("/", fallback)
	return mux
}
