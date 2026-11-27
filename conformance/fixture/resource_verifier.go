package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// resourceVerifierFixture answers POST /__fixture/verify-bearer with what an
// access token verifier makes of a token, for conformance/resource-verifier.mjs.
func resourceVerifierFixture(config string, fallback http.Handler) http.Handler {
	var opts oauthprovider.AccessTokenVerifierOptions
	if err := json.Unmarshal([]byte(config), &opts); err != nil {
		log.Fatal(err)
	}
	verifier, err := oauthprovider.NewAccessTokenVerifier(opts)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /__fixture/verify-bearer", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token  string   `json:"token"`
			Scopes []string `json:"scopes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		claims, err := verifier.VerifyBearer(r.Context(), req.Token, req.Scopes...)
		writeVerification(w, claims, err)
	})
	protected, err := verifier.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := oauthprovider.AccessTokenClaims(r.Context())
		writeVerification(w, claims, nil)
	}), "read")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("GET /__fixture/protected", protected)
	mux.HandleFunc("GET /__fixture/verified-resource", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.VerifyRequest(r.Context(), oauthprovider.ResourceRequestFrom(r, "http://"+r.Host))
		writeVerification(w, claims, err)
	})
	mux.Handle("/", fallback)
	return mux
}

func writeVerification(w http.ResponseWriter, claims map[string]any, err error) {
	result := map[string]any{"status": 200, "payload": claims}
	var failure *oauthprovider.ResourceFailure
	switch {
	case errors.As(err, &failure):
		result = map[string]any{"status": failure.Status, "error": failure.Code, "error_description": failure.Description, "message": failure.Message, "scopes": failure.MissingScopes}
	case err != nil:
		result = map[string]any{"status": 500}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
