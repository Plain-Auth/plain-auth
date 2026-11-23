package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

func dpopFixture(origin, boundKey string, store oauthprovider.DPoPReplayStore, next http.Handler) http.Handler {
	verifier, err := oauthprovider.NewDPoPVerifier(oauthprovider.DPoPOptions{ReplayStore: store})
	if err != nil {
		log.Fatal(err)
	}
	fail := func(w http.ResponseWriter, err error) {
		var problem *auth.OAuthError
		if errors.As(err, &problem) {
			http.Error(w, problem.Code, problem.Status)
			return
		}
		http.Error(w, "proof storage unavailable", http.StatusServiceUnavailable)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /__fixture/proof", func(w http.ResponseWriter, r *http.Request) {
		proof, err := verifier.Verify(r.Context(), r.Header.Get("DPoP"), oauthprovider.DPoPProofRequest{Method: r.Method, URL: origin + r.URL.RequestURI()})
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	})
	mux.HandleFunc("GET /__fixture/reports", func(w http.ResponseWriter, r *http.Request) {
		scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		// Stand in for an issuer that has already authenticated two fixture tokens.
		var thumb string
		switch token {
		case "bound-token":
			thumb = boundKey
		case "bearer-token":
		default:
			http.Error(w, "invalid_token", 401)
			return
		}
		err := verifier.CheckBinding(r.Context(), scheme, r.Header.Get("DPoP"), oauthprovider.DPoPProofRequest{Method: r.Method, URL: origin + r.URL.RequestURI(), AccessToken: token, ExpectedThumbprint: thumb})
		if err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", next)
	return mux
}
