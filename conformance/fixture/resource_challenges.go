package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

func resourceChallengeFixture(config string, fallback http.Handler) http.Handler {
	var settings struct {
		Resources []string
		Options   oauthprovider.ChallengeOptions
	}
	if err := json.Unmarshal([]byte(config), &settings); err != nil {
		log.Fatal(err)
	}
	challenges, err := oauthprovider.NewResourceChallenges(settings.Resources, settings.Options)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /__fixture/resource-challenge", func(w http.ResponseWriter, r *http.Request) {
		var failure oauthprovider.ResourceFailure
		if err := json.NewDecoder(r.Body).Decode(&failure); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.URL.Query().Has("detached") {
			r = nil
		}
		written, err := challenges.Write(w, r, failure)
		if err != nil && !written {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else if !written {
			w.WriteHeader(failure.Status)
		}
	})
	mux.Handle("/", fallback)
	return mux
}
