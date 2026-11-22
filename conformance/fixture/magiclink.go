package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/Plain-Auth/plain-auth/plugins/magiclink"
)

func fixtureMagicLink(path string) magiclink.Options {
	return magiclink.Options{
		HashTokens: true, DisableSignUp: os.Getenv("CONFORMANCE_MAGIC_CLOSED") == "1",
		Send: func(_ context.Context, m magiclink.Message) error {
			// Only explicitly chosen, synthetic request metadata enters this mailbox.
			record := struct {
				magiclink.Message
				Method, Route, Locale string
			}{m, m.Request.Method, m.Request.URL.Path, m.Request.Header.Get("Accept-Language")}
			payload, err := json.Marshal(record)
			if err != nil {
				return err
			}
			return os.WriteFile(path, payload, 0600)
		},
	}
}
