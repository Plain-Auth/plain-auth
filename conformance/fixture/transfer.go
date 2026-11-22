package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/onetimetoken"
)

func transferPlugin(mode string) (auth.Plugin, error) {
	if mode == "1" {
		return onetimetoken.New(onetimetoken.Options{HashTokens: true})
	}
	opts := onetimetoken.Options{
		SetHeaderOnNewSession: true, DisableSetSessionCookie: true,
		GenerateTokenWithRequest: func(_ context.Context, owner auth.SessionResult, r *http.Request) (string, error) {
			if owner.Session.UserID != owner.User.ID || owner.User.ID == "" || r == nil {
				return "", errors.New("missing transfer context")
			}
			return path.Base(r.URL.Path) + "-" + rand.Text(), nil
		},
	}
	switch mode {
	case "plain":
	case "hashed":
		opts.HashTokens = true
	case "custom":
		opts.HashToken = func(_ context.Context, raw string) (string, error) {
			sum := sha256.Sum256([]byte(raw))
			return hex.EncodeToString(sum[:]), nil
		}
	default:
		return auth.Plugin{}, errors.New("unrecognized transfer fixture")
	}
	return onetimetoken.New(opts)
}
