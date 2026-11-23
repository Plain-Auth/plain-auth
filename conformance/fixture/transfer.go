package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/onetimetoken"
)

func transferPlugin(mode string) (auth.Plugin, error) {
	switch mode {
	case "default":
		return onetimetoken.New(onetimetoken.Options{})
	case "header", "restricted", "suppress":
		return onetimetoken.New(onetimetoken.Options{SetHeaderOnNewSession: true, DisableClientRequest: mode == "restricted", DisableSetSessionCookie: mode == "suppress"})
	case "immediate":
		return onetimetoken.New(onetimetoken.Options{ExpireImmediately: true})
	case "short":
		return onetimetoken.New(onetimetoken.Options{ExpiresIn: 600 * time.Millisecond})
	}
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
