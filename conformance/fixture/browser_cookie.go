package main

import (
	"context"
	"encoding/json"
	"os"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/authtest"
)

func authWithBrowserFixture(opts auth.Options, path string) (*auth.Auth, error) {
	if path == "" {
		return auth.New(opts)
	}
	server, err := authtest.New(opts)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	user, err := server.SaveUser(ctx, authtest.NewUser())
	if err != nil {
		return nil, err
	}
	login, err := server.Login(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	cookies, err := login.BrowserCookies("")
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	err = json.NewEncoder(f).Encode(struct {
		UserID    string                   `json:"userId"`
		ExpiresAt int64                    `json:"expiresAt"`
		Cookies   []authtest.BrowserCookie `json:"cookies"`
	}{user.ID, login.Session.ExpiresAt.Unix(), cookies})
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	return server.Auth, closeErr
}
