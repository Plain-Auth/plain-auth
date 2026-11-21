package main

import (
	"errors"
	"net/http"
	"os"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/customsession"
)

// These additional headers let the released client exercise the projection's
// response separately from the underlying session endpoint.
func fixtureSessionProjection() (auth.Plugin, error) {
	detailed := os.Getenv("CONFORMANCE_SESSION_VIEW") == "contract"
	return customsession.NewWithOptions(func(c auth.EndpointContext, data auth.SessionResult) (any, error) {
		if !detailed {
			return map[string]string{"viewer": data.User.Email}, nil
		}
		c.ResponseHeader.Set("Cache-Control", "public, max-age=3600")
		c.ResponseHeader.Set("Pragma", "cache")
		c.ResponseHeader.Set("X-Application-View", "active")
		for _, item := range []struct {
			name string
			age  int
		}{{"fixture_first", 11}, {"fixture_second", 22}} {
			cookie := &http.Cookie{Name: item.name, Value: "view", MaxAge: item.age, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode, Partitioned: true}
			c.ResponseHeader.Add("Set-Cookie", cookie.String())
		}
		if c.Request.Header.Get("X-Fail-Projection") == "yes" {
			return nil, errors.New("private projection backend detail")
		}
		out := map[string]any{"viewer": data.User.Email}
		if data.NeedsRefresh != nil {
			out["needsRefresh"] = *data.NeedsRefresh
		}
		return out, nil
	}, customsession.Options{ProjectDeviceSessions: os.Getenv("CONFORMANCE_DEVICE_VIEW") == "1"})
}

func fixtureSessionUpdateAge() *time.Duration {
	if os.Getenv("CONFORMANCE_SESSION_VIEW") != "contract" {
		return nil
	}
	immediate := time.Duration(0)
	return &immediate
}
