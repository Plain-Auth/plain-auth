// Command env reports only public configuration and the signature of a fixed
// test value. The test harness supplies synthetic signing keys.
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/memory"
	"github.com/nabuhadba/go-better-auth/client"
)

type recordTarget struct{ url string }

func (r *recordTarget) RoundTrip(req *http.Request) (*http.Response, error) {
	r.url = req.URL.String()
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader("null"))}, nil
}
func main() {
	if len(os.Args) == 3 && os.Args[1] == "client" {
		r := &recordTarget{}
		c, err := client.New(os.Args[2], &http.Client{Transport: r})
		if err != nil {
			log.Fatal(err)
		}
		if _, err = c.GetSession(context.Background()); err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(r.url); err != nil {
			log.Fatal(err)
		}
		return
	}
	a, err := auth.New(auth.Options{Store: memory.New()})
	if err != nil {
		log.Fatal(err)
	}
	mount, err := a.CallbackURL(a.BasePath())
	if err != nil {
		log.Fatal(err)
	}
	_, trusted := a.CallbackURL("https://client.example.test/return")
	_, unknown := a.CallbackURL("https://other.example.test/return")
	cookie, err := url.PathUnescape(a.SessionCookie("fixture", true).Value)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"mount": mount, "cookie": cookie, "trusted": trusted == nil, "unknown": unknown == nil,
	}); err != nil {
		log.Fatal(err)
	}
}
