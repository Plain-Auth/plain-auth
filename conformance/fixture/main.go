// Command fixture serves a disposable instance to the differential client tests.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	authn "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlstore"
	"github.com/nabuhadba/go-better-auth/plugins/magiclink"
	"github.com/nabuhadba/go-better-auth/plugins/onetimetoken"
	"github.com/nabuhadba/go-better-auth/plugins/organization"
	"github.com/nabuhadba/go-better-auth/plugins/passkey"
	"github.com/nabuhadba/go-better-auth/plugins/pwnedpassword"
	"github.com/nabuhadba/go-better-auth/plugins/twofactor"
	"github.com/nabuhadba/go-better-auth/schema"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: fixture <temporary-database-path> [organization|two-factor ...]")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	baseURL := "http://" + listener.Addr().String()
	ddl, err := schema.Generate("sqlite", os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(context.Background(), "sqlite", os.Args[1], ddl)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	var plugins []authn.Plugin
	for _, id := range os.Args[2:] {
		switch id {
		case "passkey":
			p, err := passkey.New(passkey.Options{RPID: "example.test", RPName: "Local Test", Origins: []string{"https://accounts.example.test"}, RequireUserVerification: true})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "organization":
			p, err := organization.New(organization.Options{Store: store})
			if err != nil {
				log.Fatal(err)
			}
			plugins = append(plugins, p)
		case "two-factor":
			plugins = append(plugins, twofactor.New(twofactor.Options{}))
		default:
			log.Fatal("unknown runtime plugin")
		}
	}
	if os.Getenv("CONFORMANCE_MAILBOX") == "1" {
		mailbox := filepath.Join(filepath.Dir(os.Args[1]), "mailbox.json")
		p, err := magiclink.New(magiclink.Options{HashTokens: true, Send: func(_ context.Context, m magiclink.Message) error {
			payload, err := json.Marshal(m)
			if err != nil {
				return err
			}
			return os.WriteFile(mailbox, payload, 0600)
		}})
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if os.Getenv("CONFORMANCE_TRANSFER") == "1" {
		p, err := onetimetoken.New(onetimetoken.Options{HashTokens: true})
		if err != nil {
			log.Fatal(err)
		}
		plugins = append(plugins, p)
	}
	if digest := os.Getenv("CONFORMANCE_SYNTHETIC_BREACH"); digest != "" {
		if len(digest) != 40 {
			log.Fatal("invalid synthetic breach fixture")
		}
		plugins = append(plugins, pwnedpassword.New(pwnedpassword.Options{Transport: passwordRangeFixture{digest}}))
	}
	var social map[string]authn.OAuthProvider
	if os.Getenv("CONFORMANCE_PROVIDER") == "1" {
		social = fixtureSocialProvider()
	}
	auth, err := authn.New(authn.Options{
		SocialProviders:  social,
		Plugins:          plugins,
		BaseURL:          baseURL,
		EmailAndPassword: true,
		Secret:           "local-conformance-0123456789-abcdefghijk",
		Store:            store,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(baseURL)
	log.Fatal(http.Serve(listener, auth))
}
