// The application owns the listener, routes and database lifetime.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	path := os.Getenv("AUTH_DB")
	if path == "" {
		path = "auth.db"
	}
	store, err := sqlite.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()
	auth, err := plainauth.New(plainauth.Options{
		Store:            store,
		EmailAndPassword: true,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle(strings.TrimSuffix(auth.BasePath(), "/")+"/", auth)
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		session, err := auth.GetSession(r.Context(), r.Header)
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			http.Error(w, "Session lookup failed", http.StatusInternalServerError)
			return
		}
		if session == nil {
			http.Error(w, "Sign in first", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(session.User)
	})
	server := &http.Server{Addr: "127.0.0.1:3000", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	log.Printf("Listening on http://%s", server.Addr)
	select {
	case err := <-done:
		return err
	case <-stop.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return err
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
