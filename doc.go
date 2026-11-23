// Package plainauth embeds authentication in the host application's HTTP server.
//
// An [Auth] instance implements [net/http.Handler]. Mount it under its base path on
// any router, and use the same instance inside your own handlers to read the
// signed-in user:
//
//	auth, err := plainauth.New(plainauth.Options{
//		Store:            store, // for example sqlite.Open("auth.db")
//		EmailAndPassword: true,
//	})
//	if err != nil {
//		return err
//	}
//	mux.Handle(strings.TrimSuffix(auth.BasePath(), "/")+"/", auth)
//
//	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
//		session, err := auth.GetSession(r.Context(), r.Header)
//		// session is nil when the request is not signed in.
//	})
//
// The application owns the listener, routes, middleware, database lifetime
// and every screen. Any HTTP client can call the JSON API, and the client
// package provides a typed Go client.
//
// [New] reads AUTH_SECRET and AUTH_URL from the environment when the matching
// options are empty. Storage adapters live in the adapters directory, optional
// features in plugins, and sign-in providers in providers. The guides at
// https://github.com/Plain-Org/plain-auth/tree/main/docs cover each feature.
package plainauth
