# Mounting the auth handler

Construct one `*stonewrit.Auth` during application startup and reuse it across requests. It implements `http.Handler`. Mount the whole auth prefix so endpoint paths and repeated `Set-Cookie` headers reach the client intact. Set `Options.BasePath` to the same prefix when using a custom mount. Pass the original request path through to the library.

Register both the auth handler and your own route with your router. The `me` handler below reads the session created by `auth`.

| Router | Auth endpoints | Your protected route |
| --- | --- | --- |
| Standard `http.ServeMux` | `mux.Handle("/api/auth/", auth)` | `mux.HandleFunc("GET /me", me)` |
| chi v5 | `router.Handle("/api/auth/*", auth)` | `router.Get("/me", me)` |
| Gorilla Mux | `router.PathPrefix("/api/auth/").Handler(auth)` | `router.HandleFunc("/me", me).Methods("GET")` |
| Gin | `router.Any("/api/auth/*path", gin.WrapH(auth))` | `router.GET("/me", gin.WrapH(me))` |
| Echo v5 | `router.Any("/api/auth/*", echo.WrapHandler(auth))` | `router.GET("/me", echo.WrapHandler(me))` |
| Fiber v3 | `app.All("/api/auth/*", adaptor.HTTPHandler(auth))` | `app.Get("/me", adaptor.HTTPHandler(me))` |

Fiber uses `github.com/gofiber/fiber/v3/middleware/adaptor`. Gin's wrapper comes from `github.com/gin-gonic/gin`. Your service only needs the router it uses. Other routers that accept `http.Handler` can use the same mount pattern. A framework with its own request model needs an adapter that preserves the path, body, cookies, and response headers.

## Protect an application route

Use the request context and headers from the incoming request. Treat a missing session as signed out. Handle storage errors separately so an outage can be diagnosed.

```go
me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
```

## Verify your mount

Call `GET /api/auth/ok` to check routing. Then run the signup and sign-out flow in the [quickstart](../README.md#run-it-locally). Sign-out can expire multiple cookies in one response. Proxies and framework adapters must preserve each header independently.

The [router tests](../integrations/routers/routers_test.go) exercise real router packages in their own Go module. Run them from the repository root.

```sh
(cd integrations/routers && go test -race ./...)
```
