package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/Plain-Org/plain-auth/plugins/mcp"
)

// mcpHandlerFixture serves a protected MCP route at /mcp for conformance/mcp.mjs.
func mcpHandlerFixture(config string, fallback http.Handler) http.Handler {
	var opts mcp.ProtectedHandlerOptions
	if err := json.Unmarshal([]byte(config), &opts); err != nil {
		log.Fatal(err)
	}
	protected, err := mcp.NewProtectedHandler(opts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := mcp.AccessTokenClaims(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"sub": claims["sub"]})
	}))
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /mcp", protected)
	mux.Handle("/", fallback)
	return mux
}
