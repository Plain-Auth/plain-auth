# Client ID metadata documents

The `plugins/cimd` package identifies OAuth clients by Client ID Metadata Documents ([draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)), as another runtime's cimd plugin does: a client ID that is an HTTPS URL names a JSON document with the client's metadata. [Feature checklist](parity/plugins/cimd.md)

## Enable metadata document clients

Install `cimd.NewClientDiscovery` on the OAuth provider through an extension. Another runtime adds it as a companion plugin; here it is composed explicitly. Every option is optional:

```go
discovery, err := cimd.NewClientDiscovery(cimd.Options{
    MetadataRevalidationInterval: 10 * time.Minute,
    MaxCacheEntries:              1000,
    FetchPolicy: cimd.FetchPolicy{
        MinimumFetchInterval:          time.Second,
        MaxConcurrentFetches:          16,
        MaxConcurrentFetchesPerOrigin: 4,
        MaxFetchesPerMinute:           120,
        MaxFetchesPerOriginPerMinute:  30,
    },
    OriginBoundFields: []string{"post_logout_redirect_uris"},
    AllowMetadataURL: func(ctx context.Context, clientIDURL string) (bool, error) {
        u, err := url.Parse(clientIDURL)
        return err == nil && strings.HasSuffix(u.Hostname(), ".trusted.example"), nil
    },
    OnClientCreated: func(ctx context.Context, e cimd.ClientCreatedEvent) error {
        return nil // assign local trust or audit state
    },
    OnClientRefreshed: func(ctx context.Context, e cimd.ClientRefreshedEvent) error {
        return nil // compare e.PreviousClient with e.Client
    },
})
provider, err := oauthprovider.New(oauthprovider.Options{
    Extensions: []oauthprovider.Extension{{ClientDiscoveries: []oauthprovider.ClientDiscovery{discovery}}},
    // ...
})
```

For the Model Context Protocol, set `Profile: cimd.ProfileMCP20260728` and pass the extension in the options of [`mcp.New`](mcp.md); the profile requires `client_name` and a non-empty `redirect_uris`. Dynamic registration stays off unless the provider enables it. Durations are `time.Duration`, where another runtime takes seconds or duration strings, and the transport defaults to `NewTransport`, which pins addresses, where another runtime needs the host to supply one.

## Validate client ID URLs and documents

`cimd.IsClientIDURLCandidate` tells a metadata document URL from another client ID without any lookup: an `https` URL that names a host. `cimd.ValidateClientIDURL` then checks it as draft-02 §3 requires, in another runtime's order: no dot segments, no fragment, a valid URL, `https` with an explicit `https://` authority and a path, no credentials, and a public host. Explicit default ports are significant, since the document's `client_id` must equal the URL exactly.

`cimd.ValidateMetadata` checks a fetched document as §4.1 requires and returns it with unknown members stripped, `token_endpoint_auth_method` defaulted to `none`, and warnings for a `/` path or a query string. It refuses, in order:

- anything but a JSON object, and the first server-owned member in document order, such as `client_secret`, `skip_consent` or `redirectUris`;
- the registration rules' type errors, in the provider's wording;
- a `client_id` that does not equal the URL;
- under `cimd.ProfileMCP20260728`, a missing `client_name` or `redirect_uris`; both are optional otherwise;
- back-channel logout fields, symmetric or other authentication methods than `none` and `private_key_jwt`, `private_key_jwt` without keys, a JWK set with private or invalid keys, and a `jwks_uri` with credentials or a fragment;
- redirect URIs that are not absolute HTTP(S) or native private-use URIs;
- `client_uri`, `logo_uri`, `tos_uri` and `policy_uri` unless they are credential-free HTTP(S) URLs on a public host;
- an origin-bound member whose URL does not share the client ID's origin.

`ValidationOptions.OriginBoundFields` names the origin-bound members. Nil means `post_logout_redirect_uris`; an empty, non-nil list binds none. The informative URIs are not bound by default, since an application's website often lives apart from its metadata document. Origins compare as a browser serializes them: the scheme, the host in ASCII, so `bücher.example` is `xn--bcher-kva.example`, and a port other than the default. A private-use redirect URI has no origin and is exempt, in `post_logout_redirect_uris` only in its reverse-domain form such as `com.example.app:/logout`, and loopback HTTP(S) redirect URIs are exempt for native apps.

A public host is a public IP address or a dotted DNS name that is not loopback, not spelled like a number, not a cloud metadata name and not under `.internal` or `.local`. Another runtime refuses only special-use addresses, `localhost` and cloud metadata names; the other refusals are kept for safety. Results are a document, warnings and an error, where another runtime returns a valid flag with an error string. [Validation tests](../plugins/cimd/validate_test.go)

## Fetch through the pinned transport

`cimd.NewTransport` fetches metadata documents and the resources their clients publish, such as a `jwks_uri`. It sends only HTTPS `GET` and `HEAD` without a body, resolves the host once, refuses the request unless every answer is a public address, and dials only those addresses, in order, so a second lookup cannot redirect it to an internal host. An IP literal is checked the same way and dialed without a lookup. The `Host` header and TLS server name stay the URL's host. Redirects come back as responses and are never followed, a protocol upgrade is refused, no proxy is used and no connection is kept. At most 16 lookups run at once on one transport, where another runtime's limit is per process; a lookup the caller abandons keeps its slot until it settles, so a slow resolver cannot pile lookups up. Another runtime leaves this transport to the host, because its fetch API cannot pin addresses; Go can, so this is the default. [Transport tests](../plugins/cimd/transport_test.go)

## Bound metadata fetches

`cimd.FetchPolicy` bounds metadata document fetches, which are refused at once with 429 `temporarily_unavailable` rather than queued. After a failed fetch, a client ID waits `MinimumFetchInterval`, one second by default, from when the failure settled; a negative value turns that off, where another runtime uses 0, since a zero duration means unset in Go. Fetches in flight are bounded by `MaxConcurrentFetches` and `MaxConcurrentFetchesPerOrigin`, 16 and 4 by default, and fetch starts in a rolling minute by `MaxFetchesPerMinute` and `MaxFetchesPerOriginPerMinute`, 120 and 30. A negative limit is refused. The records behind pacing and per-origin budgets are bounded by the cache size; only records past their interval or window are evicted, so a full table of live records refuses newcomers. Another runtime records pacing when a fetch starts and again when it settles; here it is recorded when a fetch fails, with the same effect, since concurrent fetches of one client share one fetch. [Governor tests](../plugins/cimd/governor_test.go)

## Fetch one document

`cimd.Options` configures the discovery. `Transport` fetches documents and the resources their clients publish; nil uses `NewTransport`. `Profile` and `OriginBoundFields` pass to `ValidateMetadata`. `AllowMetadataURL` may refuse a client ID URL with invalid_client `client_id URL is not permitted by the server's fetch policy`; an error it returns is answered as is. A URL that misses the cache is checked with `ValidateClientIDURL` and then `AllowMetadataURL`, with the request's own context, before the request joins or starts a fetch, so before any fetch budget is spent. Another runtime checks both inside the permitted fetch, which spends the budget and shares one request's answer with the others; here host code never runs inside a fetch other requests share, so a hook that hangs or panics affects only its own request, and a refused URL makes no request. A request whose context ends during the check gets its context's error and records nothing. A fresh cached document, or a stored client standing in after a transient failure, answers without the check, as in another runtime.

A document is fetched with `Accept: application/json`, and with `If-None-Match` and `If-Modified-Since` only from a document validated before, within five seconds for headers and body, as another runtime does. Each failure answers invalid_client with the other runtime's description: a network failure or a blocked redirect, a timeout, a 304 without a validator, any status but 200 and 304, a media type other than JSON or `application/*+json`, a declared or read body over 5 KB, invalid JSON, or a document `ValidateMetadata` refuses. Failures fall in four classes. A transient one may pass on retry: a 500, 502, 503 or 504 answer, the five-second timeout once the host's address was resolved, a temporary DNS answer, or a connection reset, refused, timed out or unreachable, a broken pipe or a connection closed before or during the response, where another runtime reads Node error codes. A transport failure retrieved nothing: a timeout during the lookup, which says nothing about the host, a private or missing address, a TLS failure; it ends a transient record and paces the client like any failed fetch. A transport's lookup limit answers 429 `temporarily_unavailable`. Everything else is terminal. A custom `Transport` reports a lookup the deadline ended by wrapping `oauthprovider.ErrLookupAborted`, as `NewTransport` does; its other timeouts count as reaching the host. It must honour the request's context, which carries the five-second deadline; another runtime also settles a fetch whose transport ignores its signal, which Go cannot do without leaving the transport's goroutine running. A panic in its `RoundTrip`, for a document or a client's key set, fails the shared fetch as a transport failure, with the panic logged; a panic in a goroutine the transport starts itself, such as its dialer's, cannot be recovered. A repeated `Cache-Control`, `Vary` or `Date` reads as its lines joined and a repeated `Content-Type`, `Expires`, `Age`, `ETag` or `Last-Modified` by its first line, as another runtime's Node transport reads them. A leading UTF-8 byte order mark counts toward the 5 KB and is then dropped, as a browser's text decoder does. Each validation warning is logged. [Fetch tests](../plugins/cimd/fetch_test.go)

## Discover clients

`cimd.NewClientDiscovery` returns the client discovery for metadata documents, as another runtime's `createCimdClientDiscovery` does. Install it on the OAuth provider through an [extension](oauth-extensions.md#resolve-clients-through-a-discovery):

```go
discovery, err := cimd.NewClientDiscovery(cimd.Options{})
provider, err := oauthprovider.New(oauthprovider.Options{
    Extensions: []oauthprovider.Extension{{ClientDiscoveries: []oauthprovider.ClientDiscovery{discovery}}},
    // ...
})
```

Its ID is `cimd`, stored on every client it saves, it handles every `https` client ID, and it publishes `client_id_metadata_document_supported`. Each discovery owns its cache, validators and fetch budgets. A client the provider stores locally is never fetched, so a managed or registered client whose ID begins with `https://` cannot be taken over.

A validated document is cached by HTTP shared-cache rules, under `MetadataRevalidationInterval`, 60 minutes by default, which caps its lifetime and stands in for a missing one; a negative value revalidates on every resolution. `s-maxage` wins over `max-age`, which wins over `Expires`, `Age` and `Date` shorten the lifetime, an `Expires` or `Date` value is read as an HTTP date, as RFC 1123 with a numeric zone or with `UT`, `UTC`, `GMT`, `Z` or a US zone name (`EST` to `PDT`), or as RFC 3339, as another runtime's date parser reads them, and an `Expires` that does not parse, such as `0`, means already expired, as RFC 9111 says, where that parser accepts more forms and keeps the interval for a date it refuses, and `no-store`, `private` and `Vary: *` keep a document out of the cache, while `no-cache` caches it already expired. An expired document is revalidated with its `ETag` and `Last-Modified` the next time the client resolves, never in the background, and a 304 reuses it. At most `MaxCacheEntries` documents are kept, 1000 by default, the least recently used dropped first.

Concurrent resolutions of one client share one fetch, which spends the fetch budget once; a fresh cached document spends none. Each resolution then stores the document through the provider's registration rules with its own context, so none waits for another's save, and a save that fails drops its cached document and paces the client. A cached document the stored client already matches answers without a save. Another runtime also bounds how long a request waits to join a fetch and retires fetches a request abandoned, because some runtimes end a request's I/O; here a fetch runs in its own goroutine under its five-second deadline and always settles.

After a save, `OnClientCreated` runs for a new client and `OnClientRefreshed` for a replaced one, with the stored client, the previous one, the document and the request headers; an error is logged and never undoes the save. A refresh replaces the fields the document owns, clearing those it no longer lists, keeps a stored `subject_type` it omits, and never touches the server-owned settings. [Resolver tests](../plugins/cimd/resolver_test.go) · [End-to-end tests](../adapters/sqlstore/oauth_cimd_test.go)

## Serve stored clients through transient failures

By default a failed refresh refuses the request, so a short outage at a client's metadata host stops its users from signing in. `MetadataStaleIfError`, modeled on RFC 5861 stale-if-error, serves the stored client unchanged instead, with a warning, when it was last validated within that bound, at most 24 hours, and the failure is transient, as the fetch classes above say: a 500, 502, 503 or 504 answer, the five-second timeout once the host's address was resolved, or a connection failure. While it serves a stored client, the document is fetched at most once a minute, and a fetch limit's refusal serves it too within five minutes of the last transient failure. The document's cache directives do not matter here.

A terminal failure stops stale serving until a fetch succeeds, so an owner can revoke a client by removing its document: a document retrieved and refused, for any other status, a redirect, the media type, the size, invalid JSON or an invalid document, a refused or invalid client ID URL, or a document the provider refuses. An error from `AllowMetadataURL` also stops it, as in another runtime. A transport failure that retrieved nothing ends the transient record without stopping stale serving; a storage failure leaves no record but drops the cached document and paces the client; a request that ended mid-save leaves no record and keeps the document cached; a fetch limit's or a lookup limit's refusal paces nothing, and a successful fetch clears the client's pace. Only a successful save advances the stored client's `updatedAt`, a 304 revalidation included; an administrator's edit does not, so it cannot extend the bound. The records are bounded by `MaxCacheEntries`, and evicting a terminal record moves a watermark, so clients validated before it are not served stale. The same bound keeps a `private_key_jwt` client's cached `jwks_uri` keys verifying through transient failures, counted from the last successful key fetch, and through a lookup limit's refusal within five minutes of a transient one, unless a refused response came since; a failure that retrieved nothing ends the transient record, and such failures and refusals never discard the keys. [Stale tests](../plugins/cimd/stale_test.go)

## Security boundary

A document fetch is bounded to five seconds, 5 KB, JSON or `application/*+json`, and no redirects; a discovered client's key set to 64 KiB. Client ID URLs on loopback, private or reserved hosts are refused, and the default transport refuses any host that resolves to one. Tests route HTTPS `.test` origins to in-process handlers through a custom `Transport` without loosening the URL rules; a custom transport must keep the default's guarantees: one lookup, public addresses only, the address pinned, and no redirects.

## Write another discovery

A discovery for another source of client metadata implements `oauthprovider.ClientDiscovery`: a stable `ID`, stored as each client's provenance, so changing it orphans the clients it saved; `Matches`; and `Resolve`, which validates the source's metadata, turns it into an `oauthprovider.ClientMetadataDocument` and stores it through `req.Register`, or returns nil. `Resolve` runs outside any store transaction with the request's context, and `req.Existing` is the row it saved before. See [OAuth provider extensions](oauth-extensions.md#resolve-clients-through-a-discovery).
