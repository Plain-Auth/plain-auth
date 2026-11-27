# Client ID metadata documents

The `plugins/cimd` package identifies OAuth clients by Client ID Metadata Documents ([draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)), as another runtime's cimd plugin does: a client ID that is an HTTPS URL names a JSON document with the client's metadata. [Feature checklist](parity/plugins/cimd.md)

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

`ValidationOptions.OriginBoundFields` names the origin-bound members. Nil means `post_logout_redirect_uris`; an empty, non-nil list binds none. The informative URIs are not bound by default, since an application's website often lives apart from its metadata document. A private-use redirect URI has no origin and is exempt, in `post_logout_redirect_uris` only in its reverse-domain form such as `com.example.app:/logout`, and loopback HTTP(S) redirect URIs are exempt for native apps.

A public host is a public IP address or a dotted DNS name that is not loopback, not spelled like a number, not a cloud metadata name and not under `.internal` or `.local`. Another runtime refuses only special-use addresses, `localhost` and cloud metadata names; the other refusals are kept for safety. Results are a document, warnings and an error, where another runtime returns a valid flag with an error string. [Validation tests](../plugins/cimd/validate_test.go)

## Fetch through the pinned transport

`cimd.NewTransport` fetches metadata documents and the resources their clients publish, such as a `jwks_uri`. It sends only HTTPS `GET` and `HEAD` without a body, resolves the host once, refuses the request unless every answer is a public address, and dials only those addresses, in order, so a second lookup cannot redirect it to an internal host. An IP literal is checked the same way and dialed without a lookup. The `Host` header and TLS server name stay the URL's host. Redirects come back as responses and are never followed, a protocol upgrade is refused, no proxy is used and no connection is kept. At most 16 lookups run at once on one transport, where another runtime's limit is per process; a lookup the caller abandons keeps its slot until it settles, so a slow resolver cannot pile lookups up. Another runtime leaves this transport to the host, because its fetch API cannot pin addresses; Go can, so this is the default. [Transport tests](../plugins/cimd/transport_test.go)

## Bound metadata fetches

`cimd.FetchPolicy` bounds metadata document fetches, which are refused at once with 429 `temporarily_unavailable` rather than queued. After a failed fetch, a client ID waits `MinimumFetchInterval`, one second by default, from when the failure settled; a negative value turns that off, where another runtime uses 0, since a zero duration means unset in Go. Fetches in flight are bounded by `MaxConcurrentFetches` and `MaxConcurrentFetchesPerOrigin`, 16 and 4 by default, and fetch starts in a rolling minute by `MaxFetchesPerMinute` and `MaxFetchesPerOriginPerMinute`, 120 and 30. A negative limit is refused. The records behind pacing and per-origin budgets are bounded by the cache size; only records past their interval or window are evicted, so a full table of live records refuses newcomers. Another runtime records pacing when a fetch starts and again when it settles; here it is recorded when a fetch fails, with the same effect, since concurrent fetches of one client share one fetch. [Governor tests](../plugins/cimd/governor_test.go)
