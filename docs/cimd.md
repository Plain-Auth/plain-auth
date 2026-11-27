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
