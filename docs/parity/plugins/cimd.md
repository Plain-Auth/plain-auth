# Client ID metadata documents

[Feature index](../README.md)

## Interfaces

- [ ] Client ID metadata documents endpoints, types and options
  - [ ] `createCimdClientDiscovery`
  - [ ] `cimd`
  - [ ] `fetchClientMetadataResource`
    - [x] Fetch metadata resources over HTTPS GET and HEAD only, pinning the vetted public addresses of one lookup, returning redirects unfollowed, refusing upgrades and bounding concurrent lookups ([test](../../../plugins/cimd/transport_test.go#L55))
  - [ ] `CimdClientCreatedEvent`
  - [ ] `CimdClientRefreshedEvent`
  - [ ] `CimdMetadataFetchPolicy`
  - [ ] `CimdMetadataProfile`
  - [ ] `CimdOptions`
    - [ ] `fetchClientMetadataResource`
    - [ ] `metadataProfile`
    - [ ] `metadataRevalidationInterval`
    - [ ] `metadataStaleIfError`
    - [ ] `metadataFetchPolicy`
    - [ ] `maxCacheEntries`
    - [ ] `originBoundFields`
    - [ ] `isMetadataDocumentUrlAllowed`
    - [ ] `isCrossOriginJwksUriAllowed`
    - [ ] `onClientCreated`
    - [ ] `onClientRefreshed`
  - [x] `CimdMetadataValidationOptions` ([test](../../../plugins/cimd/validate_test.go#L65))
    - [x] Configure origin-bound members and the protocol profile of document validation ([test](../../../plugins/cimd/validate_test.go#L65))
    - [x] `originBoundFields` ([test](../../../plugins/cimd/validate_test.go#L129))
      - [x] Bind post_logout_redirect_uris by default, a custom list instead, or none with an empty list, exempting private-use and loopback redirect URIs ([test](../../../plugins/cimd/validate_test.go#L129))
    - [x] `metadataProfile` ([test](../../../plugins/cimd/validate_test.go#L78))
      - [x] Require client_name and redirect_uris under the MCP 2026-07-28 profile and neither otherwise ([test](../../../plugins/cimd/validate_test.go#L78))
  - [x] `CimdMetadataValidationResult` ([test](../../../plugins/cimd/validate_test.go#L65))
    - [x] Return the validated document, warnings and an error, where another runtime returns a valid flag, as a documented deviation ([test](../../../plugins/cimd/validate_test.go#L65))
  - [x] `isCimdClientIdUrlCandidate` ([test](../../../plugins/cimd/validate_test.go#L9))
    - [x] Tell an https client ID URL from other client IDs without any lookup, including the forms without // that are refused later ([test](../../../plugins/cimd/validate_test.go#L9))
  - [x] `validateCimdMetadata` ([test](../../../plugins/cimd/validate_test.go#L65))
    - [x] Validate a metadata document in order: object, server-owned members in document order, registration rules, client_id, profile, back-channel fields, auth method, keys, redirect URIs, informative URIs and origin-bound members, stripping unknown members and defaulting the method to none ([test](../../../plugins/cimd/validate_test.go#L65))
  - [x] `validateClientIdUrl` ([test](../../../plugins/cimd/validate_test.go#L21))
    - [x] Refuse dot segments, fragments, invalid URLs, other schemes, missing authority or path, credentials and non-public hosts in a client ID URL, in order ([test](../../../plugins/cimd/validate_test.go#L21))

## Client ID Metadata Document (CIMD)

- [ ] Client ID Metadata Document (CIMD)
  - [ ] MCP configuration
  - [ ] Configuration
    - [ ] `cimdOptionsType.fetchClientMetadataResource`
    - [ ] `cimdOptionsType.metadataProfile`
    - [ ] `cimdOptionsType.metadataRevalidationInterval`
    - [ ] `cimdOptionsType.metadataStaleIfError`
    - [ ] `cimdOptionsType.maxCacheEntries`
    - [ ] `cimdOptionsType.metadataFetchPolicy`
    - [ ] `cimdOptionsType.originBoundFields`
    - [ ] `cimdOptionsType.isMetadataDocumentUrlAllowed`
    - [ ] `cimdOptionsType.isCrossOriginJwksUriAllowed`
    - [ ] `cimdOptionsType.onClientCreated`
    - [ ] `cimdOptionsType.onClientRefreshed`
    - [x] Origin-bound fields ([test](../../../plugins/cimd/validate_test.go#L129))
      - [x] Bind only post_logout_redirect_uris by default, leaving informative URIs unbound but credential-free HTTP(S) on public hosts ([test](../../../plugins/cimd/validate_test.go#L129))
  - [ ] Draft-02 validation
    - [x] Require client_id to equal the URL exactly, refuse unsafe client ID URLs with warnings for a root path and a query, and leave client_name and redirect_uris optional outside the MCP profile ([test](../../../plugins/cimd/validate_test.go#L65))
  - [ ] Key set origin
  - [ ] Persistence and refresh
    - [ ] Transient refresh failures
  - [ ] Security boundary
  - [ ] Explicit discovery composition
