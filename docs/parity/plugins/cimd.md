# Client ID metadata documents

[Feature index](../README.md)

## Interfaces

- [ ] Client ID metadata documents endpoints, types and options
  - [ ] `createCimdClientDiscovery`
  - [ ] `cimd`
  - [ ] `fetchClientMetadataResource`
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
  - [ ] `CimdMetadataValidationOptions`
    - [ ] `originBoundFields`
    - [ ] `metadataProfile`
  - [ ] `CimdMetadataValidationResult`
  - [ ] `isCimdClientIdUrlCandidate`
  - [ ] `validateCimdMetadata`
  - [ ] `validateClientIdUrl`

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
    - [ ] Origin-bound fields
  - [ ] Draft-02 validation
  - [ ] Key set origin
  - [ ] Persistence and refresh
    - [ ] Transient refresh failures
  - [ ] Security boundary
  - [ ] Explicit discovery composition
