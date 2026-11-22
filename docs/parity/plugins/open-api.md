# OpenAPI

[Feature index](../README.md)

## Interfaces

- [ ] OpenAPI endpoints, types and options
  - [ ] `FieldSchema`
  - [ ] `OpenAPIModelSchema`
  - [ ] `Path`
  - [ ] `generator`
  - [ ] `OpenAPISchema`
  - [ ] `OpenAPIParameter`
  - [ ] `GET /open-api/generate-schema`
    - [x] Describe enterprise provider management, redacted reads, browser sign-in and both bound callback routes against the configured SQL handler ([test](../../../plugins/openapi/sso_directory_test.go#L24))
    - [x] Describe the enabled enterprise DNS management inputs, outputs and session credentials ([test](../../../plugins/openapi/sso_domain_test.go#L28))
    - [x] Publish declared success codes, empty 204 responses and explicit operation overrides while preserving redirects ([test](../../../plugins/openapi/endpoint_status_test.go#L12))
    - [x] Serve the mounted versioned JSON document and match required fields for core and username operations ([test](../../../conformance/openapi-contract.mjs#L48))
    - [x] Expose the actual response fields, cookie name, optional bearer scheme and custom operation metadata ([test](../../../plugins/openapi/openapi_test.go#L76))
    - [x] Resolve every local schema reference and suppress unavailable routes for a configured SQL-backed instance ([test](../../../plugins/openapi/profile_test.go#L136))
    - [x] Describe the public user model and writable registration fields across owner updates, administrative creation and first OTP sign-in ([test](../../../plugins/openapi/user_fields_test.go#L21))
    - [x] Compare both live schema endpoints and verify required signup inputs, partial profile updates and hidden response fields ([test](../../../conformance/openapi-contract.mjs#L64))
  - [ ] `GET /reference (configurable)`
    - [x] Filter a local interactive reference in headless Chrome under its nonce policy ([test](../../../plugins/openapi/openapi_test.go#L231))
  - [ ] `OpenAPIOptions`
    - [ ] `path`
      - [x] Serve the page at an application-selected path beneath the configured auth mount ([test](../../../plugins/openapi/openapi_test.go#L177))
    - [ ] `disableDefaultReference`
      - [x] Disable the reference page while continuing to serve its JSON schema ([test](../../../plugins/openapi/openapi_test.go#L184))
    - [ ] `theme`
      - [x] Apply a configured theme in the rendered browser page ([test](../../../plugins/openapi/openapi_test.go#L231))
    - [ ] `nonce`
      - [x] Apply the configured nonce to inline scripts and styles and send the matching CSP ([test](../../../plugins/openapi/openapi_test.go#L177))
  - [ ] `openAPI`

## Open API

- [ ] Open API
  - [ ] Usage
    - [ ] Generated Schema
      - [x] Return the public document from its mounted HTTP endpoint ([test](../../../conformance/openapi-contract.mjs#L28))
    - [ ] Using Scalar with Multiple Sources
  - [ ] Configuration
    - [ ] `path`
    - [ ] `disableDefaultReference`
    - [ ] `theme`
    - [ ] `nonce`
