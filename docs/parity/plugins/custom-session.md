# Custom session

[Feature index](../README.md)

## Interfaces

- [ ] Custom session endpoints, types and options
  - [x] `customSessionClient` ([test](../../../conformance/custom-session-types.mts#L26))
    - [x] Read an application-defined response through the JavaScript projection client on both runtimes ([test](../../../conformance/core.test.mjs#L431))
    - [x] Infer the configured JavaScript response type and reject access to a field the projection omits ([test](../../../conformance/custom-session-types.mts#L26))
    - [x] Preserve application projection types alongside client-inferred additional user fields ([test](../../../conformance/custom-session-types.mts#L39))
  - [ ] `GET /get-session`
    - [x] Project a verified session, preserve refresh headers, retain anonymous null and redact application errors ([test](../../../plugins/customsession/customsession_test.go#L18))
    - [x] Read the same custom payload through the official JavaScript client ([test](../../../conformance/core.test.mjs#L427))
    - [x] Decode a nested Go session view and preserve the signed session cookie on refresh ([test](../../../client/session_view_test.go#L103))
    - [x] Expose only GET with the projection installed and retain deferred POST on the standard session endpoint ([test](../../../plugins/customsession/customsession_test.go#L222))
    - [x] Forward individual cookies and authoritative cache headers after the projection returns ([test](../../../conformance/custom-session-contract.mjs#L76))
    - [x] Propagate SQL lookup failures and discard callback headers and cookies on error ([test](../../../conformance/custom-session-contract.mjs#L98))
    - [x] Clear stale cache chunks and expired credentials during database-backed reads ([test](../../../conformance/custom-session-contract.mjs#L107))
    - [x] Expose deferred refresh state and accept the released query string coercion rules ([test](../../../conformance/custom-session-contract.mjs#L65))
    - [x] Omit disabled flags and suppress renewal on an explicitly non-refreshing native client read ([test](../../../client/session_view_test.go#L185))
    - [x] Project another runtime’s compact browser snapshot and compare it with a fresh deferred session result ([test](../../../conformance/session-cache-compact.mjs#L127))
  - [x] `CustomSessionPluginOptions` ([test](../../../conformance/custom-session-types.mts#L7))
    - [x] Verify that the public options type exposes only the tested device-list setting ([test](../../../conformance/custom-session-types.mts#L7))
    - [x] `shouldMutateListDeviceSessionsEndpoint` ([test](../../../conformance/core.test.mjs#L592))
      - [x] Compare both opt-in and default device-list projections with the public browser client ([test](../../../conformance/core.test.mjs#L592))
      - [x] Decode nested remembered-account views in Go and discard all results when one projection fails ([test](../../../client/session_view_test.go#L134))
      - [x] Filter remembered accounts through the current SQL ban and delegation policy after a live administrative migration ([test](../../../adapters/sqlstore/custom_session_test.go#L109))
  - [ ] `customSession`
    - [x] Reject ambiguous or missing callback registrations and isolate concurrent application projections ([test](../../../plugins/customsession/customsession_test.go#L106))
