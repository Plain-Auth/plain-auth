# Custom session

[Feature index](../README.md)

## Interfaces

- [ ] Custom session endpoints, types and options
  - [x] `customSessionClient` ([test](../../../conformance/custom-session-types.mts#L26))
    - [x] Read an application-defined response through the JavaScript projection client on both runtimes ([test](../../../conformance/core.test.mjs#L426))
    - [x] Infer the configured JavaScript response type and reject access to a field the projection omits ([test](../../../conformance/custom-session-types.mts#L26))
  - [ ] `GET /get-session`
    - [x] Project a verified session, preserve refresh headers, retain anonymous null and redact application errors ([test](../../../plugins/customsession/customsession_test.go#L18))
    - [x] Read the same custom payload through the official JavaScript client ([test](../../../conformance/core.test.mjs#L422))
    - [x] Decode a nested Go session view and preserve the signed session cookie on refresh ([test](../../../client/session_view_test.go#L103))
  - [x] `CustomSessionPluginOptions` ([test](../../../conformance/custom-session-types.mts#L7))
    - [x] Verify that the public options type exposes only the tested device-list setting ([test](../../../conformance/custom-session-types.mts#L7))
    - [x] `shouldMutateListDeviceSessionsEndpoint` ([test](../../../conformance/core.test.mjs#L574))
      - [x] Compare both opt-in and default device-list projections with the public browser client ([test](../../../conformance/core.test.mjs#L574))
      - [x] Decode nested remembered-account views in Go and discard all results when one projection fails ([test](../../../client/session_view_test.go#L134))
  - [ ] `customSession`
