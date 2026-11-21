# Custom session

[Feature index](../README.md)

## Interfaces

- [ ] Custom session endpoints, types and options
  - [ ] `customSessionClient`
  - [ ] `GET /get-session`
    - [x] Project a verified session, preserve refresh headers, retain anonymous null and redact application errors ([test](../../../plugins/customsession/customsession_test.go#L18))
    - [x] Read the same custom payload through the official JavaScript client ([test](../../../conformance/core.test.mjs#L393))
  - [ ] `CustomSessionPluginOptions`
    - [x] `shouldMutateListDeviceSessionsEndpoint` ([test](../../../conformance/core.test.mjs#L545))
      - [x] Compare both opt-in and default device-list projections with the public browser client ([test](../../../conformance/core.test.mjs#L545))
  - [ ] `customSession`
