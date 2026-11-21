# Multi session

[Feature index](../README.md)

## Interfaces

- [ ] Multi session endpoints, types and options
  - [ ] `multiSessionClient`
    - [x] Use the public browser client to list, select, revoke, and sign out across independent cookie jars ([test](../../../conformance/core.test.mjs#L513))
  - [ ] `GET /multi-session/list-device-sessions`
    - [x] List live accounts from this browser, including when the primary cookie is missing ([test](../../../plugins/multisession/multisession_test.go#L160))
    - [x] Remove surplus entries after simultaneous browser logins ([test](../../../plugins/multisession/multisession_test.go#L311))
  - [ ] `POST /multi-session/set-active`
    - [x] Preserve browser-only persistence when a remembered account becomes active ([test](../../../plugins/multisession/multisession_test.go#L141))
    - [x] Require the signed cookie and reject expired or mismatched credentials ([test](../../../plugins/multisession/multisession_test.go#L177))
  - [ ] `POST /multi-session/revoke`
    - [x] Authorize revocation transactionally across independent database connections ([test](../../../adapters/sqlstore/multisession_test.go#L85))
    - [x] Use the public browser client to list, select, revoke, and sign out across independent cookie jars ([test](../../../conformance/core.test.mjs#L513))
  - [ ] `MultiSessionConfig`
    - [x] Remember five accounts by default while allowing another account to sign in ([test](../../../plugins/multisession/multisession_test.go#L283))
    - [x] Honor a zero limit and reject negative limits ([test](../../../plugins/multisession/multisession_test.go#L243))
  - [ ] `multiSession`
    - [x] Revoke remembered logins on sign-out and preserve an independent browser session ([test](../../../plugins/multisession/multisession_test.go#L231))

## Multi Session

- [ ] Multi Session
  - [ ] Usage
    - [ ] List all device sessions
      - [x] List live accounts from this browser, including when the primary cookie is missing ([test](../../../plugins/multisession/multisession_test.go#L160))
      - [ ] `GET /multi-session/list-device-sessions`
    - [ ] Set active session
      - [x] Preserve browser-only persistence when a remembered account becomes active ([test](../../../plugins/multisession/multisession_test.go#L141))
      - [ ] `POST /multi-session/set-active`
        - [ ] Parameter `sessionToken`
    - [ ] Revoke a session
      - [x] Authorize revocation transactionally across independent database connections ([test](../../../adapters/sqlstore/multisession_test.go#L85))
      - [ ] `POST /multi-session/revoke`
        - [ ] Parameter `sessionToken`
    - [ ] Signout and Revoke all sessions
      - [x] Revoke remembered logins on sign-out and preserve an independent browser session ([test](../../../plugins/multisession/multisession_test.go#L231))
    - [ ] Max Sessions
      - [x] Remember five accounts by default while allowing another account to sign in ([test](../../../plugins/multisession/multisession_test.go#L283))
