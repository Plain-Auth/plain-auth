# Anonymous

[Feature index](../README.md)

## Interfaces

- [ ] Anonymous endpoints, types and options
  - [ ] `anonymousClient`
  - [ ] `POST /sign-in/anonymous`
  - [ ] `POST /delete-anonymous-user`
  - [ ] `anonymous`
  - [ ] `AnonymousSession`
  - [ ] `UserWithAnonymous`
  - [ ] `AnonymousOptions`
    - [ ] `emailDomainName`
    - [ ] `onLinkAccount`
    - [ ] `disableDeleteAnonymousUser`
    - [ ] `generateName`
    - [ ] `generateRandomEmail`
    - [ ] `schema`

## Anonymous

- [ ] Anonymous
  - [ ] Usage
    - [ ] Sign In Anonymously
      - [ ] `POST /sign-in/anonymous`
    - [ ] Link Account
    - [ ] Delete Anonymous User
      - [ ] `POST /delete-anonymous-user`
      - [ ] Notes:
  - [ ] Options
    - [ ] `emailDomainName`
    - [ ] `generateRandomEmail`
      - [ ] Notes:
    - [ ] `onLinkAccount`
    - [ ] `disableDeleteAnonymousUser`
    - [ ] `generateName`
  - [ ] Schema
    - [x] Generate the canonical columns on SQLite, PostgreSQL and MySQL, including combined plugin selections ([test](../../../conformance/schema.test.mjs#L66))
    - [ ] `anonymousUserTableFields.isAnonymous`
