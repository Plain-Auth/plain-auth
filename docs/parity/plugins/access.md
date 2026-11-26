# Access

[Feature index](../README.md)

## Interfaces

- [ ] Access endpoints, types and options
  - [ ] `role`
    - [x] Check all or any requested actions across resources and reject empty or ungranted requests ([test](../../../plugins/access/access_test.go#L12))
    - [x] Compare nested permission decisions with the pinned client using the same test cases ([test](../../../conformance/access.test.mjs#L6))
  - [x] `createAccessControl` ([test](../../../plugins/organization/default_roles_test.go#L31))
    - [x] Validate role grants against the catalog and isolate both from later changes to their input ([test](../../../plugins/access/access_test.go#L42))
    - [x] HasAction reports each action in the organization's default catalog, and HasResource and HasAction reject a resource or action outside it ([test](../../../plugins/organization/default_roles_test.go#L31))
  - [x] `AuthorizeResponse` ([test](../../../plugins/access/access_test.go#L35))
    - [x] Authorize returns nil for an allowed request and an error matching access.ErrDenied for a denied one, across the shared decision cases ([test](../../../plugins/access/access_test.go#L35))
  - `ArrayElement` — *not applicable: TypeScript type*
  - `SubArray` — *not applicable: TypeScript type*
  - `Subset` — *not applicable: TypeScript type*
  - [x] `Statements` ([test](../../../plugins/access/access_test.go#L54))
    - [x] access.New and NewRole copy their Statements maps, so later changes to the caller's slices leave the catalog and role unchanged ([test](../../../plugins/access/access_test.go#L54))
  - [x] `RoleStatements` ([test](../../../plugins/access/access_test.go#L58))
    - [x] NewRole refuses a grant naming an action outside the catalog or a resource the catalog lacks ([test](../../../plugins/access/access_test.go#L58))
  - [x] `RoleInput` ([test](../../../plugins/access/access_test.go#L58))
    - [x] NewRole refuses role grants with a resource or action the catalog does not declare ([test](../../../plugins/access/access_test.go#L58))
  - `ExactRoleStatements` — *not applicable: TypeScript type*
  - [x] `AccessControl` ([test](../../../plugins/organization/default_roles_test.go#L31))
    - [x] Validate role grants against the catalog and isolate both from later changes to their input ([test](../../../plugins/access/access_test.go#L42))
    - [x] HasAction reports each action in the organization's default catalog, and HasResource and HasAction reject a resource or action outside it ([test](../../../plugins/organization/default_roles_test.go#L31))
  - [x] `RoleAuthorizeRequest` ([test](../../../conformance/access.test.mjs#L12))
    - [x] Keep resource-level and request-level permission checks independent ([test](../../../plugins/access/access_test.go#L12))
    - [x] Map each shared Go case to the other runtime's plain action list, or to its actions with the OR connector, and get the same decision ([test](../../../conformance/access.test.mjs#L12))
  - [ ] `Role`
    - [x] Check all or any requested actions across resources and reject empty or ungranted requests ([test](../../../plugins/access/access_test.go#L12))
    - [x] Compare nested permission decisions with the pinned client using the same test cases ([test](../../../conformance/access.test.mjs#L6))
