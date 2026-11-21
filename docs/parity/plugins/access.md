# Access

[Feature index](../README.md)

## Interfaces

- [ ] Access endpoints, types and options
  - [ ] `ArrayElement`
  - [ ] `SubArray`
  - [ ] `Subset`
  - [ ] `Statements`
  - [ ] `RoleStatements`
  - [ ] `RoleInput`
  - [ ] `ExactRoleStatements`
  - [ ] `AccessControl`
    - [x] Validate role grants against the catalog and isolate both from later changes to their input ([test](../../../plugins/access/access_test.go#L42))
  - [ ] `RoleAuthorizeRequest`
    - [x] Keep resource-level and request-level permission checks independent ([test](../../../plugins/access/access_test.go#L12))
  - [ ] `Role`
    - [x] Check all or any requested actions across resources and reject empty or ungranted requests ([test](../../../plugins/access/access_test.go#L12))
    - [x] Compare nested permission decisions with the pinned client using the same test cases ([test](../../../conformance/access.test.mjs#L6))
