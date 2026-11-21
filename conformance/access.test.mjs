import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createAccessControl } from "better-auth/plugins/access";

test("role permission decisions match the shared Go cases", () => {
  const control = createAccessControl({ project: ["create", "edit", "delete"], audit: ["read", "edit"] });
  const role = control.newRole({ project: ["create", "edit"], audit: ["read"] });
  const cases = JSON.parse(readFileSync(new URL("../plugins/access/testdata/decisions.json", import.meta.url), "utf8"));
  for (const example of cases) {
    const request = Object.fromEntries((example.requirements ?? []).map(({ resource, actions, match }) => [
      resource, match === 1 ? { actions, connector: "OR" } : actions,
    ]));
    assert.equal(role.authorize(request, example.match === 1 ? "OR" : "AND").success, example.allowed, example.case);
  }
});
