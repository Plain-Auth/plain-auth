import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { defaultAc } from "better-auth/plugins/organization/access";

export async function compareOrganizationRoleFields(t, { goFixture, instrument }) {
  const go = await goFixture(t, ["organization-roles"], { CONFORMANCE_ROLE_FIELDS: "1" });
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const fields = {
    color: { type: "string", fieldName: "display_color", required: false, defaultValue: "blue" },
    priority: { type: "number", required: false },
    enabled: { type: "boolean", required: false },
    source: { type: "string", required: false, input: false, defaultValue: "host" },
  };
  const options = { ac: defaultAc, dynamicAccessControl: { enabled: true }, schema: { organizationRole: { additionalFields: fields } } };
  const baseURL = "http://reference.localhost";
  const ref = betterAuth({ baseURL, database: db, secret: "local-conformance-0123456789-abcdefghijk",
    emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, telemetry: { enabled: false }, plugins: [organization(options)] });
  const client = server => instrument(server, [organizationClient(options)]).client;
  const left = client(go), right = client({ baseURL, send: request => ref.handler(request) });
  function ok(result) {
    assert.equal(result.error, null, JSON.stringify(result.error));
    return result.data;
  }
  const credentials = { email: "roles@example.test", password: "local-role-fields-password" };
  ok(await left.signUp.email({ ...credentials, name: "Owner" }));
  ok(await right.signIn.email(credentials));
  const org = ok(await left.organization.create({ name: "Journal", slug: "journal" }));
  for (const [name, writer, reader] of [["Go", left, right], ["reference", right, left]]) {
    await t.test(name + " creates a role that the other implementation can edit", async () => {
      const scope = { organizationId: org.id };
      const create = (role, extra) => writer.organization.createRole({ ...scope, role, permission: {}, ...extra });
      const defaults = ok(await create(name + "-defaults", {})).roleData;
      assert.deepEqual([defaults.color, defaults.source, defaults.priority, defaults.enabled], ["blue", "host", null, null]);
      const created = ok(await create(name + "-editor", { additionalFields: {
        color: null, priority: 0, enabled: false, source: "client", unknown: true,
      } })).roleData;
      const selector = { ...scope, roleId: created.id };
      assert.deepEqual([created.color, created.priority, created.enabled, created.source], [null, 0, false, "host"]);
      assert.equal(Object.hasOwn(created, "unknown"), false);
      assert.equal(Object.hasOwn(created, "display_color"), false);
      const loaded = ok(await reader.organization.getRole({ query: selector }));
      assert.deepEqual(loaded, created);
      const bad = await reader.organization.updateRole({ ...selector, data: { color: "never saved", enabled: "yes" } });
      assert.equal(bad.error?.status, 400);
      assert.equal(bad.error.code, "VALIDATION_ERROR");
      assert.equal(bad.error.message, "[body.data.enabled] Invalid input: expected boolean, received string");
      const changed = ok(await reader.organization.updateRole({ ...selector, data: { color: "amber", source: "client", unknown: true } })).roleData;
      assert.deepEqual([changed.color, changed.priority, changed.enabled, changed.source], ["amber", 0, false, "host"]);
      const rows = ok(await writer.organization.listRoles({ query: scope }));
      const row = rows.find(item => item.id === created.id);
      assert.deepEqual([row.color, row.priority, row.enabled, row.source], ["amber", 0, false, "host"]);
      assert.equal(db.prepare('select display_color from organizationRole where id=?').get(created.id).display_color, "amber");
    });
  }
}
