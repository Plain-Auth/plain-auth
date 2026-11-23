import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { defaultAc } from "better-auth/plugins/organization/access";

function ok(result) {
  assert.equal(result.error, null, JSON.stringify(result.error));
  return result.data;
}

async function roleFieldClients(t, { goFixture, instrument }, mode, fields) {
  const go = await goFixture(t, ["organization-roles"], { CONFORMANCE_ROLE_FIELDS: mode });
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const options = {
    ac: defaultAc, dynamicAccessControl: { enabled: true },
    schema: { organizationRole: { additionalFields: fields } },
  };
  const baseURL = "http://reference.localhost";
  const reference = betterAuth({
    baseURL, database: db, secret: "local-conformance-0123456789-abcdefghijk",
    emailAndPassword: { enabled: true }, rateLimit: { enabled: false },
    telemetry: { enabled: false }, plugins: [organization(options)],
  });
  const connect = server => instrument(server, [organizationClient(options)]).client;
  const left = connect(go), right = connect({ baseURL, send: req => reference.handler(req) });
  const credentials = { email: "roles@example.test", password: "local-role-fields-password" };
  ok(await left.signUp.email({ ...credentials, name: "Owner" }));
  ok(await right.signIn.email(credentials));
  const org = ok(await left.organization.create({ name: "Studio", slug: "studio" }));
  return { db, scope: { organizationId: org.id }, left, right };
}

export async function compareOrganizationRoleFields(t, fixtures) {
  const fields = {
    color: { type: "string", fieldName: "display_color", required: false, defaultValue: "blue" },
    priority: { type: "number", required: false },
    enabled: { type: "boolean", required: false },
    source: { type: "string", required: false, input: false, defaultValue: "host" },
  };
  const { db, scope, left, right } = await roleFieldClients(t, fixtures, "1", fields);
  for (const [name, writer, reader] of [["Go", left, right], ["reference", right, left]]) {
    await t.test(name + " creates a role that the other implementation can edit", async () => {
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

export async function compareStructuredRoleFields(t, fixtures) {
  const fields = {
    metadata: { type: "json", fieldName: "role_metadata", required: false },
    tags: { type: "string[]", fieldName: "role_tags", required: false, defaultValue: ["review"] },
    weights: { type: "number[]", fieldName: "role_weights", required: false },
  };
  const { scope, left, right } = await roleFieldClients(t, fixtures, "structured", fields);
  for (const [name, writer, reader] of [["Go", left, right], ["reference", right, left]]) {
    await t.test(name + " exchanges JSON and typed arrays", async () => {
      const fresh = ok(await writer.organization.createRole({ ...scope, role: name, permission: {} })).roleData;
      assert.deepEqual([fresh.metadata, fresh.tags, fresh.weights], [null, ["review"], null]);
      const q = { ...scope, roleId: fresh.id };
      const metadata = { display: ["blue", null], release: { enabled: false, code: "λ" }, count: 2 };
      const changed = ok(await writer.organization.updateRole({ ...q, data: { metadata, tags: [], weights: [0, -1.75, 2.125] } })).roleData;
      assert.deepEqual([changed.metadata, changed.tags, changed.weights], [metadata, [], [0, -1.75, 2.125]]);
      const fetched = ok(await reader.organization.getRole({ query: q }));
      assert.deepEqual([fetched.metadata, fetched.tags, fetched.weights], [metadata, [], [0, -1.75, 2.125]]);
      const invalid = await reader.organization.updateRole({ ...q, data: { tags: ["ok", false, 2], metadata: { lost: true } } });
      assert.equal(invalid.error?.status, 400);
      assert.equal(invalid.error.message, "[body.data.tags.1] Invalid input: expected string, received boolean; [body.data.tags.2] Invalid input: expected string, received number");
      const retained = ok(await reader.organization.getRole({ query: q }));
      assert.deepEqual(retained.metadata, metadata);
      const cleared = ok(await reader.organization.updateRole({ ...q, data: { metadata: null, weights: [], tags: null } })).roleData;
      assert.deepEqual([cleared.metadata, cleared.tags, cleared.weights], [null, null, []]);
      const list = ok(await writer.organization.listRoles({ query: scope }));
      const row = list.find(role => role.id === fresh.id);
      assert.deepEqual([row.metadata, row.tags, row.weights], [null, null, []]);
    });
  }
}
