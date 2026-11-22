import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { adminClient, inferAdditionalFields } from "better-auth/client/plugins";
import { admin } from "better-auth/plugins";
import { adminAc, defaultAc, userAc } from "better-auth/plugins/admin/access";
import { userFields } from "./user-fields.mjs";

function ok(result) {
  assert.equal(result.error, null, result.error?.message);
  return result.data;
}

function visible(user, accountClass, locale) {
  assert.equal(user.accountClass, accountClass);
  assert.equal(user.locale, locale);
  assert.equal(user.count, 0);
  assert.equal(user.flag, false);
  for (const key of ["privateNote", "internalRisk", "preferred_locale"]) {
    assert.ok(!Object.hasOwn(user, key), key);
  }
}

export async function adminFields(t, { goFixture, reference, instrument }) {
  const go = await goFixture(t, ["admin"], { CONFORMANCE_ADMIN_FIELDS: "1", CONFORMANCE_USER_FIELDS: "1" });
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const roles = { admin: adminAc, user: userAc, creator: defaultAc.newRole({ user: ["create"] }) };
  const ref = await reference(t, [admin({ roles })], { database: db, user: { additionalFields: userFields } });
  const make = runtime => instrument(runtime, [adminClient(), inferAdditionalFields()]).client;
  const password = "local-admin-profile-fixture";
  for (const role of ["admin", "creator", "user"]) {
    const account = ok(await make(go).signUp.email({
      name: role, email: role + "@operator.test", password, locale: "operator",
    })).user;
    db.prepare('UPDATE "user" SET role=? WHERE id=?').run(role, account.id);
  }
  const native = await ref.api.createUser({ body: {
    name: "Native", email: "native@create.test", role: "user",
    data: { locale: "host", count: 0, flag: false, accountClass: "managed", privateNote: "concealed", internalRisk: 71 },
  } });
  visible(native.user, "managed", "host");
  for (const [runtime, peer, label] of [[ref, go, "reference"], [go, ref, "go"]]) {
    const operator = async role => {
      const client = make(runtime);
      ok(await client.signIn.email({ email: role + "@operator.test", password }));
      return client;
    };
    const manager = await operator("admin");
    const creator = await operator("creator");
    const ordinary = await operator("user");
    const target = {
      name: "Target", email: label + "@created.test", password,
      data: { locale: "target", count: 0, flag: false, privateNote: "stored-private", internalRisk: 17, accountClass: "browser-value" },
    };
    assert.equal((await make(runtime).admin.createUser(target)).error.status, 401);
    assert.equal((await ordinary.admin.createUser(target)).error.status, 403);
    for (const protectedData of [{ role: "admin" }, { banned: true }]) {
      const denied = await creator.admin.createUser({ ...target, data: { ...target.data, ...protectedData } });
      assert.equal(denied.error.status, 403);
    }
    assert.equal(db.prepare('SELECT count(*) AS n FROM "user" WHERE email=?').get(target.email).n, 0);
    const profile = ok(await manager.admin.createUser({
      ...target, role: "user", data: { ...target.data, role: "admin", name: "ignored", email: "other@example.test" },
    })).user;
    // The Go host keeps application-owned overrides on its trusted native API.
    const accountClass = runtime === ref ? "browser-value" : "standard";
    visible(profile, accountClass, "target");
    assert.equal(profile.role, "user");
    assert.equal(profile.email, target.email);
    assert.equal(profile.name, "Target");
    const saved = db.prepare('SELECT preferred_locale,accountClass,privateNote,internalRisk FROM "user" WHERE id=?').get(profile.id);
    assert.deepEqual({ ...saved }, {
      preferred_locale: "target", accountClass, privateNote: "stored-private", internalRisk: runtime === ref ? 17 : 9,
    });
    visible(ok(await manager.admin.getUser({ query: { id: profile.id } })), accountClass, "target");
    const list = ok(await manager.admin.listUsers({ query: { searchField: "email", searchValue: target.email, searchOperator: "contains" } }));
    visible(list.users.find(u => u.id === profile.id), accountClass, "target");
    visible(ok(await make(peer).signIn.email({ email: target.email, password })).user, accountClass, "target");
    const limited = ok(await creator.admin.createUser({
      name: "Limited", email: label + "@limited.test", data: { locale: "limited" },
    })).user;
    assert.equal(limited.locale, "limited");
    assert.equal(limited.role, "user");
  }
}
