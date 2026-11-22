import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { inferAdditionalFields } from "better-auth/client/plugins";

const fields = {
  locale: { type: "string", required: true, fieldName: "preferred_locale" },
  count: { type: "number", required: false, defaultValue: 4 },
  flag: { type: "boolean", required: false },
  accountClass: { type: "string", required: false, input: false, defaultValue: "standard" },
  privateNote: { type: "string", required: false, returned: false },
  internalRisk: { type: "number", required: false, input: false, returned: false, defaultValue: 9 },
};

function geometry(db) {
  const names = Object.entries(fields).map(([name, f]) => f.fieldName || name);
  return db.prepare('pragma table_info("user")').all().filter(row => names.includes(row.name))
    .map(({ name, type, notnull, dflt_value }) => [name, type.toLowerCase(), notnull, dflt_value])
    .sort((a, b) => a[0].localeCompare(b[0]));
}

function visible(user, locale, count, flag) {
  assert.equal(user.locale, locale);
  assert.equal(user.count, count);
  assert.equal(user.flag, flag);
  assert.equal(user.accountClass, "standard");
  for (const key of ["preferred_locale", "privateNote", "internalRisk"]) assert.ok(!(key in user), key);
}

export async function compareUserFields(t, { reference, goFixture, instrument }) {
  const refSchema = new DatabaseSync(":memory:");
  t.after(() => refSchema.close());
  await reference(t, [], { database: refSchema, user: { additionalFields: fields } });
  const go = await goFixture(t, [], { CONFORMANCE_USER_FIELDS: "1" });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  assert.deepEqual(geometry(database), geometry(refSchema));
  const ref = await reference(t, [], { database, user: { additionalFields: fields } });
  for (const [issuer, other, name] of [[go, ref, "go"], [ref, go, "ts"]]) {
    const credential = { name, email: name + "@profile.test", password: "test credential" };
    const make = server => instrument(server, [inferAdditionalFields()]).client;
    const actor = make(issuer);
    const missing = await actor.signUp.email(credential);
    assert.equal(missing.error?.code, "MISSING_FIELD");
    const result = await actor.signUp.email({ ...credential, locale: "en", flag: false, privateNote: "first", accountClass: "override" });
    assert.equal(result.error, null);
    visible(result.data.user, "en", 4, false);
    const consumer = make(other);
    const signin = await consumer.signIn.email(credential);
    assert.equal(signin.error, null);
    visible(signin.data.user, "en", 4, false);
    const update = await consumer.updateUser({ name: "Changed", locale: "es", count: 0, privateNote: "new", flag: null });
    assert.equal(update.error, null);
    const read = await actor.getSession();
    assert.equal(read.error, null);
    assert.equal(read.data.user.name, "Changed");
    visible(read.data.user, "es", 0, null);
    assert.deepEqual({ ...database.prepare('SELECT preferred_locale, count, flag, privateNote, internalRisk, accountClass FROM "user" WHERE id = ?').get(result.data.user.id) },
      { preferred_locale: "es", count: 0, flag: null, privateNote: "new", internalRisk: 9, accountClass: "standard" });
    for (const empty of [false, 0, "", null]) {
      const ignored = await consumer.updateUser({ accountClass: empty, locale: "es" });
      assert.equal(ignored.error, null);
      visible((await actor.getSession()).data.user, "es", 0, null);
    }
    const refused = await consumer.updateUser({ accountClass: "untrusted", locale: "discard" });
    assert.equal(refused.error?.code, "FIELD_NOT_ALLOWED");
    visible((await actor.getSession()).data.user, "es", 0, null);
  }
}
