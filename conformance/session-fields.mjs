import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { inferAdditionalFields } from "better-auth/client/plugins";

const fields = {
  locale: { type: "string", required: true, fieldName: "preferred_locale", defaultValue: "en" },
  count: { type: "number", required: false, defaultValue: 4 },
  flag: { type: "boolean", required: false },
  deviceClass: { type: "string", required: false, input: false, defaultValue: "browser" },
  privateNote: { type: "string", required: false, returned: false },
  internalRisk: { type: "number", required: false, input: false, returned: false, defaultValue: 9 },
};

function sessionColumns(database) {
  const names = new Set(Object.values(fields).map(f => f.fieldName));
  return database.prepare('pragma table_info("session")').all()
    .filter(row => Object.hasOwn(fields, row.name) || names.has(row.name))
    .map(({ name, type, notnull, dflt_value }) => ({ name, type: type.toLowerCase(), notnull, dflt_value }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export async function compareSessionFields(t, { reference, goFixture, instrument }) {
  const refDatabase = new DatabaseSync(":memory:");
  t.after(() => refDatabase.close());
  await reference(t, [], { database: refDatabase, session: { additionalFields: fields } });
  const go = await goFixture(t, [], { CONFORMANCE_SESSION_FIELDS: "1" });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  assert.deepEqual(sessionColumns(database), sessionColumns(refDatabase));

  const ref = await reference(t, [], { database, session: { additionalFields: fields } });
  for (const [issuer, other, prefix] of [[ref, go, "ts"], [go, ref, "go"]]) {
    const plugins = [inferAdditionalFields()];
    const client = instrument(issuer, plugins).client;
    const credentials = { email: prefix + "@fields.test", password: "local field fixture" };
    const account = await client.signUp.email({ ...credentials, name: "Fields" });
    assert.equal(account.error, null);
    const signIn = await issuer.send(new Request(issuer.baseURL + "/api/auth/sign-in/email", {
      method: "POST",
      headers: { "content-type": "application/json", origin: issuer.baseURL },
      body: JSON.stringify(credentials),
    }));
    const cookie = signIn.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
    assert.ok(cookie);
    const consumer = instrument({
      ...other,
      send(request) {
        if (!request.headers.has("cookie")) request.headers.set("cookie", cookie);
        return other.send(request);
      },
    }, plugins).client;

    const saved = await consumer.getSession();
    assert.equal(saved.error, null);
    const snapshot = saved.data.session;
    assert.equal(snapshot.locale, "en");
    assert.equal(snapshot.count, 4);
    assert.equal(snapshot.flag, null);
    assert.equal(snapshot.deviceClass, "browser");
    for (const key of ["preferred_locale", "privateNote", "internalRisk"]) {
      assert.ok(!(key in snapshot), key);
    }
    const update = await consumer.updateSession({
      locale: "es", count: 7, flag: false, privateNote: "persist privately", userId: "another",
    });
    assert.equal(update.error, null);
    assert.equal(update.data.session.userId, account.data.user.id);
    assert.equal(update.data.session.count, 7);
    assert.ok(!("privateNote" in update.data.session));
    assert.ok(!("internalRisk" in update.data.session));
    const physical = database.prepare(
      "SELECT preferred_locale, count, flag, privateNote, internalRisk FROM session WHERE id = ?",
    ).get(snapshot.id);
    assert.deepEqual({ ...physical }, {
      preferred_locale: "es", count: 7, flag: 0, privateNote: "persist privately", internalRisk: 9,
    });
    const current = await consumer.getSession();
    assert.equal(current.data.session.locale, "es");
    assert.equal(current.data.session.flag, false);
    const denied = await consumer.updateSession({ deviceClass: "untrusted" });
    assert.equal(denied.error?.code, "FIELD_NOT_ALLOWED");
    const untouched = await consumer.updateSession({ id: "another", userId: "another" });
    assert.equal(untouched.error?.status, 400);
    const foreignRedirect = await consumer.updateSession({ locale: "unused", callbackURL: "https://outside.example.test" });
    assert.equal(foreignRedirect.error?.status, 403);
    const list = await consumer.listSessions();
    assert.equal(list.error, null);
    const entry = list.data.find(v => v.id === snapshot.id);
    assert.equal(entry.locale, "es");
    assert.ok(!("privateNote" in entry));
    assert.equal((await consumer.updateSession({ flag: null })).data.session.flag, null);
    const guest = instrument(other, plugins).client;
    assert.equal((await guest.updateSession({ locale: "guest" })).error?.status, 401);
    database.prepare("DELETE FROM session WHERE id = ?").run(snapshot.id);
    assert.equal((await consumer.updateSession({ locale: "revoked" })).error?.status, 401);
  }
}

export { fields as sessionFields };
