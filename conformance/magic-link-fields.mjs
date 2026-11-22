import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { inferAdditionalFields, magicLinkClient } from "better-auth/client/plugins";
import { magicLink } from "better-auth/plugins";
import { userFields } from "./user-fields.mjs";
import { sessionFields } from "./session-fields.mjs";

export async function magicLinkFields(t, {reference, goFixture, instrument}) {
  for (const required of [false, true]) {
    await t.test(required ? "required field without default" : "static registration defaults", async t => {
      const go = await goFixture(t, [], {
        CONFORMANCE_MAILBOX: "1", CONFORMANCE_USER_FIELDS: required ? "1" : "magic-defaults", CONFORMANCE_SESSION_FIELDS: "1",
      });
      const db = new DatabaseSync(go.databasePath);
      t.after(() => db.close());
      let sent;
      const ref = await reference(t, [magicLink({
        storeToken: "hashed", sendMagicLink: async message => { sent = message; },
      })], {
        database: db, logger: { disabled: true }, emailAndPassword: { enabled: true }, rateLimit: { enabled: false },
        user: { additionalFields: { ...userFields, locale: { ...userFields.locale, ...(!required && { defaultValue: "en" }) } } },
        session: { additionalFields: sessionFields },
      });
      for (const [writer, reader, prefix] of [[ref, go, "go"], [go, ref, "ts"]]) {
        const make = server => instrument(server, [inferAdditionalFields(), magicLinkClient()]).client;
        const sender = make(writer);
        const recipient = make(reader);
        const email = prefix + "@mail-fields.test";
        const metadata = {locale:"metadata-locale", accountClass:"unsafe", privateNote:"delivery-only"};
        const send = async name => {
          const response = await sender.signIn.magicLink({
            email, name, locale: "request-locale", privateNote: "request-private",
            accountClass: "unsafe", session: {locale:"request-device"}, metadata,
          });
          assert.equal(response.error, null);
          if (writer === ref) {
            assert.deepEqual(sent.metadata, metadata);
            return sent.token;
          }
          const delivered = JSON.parse(await readFile(join(dirname(go.databasePath), "mailbox.json"), "utf8"));
          assert.deepEqual(delivered.Metadata, metadata);
          return delivered.Token;
        };
        const verify = token => recipient.magicLink.verify({query:{token}});
        const visible = (view, locale) => {
          assert.equal(view.user.locale, locale);
          assert.equal(view.user.accountClass, "standard");
          assert.equal(view.session.locale, "en");
          assert.equal(view.session.userId, view.user.id);
          for (const fields of [view.user, view.session]) {
            for (const hidden of ["privateNote", "internalRisk", "preferred_locale"]) assert.ok(!Object.hasOwn(fields, hidden));
          }
        };
        const initial = await send("First");
        if (required) {
          const failed = await verify(initial);
          assert.equal(failed.error.status, 500);
          assert.equal((await recipient.getSession()).data, null);
          assert.equal(db.prepare('SELECT count(*) AS n FROM "user" WHERE email=?').get(email).n, 0);
          const replay = await reader.send(new Request(reader.baseURL + "/api/auth/magic-link/verify?token=" + encodeURIComponent(initial), {redirect:"manual"}));
          assert.equal(new URL(replay.headers.get("location")).searchParams.get("error"), "INVALID_TOKEN");
          const signup = await sender.signUp.email({name:"Existing",email,password:"fixture-password",locale:"established",privateNote:"stored-private"});
          assert.equal(signup.error, null);
        } else {
          const fresh = await verify(initial);
          assert.equal(fresh.error, null);
          visible(fresh.data, "en");
          assert.equal(fresh.data.user.name, "First");
          const saved = db.prepare('SELECT preferred_locale,accountClass,privateNote,internalRisk FROM "user" WHERE id=?').get(fresh.data.user.id);
          assert.deepEqual({...saved}, {preferred_locale:"en", accountClass:"standard",privateNote:null,internalRisk:9});
          const updated = await recipient.updateUser({locale:"established",privateNote:"stored-private"});
          assert.equal(updated.error, null);
        }
        const previous = db.prepare('SELECT id,name,accountClass,privateNote,internalRisk FROM "user" WHERE email=?').get(email);
        const next = await verify(await send("Replaced"));
        assert.equal(next.error, null);
        visible(next.data, "established");
        assert.equal(next.data.user.id, previous.id);
        assert.equal(next.data.user.name, previous.name);
        assert.equal(db.prepare('SELECT privateNote FROM "user" WHERE id=?').get(previous.id).privateNote, "stored-private");
        visible((await recipient.getSession()).data, "established");
      }
    });
  }
}
