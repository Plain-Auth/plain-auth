import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { inferAdditionalFields, oneTimeTokenClient } from "better-auth/client/plugins";
import { oneTimeToken } from "better-auth/plugins";
import { sessionFields } from "./session-fields.mjs";
import { userFields } from "./user-fields.mjs";

function ok(response) {
  assert.equal(response.error, null, response.error?.message);
  return response.data;
}

function checkFields(view, id, userLocale, sessionLocale) {
  assert.equal(view.user.id, id);
  assert.equal(view.session.userId, id);
  assert.equal(view.user.locale, userLocale);
  assert.equal(view.session.locale, sessionLocale);
  for (const fields of [view.user, view.session]) {
    for (const hidden of ["preferred_locale", "privateNote", "internalRisk"]) {
      assert.ok(!Object.hasOwn(fields, hidden), hidden);
    }
  }
}

export async function compareTransferFields(t, { reference, goFixture, instrument }) {
  for (const mode of ["default", "compact", "suppress"]) {
    await t.test(mode, async t => {
      const suppress = mode === "suppress";
      const cache = mode !== "default";
      const go = await goFixture(t, [], {
        CONFORMANCE_TRANSFER: suppress ? "suppress" : "header",
        CONFORMANCE_USER_FIELDS: "1",
        CONFORMANCE_SESSION_FIELDS: "1",
        ...(cache && { CONFORMANCE_COMPACT_CACHE: "1" }),
      });
      const db = new DatabaseSync(go.databasePath);
      t.after(() => db.close());
      const ref = await reference(t, [oneTimeToken({
        setOttHeaderOnNewSession: true, disableSetSessionCookie: suppress,
      })], {
        baseURL: go.baseURL, database: db,
        user: { additionalFields: userFields },
        session: {
          additionalFields: sessionFields,
          ...(cache && { cookieCache: { enabled: true, strategy: "compact", version: "release-test" } }),
        },
      });
      ref.baseURL = go.baseURL;
      for (const [issuer, consumer, name] of [[go, ref, "go"], [ref, go, "ts"]]) {
        const make = server => instrument(server, [inferAdditionalFields(), oneTimeTokenClient()]);
        const sender = make(issuer);
        // Exercise one browser jar across both nodes at the same application origin.
        // The reference issues a signed visitor snapshot even when Go uses live fields.
        let active = cache ? ref : consumer;
        const recipient = make({ baseURL: go.baseURL, send: request => active.send(request) });
        const login = (browser, role) => browser.client.signUp.email({
          name: role, email: name + role + "@transfer.test", password: "local transfer fixture",
          locale: role + "-profile", privateNote: role + "-private-profile",
        }).then(ok);
        const owner = await login(sender, "owner");
        const visitor = await login(recipient, "visitor");
        if (cache) assert.ok(recipient.requests.at(-1).cookies.some(c => c.name.endsWith(".session_data")));
        ok(await recipient.client.updateSession({ locale: "visitor-device", privateNote: "visitor-private-device" }));
        const before = ok(await recipient.client.getSession({ query: { disableCookieCache: true } }));
        checkFields(before, visitor.user.id, "visitor-profile", "visitor-device");
        const proof = ok(await sender.client.oneTimeToken.generate()).token;
        ok(await sender.client.updateUser({ locale: "edited-after-issue" }));
        ok(await sender.client.updateSession({ locale: "device-after-issue", privateNote: "owner-private-device" }));

        assert.equal(db.prepare('SELECT privateNote FROM "user" WHERE id=?').get(owner.user.id).privateNote, "owner-private-profile");
        assert.equal(db.prepare('SELECT privateNote FROM session WHERE token=?').get(owner.token).privateNote, "owner-private-device");

        active = consumer;
        const redeemed = ok(await recipient.client.oneTimeToken.verify({ token: proof }));
        checkFields(redeemed, owner.user.id, "edited-after-issue", "device-after-issue");
        assert.equal(redeemed.session.token, owner.token);
        assert.equal(recipient.requests.at(-1).cookies.some(c => c.name.endsWith(".session_token")), !suppress);
        active = cache ? ref : consumer;
        const current = ok(await recipient.client.getSession());
        if (suppress) {
          checkFields(current, visitor.user.id, "visitor-profile", "visitor-device");
          continue;
        }
        checkFields(current, owner.user.id, "edited-after-issue", "device-after-issue");

        // A noncached read renews the original row after its update window.
        db.prepare('UPDATE "user" SET preferred_locale=? WHERE id=?').run("renewed-profile", owner.user.id);
        db.prepare('UPDATE session SET preferred_locale=?, expiresAt=? WHERE token=?')
          .run("renewed-device", new Date(Date.now() + 60_000).toISOString(), owner.token);
        active = consumer;
        const renewed = ok(await recipient.client.getSession({ query: { disableCookieCache: true } }));
        checkFields(renewed, owner.user.id, "renewed-profile", "renewed-device");
        assert.equal(renewed.session.id, redeemed.session.id);
        assert.ok(recipient.requests.at(-1).cookies.some(c => c.name.endsWith(".session_token")));
        active = issuer;
        checkFields(ok(await recipient.client.getSession()), owner.user.id, "renewed-profile", "renewed-device");
      }
    });
  }
}
