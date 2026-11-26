import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { magicLink, oneTimeToken } from "better-auth/plugins";
import { magicLinkClient, oneTimeTokenClient } from "better-auth/client/plugins";

const sha = (value, encoding) => createHash("sha256").update(value).digest(encoding);

// Each mode gives the reference setting and what the reference stores for a
// whole identifier. Go stores the same value after the purpose prefix.
const modes = {
  hashed: { storeIdentifier: "hashed", stored: whole => sha(whole, "base64url") },
  custom: { storeIdentifier: { hash: async whole => sha(whole, "hex") }, stored: whole => sha(whole, "hex") },
  "reset-only": {
    storeIdentifier: { default: "plain", overrides: { "reset-password": "hashed" } },
    stored: whole => whole.startsWith("reset-password:") ? sha(whole, "base64url") : whole,
  },
};

export async function compareStoredIdentifiers(t, { reference, goFixture, instrument }) {
  for (const [mode, { storeIdentifier, stored }] of Object.entries(modes)) {
    await t.test(mode, async t => {
      const refDB = new DatabaseSync(":memory:");
      t.after(() => refDB.close());
      let resetToken, magic;
      const ref = await reference(t, [
        magicLink({ storeToken: "hashed", sendMagicLink: async ({ token, url }) => { magic = { Token: token, URL: url }; } }),
        oneTimeToken({ storeToken: "hashed" }),
      ], {
        database: refDB, rateLimit: { enabled: false }, verification: { storeIdentifier },
        emailAndPassword: { enabled: true, sendResetPassword: async ({ token }) => { resetToken = token; } },
      });
      const go = await goFixture(t, [], { CONFORMANCE_STORE_IDENTIFIER: mode, CONFORMANCE_RESET_HOOK: "1", CONFORMANCE_MAILBOX: "1", CONFORMANCE_TRANSFER: "1" });
      const goDB = new DatabaseSync(go.databasePath);
      t.after(() => goDB.close());
      for (const target of [ref, go]) {
        const local = target === go;
        const db = local ? goDB : refDB;
        const row = whole => {
          const value = stored(whole);
          return local && value !== whole ? whole.slice(0, whole.indexOf(":") + 1) + value : value;
        };
        const has = identifier => db.prepare("SELECT 1 FROM verification WHERE identifier=?").get(identifier) !== undefined;
        const holds = token => db.prepare("SELECT COUNT(*) AS n FROM verification WHERE instr(identifier, ?) > 0").get(token).n > 0;
        const { client } = instrument(target, [magicLinkClient(), oneTimeTokenClient()]);
        const email = `stored-${mode}@example.test`;
        assert.equal((await client.signUp.email({ email, name: "Owner", password: "original password" })).error, null);

        const issued = (await client.oneTimeToken.generate()).data.token;
        assert.ok(has(row("one-time-token:" + sha(issued, "base64url"))));
        assert.equal((await client.oneTimeToken.verify({ token: issued })).error, null);
        assert.equal((await client.oneTimeToken.verify({ token: issued })).error?.status, 400);

        assert.equal((await client.requestPasswordReset({ email, redirectTo: "/done" })).error, null);
        const reset = local ? await readFile(go.databasePath + ".reset-link", "utf8") : resetToken;
        const resetRow = row("reset-password:" + reset);
        assert.ok(has(resetRow), resetRow);
        assert.ok(!holds(reset));
        const storedPart = local ? resetRow.slice("reset-password:".length) : resetRow;
        assert.equal((await client.resetPassword({ token: storedPart, newPassword: "replacement password" })).error?.status, 400);
        assert.equal((await client.resetPassword({ token: reset, newPassword: "replacement password" })).error, null);
        assert.equal((await client.resetPassword({ token: reset, newPassword: "third password" })).error?.status, 400);
        assert.ok(!has(resetRow));

        assert.equal((await client.signIn.magicLink({ email, callbackURL: "/done" })).error, null);
        const link = local ? JSON.parse(await readFile(join(dirname(go.databasePath), "mailbox.json"), "utf8")) : magic;
        const magicRow = row("magic-link:" + sha(link.Token, "base64url"));
        assert.ok(has(magicRow), magicRow);
        const visit = async () => (await target.send(new Request(link.URL, { redirect: "manual" }))).headers.get("Location");
        assert.doesNotMatch(await visit(), /error/);
        assert.match(await visit(), /error=INVALID_TOKEN/);
        assert.ok(!has(magicRow));
      }
    });
  }
}
