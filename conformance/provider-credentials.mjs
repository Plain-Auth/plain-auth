// Exercise the same authenticated HTTP calls and identical stored provider
// account data against both implementations. All credentials are test fixtures.
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export async function providerCredentials(t, goFixture) {
  const baseURL = "http://reference.localhost";
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  const options = {
    database, baseURL, secret: "local-conformance-0123456789-abcdefghijk",
    emailAndPassword: { enabled: true }, telemetry: { enabled: false },
    socialProviders: {
      github: {
        clientId: "fixture-client", clientSecret: "fixture-secret",
        refreshAccessToken: async (token) => {
          assert.equal(token, "stored-refresh");
          return { accessToken: "refreshed-access", refreshToken: "rotated-refresh" };
        },
        getUserInfo: async (t) => {
          assert.equal(t.accessToken, "refreshed-access");
          return {
            data: { id: "provider-person" },
            user: { name: "Fixture", email: "owner@example.org", emailVerified: true },
          };
        },
      },
    },
  };
  await (await getMigrations(options)).runMigrations();
  const reference = betterAuth(options);
  const go = await goFixture(t, [], { CONFORMANCE_PROVIDER: "1" });
  const goDB = new DatabaseSync(go.databasePath);
  t.after(() => goDB.close());

  async function run(db, origin, send) {
    let cookie = "";
    async function call(route, body, authenticated = true) {
      const headers = new Headers({ origin, "content-type": "application/json" });
      if (authenticated && cookie) headers.set("cookie", cookie);
      return send(new Request(origin + "/api/auth/" + route, {
        method: body ? "POST" : "GET", headers,
        body: body && JSON.stringify(body),
      }));
    }
    const signed = await call("sign-up/email", {
      name: "Fixture", email: "owner@example.org", password: "credential-fixture",
    });
    assert.equal(signed.status, 200);
    const { user } = await signed.json();
    cookie = signed.headers.getSetCookie().map(s => s.split(";")[0]).join("; ");
    const now = new Date().toISOString();
    db.prepare('INSERT INTO account (id,accountId,providerId,userId,accessToken,refreshToken,scope,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?)')
      .run("local-record", "provider-person", "github", user.id, "original-access", "stored-refresh", "read,write", now, now);
    const selector = { accountId: "local-record", userId: "ignored-http-user" };
    assert.equal((await call("get-access-token", { ...selector, userId: user.id }, false)).status, 401);
    const output = [];
    for (const [route, body] of [
      ["get-access-token", selector], ["refresh-token", selector],
      ["account-info?accountId=local-record", undefined], ["get-access-token", selector],
    ]) {
      const response = await call(route, body);
      const payload = await response.json();
      assert.equal(response.status, 200, JSON.stringify(payload));
      output.push(payload);
    }
    assert.equal(output[0].accessToken, "original-access");
    assert.equal(output[1].refreshToken, "rotated-refresh");
    assert.equal(output[2].account.accountId, "provider-person");
    assert.equal(output[3].accessToken, "refreshed-access");
    return output;
  }
  const expected = await run(database, baseURL, r => reference.handler(r));
  assert.deepEqual(await run(goDB, go.baseURL, go.send), expected);
}
