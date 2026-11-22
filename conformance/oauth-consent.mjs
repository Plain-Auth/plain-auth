import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

export async function compareOAuthConsents(t, reference, goFixture) {
  const options = { loginPage: "/login", consentPage: "/consent" };
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "Go"
        ? await goFixture(t, ["oauth-provider", "jwt"])
        : await reference(t, [jwt(), oauthProvider(options)]);
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      async function request(path, cookie, body) {
        const headers = { origin: server.baseURL };
        if (cookie) headers.cookie = cookie;
        if (body) headers["content-type"] = "application/json";
        return server.send(new Request(server.baseURL + "/api/auth/" + path, {
          method: body ? "POST" : "GET", headers, body: body && JSON.stringify(body),
        }));
      }
      async function account(name) {
        const response = await request("sign-up/email", "", {
          name, email: name + "@consents.test", password: "local consent management password",
        });
        assert.equal(response.status, 200);
        const { user } = await response.json();
        const cookie = response.headers.getSetCookie().map(line => line.split(";")[0]).join("; ");
        return { id: user.id, cookie };
      }
      const owner = await account("owner");
      const other = await account("other");
      const id = "consent / + &?";
      const read = "oauth2/get-consent?id=" + encodeURIComponent(id);
      const list = "oauth2/get-consents";
      const update = "oauth2/update-consent";
      const remove = "oauth2/delete-consent";
      const client = db.prepare("INSERT INTO oauthClient(id,clientId,redirectUris,scopes,referenceId,userId) VALUES(?,?,?,?,?,?)");
      client.run("client-row", "registered", "[]", '["reports","email"]', "department", owner.id);
      client.run("fallback-row", "fallback", "[]", null, null, owner.id);
      client.run("empty-row", "empty", "[]", "[]", null, owner.id);
      const insert = db.prepare("INSERT INTO oauthConsent(id,clientId,userId,referenceId,resources,requestedUserInfoClaims,scopes,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?)");
      const instant = "2025-02-03T12:34:56.000Z";
      const add = (key, clientID, userID) => insert.run(key, clientID, userID, "project", '["urn:reports"]', '["name"]', '["email"]', instant, instant);

      assert.deepEqual(await (await request(list, owner.cookie)).json(), []);
      add(id, "registered", owner.id);
      add("other-grant", "registered", other.id);
      add("unassigned", "registered", null);
      const initial = { id, clientId: "registered", userId: owner.id, referenceId: "project",
        resources: ["urn:reports"], requestedUserInfoClaims: ["name"], scopes: ["email"], createdAt: instant, updatedAt: instant };
      const firstRead = await request(read, owner.cookie);
      assert.equal(firstRead.status, 200);
      assert.deepEqual(await firstRead.json(), initial);
      assert.deepEqual(await (await request(list, owner.cookie)).json(), [initial]);

      const valid = { id, update: { scopes: ["reports", "email", "reports"] } };
      for (const [path, body] of [[read], [list], [update, valid], [remove, { id }]]) {
        const response = await request(path, "", body);
        assert.equal(response.status, 401);
        assert.deepEqual(await response.json(), { message: "Unauthorized", code: "UNAUTHORIZED" });
      }
      for (const [path, body] of [[read], [update, valid], [remove, { id }], ["oauth2/get-consent?id=unassigned"]]) {
        const response = await request(path, other.cookie, body);
        assert.equal(response.status, 401);
        assert.equal(await response.text(), "");
      }
      async function problem(path, body, status, code, description) {
        const response = await request(path, owner.cookie, body);
        assert.equal(response.status, status);
        assert.deepEqual(await response.json(), { error: code, error_description: description });
      }
      await problem("oauth2/get-consent?id=", undefined, 404, "not_found", "missing id parameter");
      await problem("oauth2/get-consent?id=absent", undefined, 404, "not_found", "no consent");
      await problem(update, { id, update: { scopes: ["reports","profile"] } }, 400, "invalid_request", "unable to provide scopes to department");
      assert.deepEqual(await (await request(read, owner.cookie)).json(), initial);

      const edited = await request(update, owner.cookie, { ...valid, userId: other.id, update: { ...valid.update, resources: [], userId: other.id } });
      assert.equal(edited.status, 200);
      const result = await edited.json();
      assert.match(result.updatedAt, /\.000Z$/);
      assert.ok(Date.parse(result.updatedAt) > Date.parse(instant));
      assert.deepEqual(result, { ...initial, scopes: valid.update.scopes, updatedAt: result.updatedAt });
      assert.deepEqual(await (await request(read, owner.cookie)).json(), result);

      add("inherited", "fallback", owner.id);
      const inherited = await request(update, owner.cookie, { id: "inherited", update: { scopes: ["openid", "offline_access", "profile", "email"] } });
      assert.equal(inherited.status, 200);
      await problem(update, { id: "inherited", update: { scopes: ["reports"] } }, 400, "invalid_request", "unable to provide scopes to " + owner.id);
      add("none", "empty", owner.id);
      await problem(update, { id: "none", update: { scopes: ["email"] } }, 400, "invalid_request", "unable to provide scopes to " + owner.id);
      client.run("unowned-row", "unowned", "[]", "[]", null, null);
      add("unowned-grant", "unowned", owner.id);
      await problem(update, { id: "unowned-grant", update: { scopes: ["email"] } }, 400, "invalid_request", "unable to provide scopes to null");
      db.prepare("UPDATE oauthClient SET clientDiscoveryId = ? WHERE clientId = ?").run("missing-provider", "unowned");
      await problem(update, { id: "unowned-grant", update: { scopes: [] } }, 404, "not_found", "client not found");
      const cleared = await request(update, owner.cookie, { id, update: { scopes: [] } });
      assert.deepEqual((await cleared.json()).scopes, []);
      const badScopes = "[body.update.scopes] Invalid input: expected array, received ";
      for (const [bad, message] of [
        [{}, "[body.id] Invalid input: expected string, received undefined; [body.update] Invalid input: expected object, received undefined"],
        [{ id }, "[body.update] Invalid input: expected object, received undefined"],
        [{ id, update: {} }, badScopes + "undefined"],
        [{ id, update: { scopes: null } }, badScopes + "null"],
        [{ id, update: { scopes: [3] } }, "[body.update.scopes.0] Invalid input: expected string, received number"],
      ]) {
        const response = await request(update, owner.cookie, bad);
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { code: "VALIDATION_ERROR", message });
      }
      const repeated = await request("oauth2/get-consent?id=one&id=two", owner.cookie);
      assert.equal(repeated.status, 400);
      assert.deepEqual(await repeated.json(), { code: "VALIDATION_ERROR", message: "[query.id] Invalid input: expected string, received array" });
      const deleted = await request(remove, owner.cookie, { id });
      assert.equal(deleted.status, 200);
      assert.equal(await deleted.text(), "");
      await problem(read, undefined, 404, "not_found", "no consent");
      await problem(remove, { id }, 404, "not_found", "no consent");
      await problem(update, valid, 404, "not_found", "no consent");
      const theirs = await (await request(list, other.cookie)).json();
      assert.deepEqual(theirs.map(c => c.id), ["other-grant"]);
      assert.equal((await request("sign-out", owner.cookie, {})).status, 200);
      assert.equal((await request(list, owner.cookie)).status, 401);
    });
  }
}
