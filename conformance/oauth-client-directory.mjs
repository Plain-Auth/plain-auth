import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

export async function compareClientDirectory(t, reference, goFixture) {
  const options = {
    loginPage: "/login",
    consentPage: "/consent",
    allowDynamicClientRegistration: true,
    cachedTrustedClients: new Set(["operator-managed"]),
    clientReference: ({ user }) => (user.email.startsWith("team-") ? "reports-team" : undefined),
    clientPrivileges: ({ action, clientId, headers }) =>
      headers.get("X-Deny-Action") !== action && (!clientId || headers.get("X-Deny-Client") !== clientId),
  };
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async (t) => {
      const server =
        runtime === "Go"
          ? await goFixture(t, ["oauth-provider", "jwt"], { CONFORMANCE_CLIENT_REGISTRATION: "directory" })
          : await reference(t, [jwt(), oauthProvider(options)], { rateLimit: { enabled: false } });
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      async function call(path, cookie, body, extra) {
        const headers = { origin: server.baseURL, ...extra };
        if (cookie) headers.cookie = cookie;
        if (body) headers["content-type"] = "application/json";
        return server.send(
          new Request(server.baseURL + "/api/auth/" + path, {
            method: body ? "POST" : "GET",
            headers,
            body: body && JSON.stringify(body),
          }),
        );
      }
      async function account(name) {
        const r = await call("sign-up/email", null, {
          email: name + "@directory.test",
          name,
          password: "local directory password",
        });
        assert.equal(r.status, 200);
        return {
          id: (await r.json()).user.id,
          cookie: r.headers
            .getSetCookie()
            .map((x) => x.split(";")[0])
            .join("; "),
        };
      }
      const individual = await account("individual");
      const tenant = await account("team-owner");
      const member = await account("team-reader");
      const other = await account("visitor");
      const metadata = {
        client_name: "Reporting",
        client_uri: "https://reports.example.test",
        logo_uri: "https://reports.example.test/logo",
        contacts: ["operator@example.test"],
        tos_uri: "https://reports.example.test/terms",
        policy_uri: "https://reports.example.test/privacy",
        redirect_uris: ["https://reports.example.test/return"],
        software_id: "software",
        software_version: "1.3",
        dpop_bound_access_tokens: false,
        post_logout_redirect_uris: ["https://reports.example.test/end"],
        subject_type: "public",
      };
      async function create(user, data) {
        const r = await call("oauth2/register", user.cookie, data);
        const app = await r.json();
        assert.equal(r.status, 201, JSON.stringify(app));
        return app;
      }
      const list = "oauth2/get-clients";
      const get = (id) => "oauth2/get-client?client_id=" + encodeURIComponent(id);
      const display = (id) => "oauth2/public-client?client_id=" + encodeURIComponent(id);
      async function ok(path, cookie, extra) {
        const r = await call(path, cookie, null, extra);
        const body = await r.json();
        assert.equal(r.status, 200, JSON.stringify(body));
        return body;
      }
      const personal = await create(individual, metadata);
      const key = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
      const shared = await create(tenant, {
        ...metadata,
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [key] },
        backchannel_logout_uri: "https://reports.example.test/logout",
        backchannel_logout_session_required: false,
      });
      db.prepare("UPDATE oauthClient SET skipConsent=1,enableEndSession=0,requirePKCE=0 WHERE clientId=?").run(
        shared.client_id,
      );
      const deniedCreate = await call("oauth2/register", other.cookie, metadata, { "X-Deny-Action": "create" });
      assert.equal(deniedCreate.status, 401);
      const extra = {
        billing: { tier: "trial" },
        client_secret: "reserved",
        clientSecret: "reserved",
        client_id: "wrong",
        reference_id: "wrong",
        client_credentials_scopes: ["forged"],
        resources: ["forged"],
        applicationType: "wrong",
        skip_consent: true,
      };
      db.prepare("UPDATE oauthClient SET metadata=? WHERE clientId=?").run(
        JSON.stringify(extra),
        personal.client_id,
      );
      const privateView = await ok(get(personal.client_id), individual.cookie);
      const expected = { ...personal, billing: { tier: "trial" } };
      delete expected.client_secret;
      assert.deepEqual(privateView, expected);
      assert.deepEqual(await ok(list, individual.cookie), [privateView]);
      assert.deepEqual(await ok(list, other.cookie), []);
      const teamView = await ok(get(shared.client_id), member.cookie);
      assert.equal(teamView.reference_id, "reports-team");
      assert.equal(teamView.user_id, undefined);
      assert.deepEqual(teamView, {
        ...shared,
        skip_consent: true,
        enable_end_session: false,
        require_pkce: false,
      });
      assert.deepEqual(await ok(list, member.cookie), [teamView]);
      const publicView = await ok(display(personal.client_id), other.cookie, { "X-Deny-Action": "read" });
      assert.deepEqual(publicView, {
        client_id: personal.client_id,
        client_name: metadata.client_name,
        client_uri: metadata.client_uri,
        logo_uri: metadata.logo_uri,
        contacts: metadata.contacts,
        tos_uri: metadata.tos_uri,
        policy_uri: metadata.policy_uri,
        redirect_uris: [],
      });
      for (const path of [list, get(personal.client_id), display(shared.client_id)]) {
        assert.equal((await call(path)).status, 401);
      }
      for (const [path, user, headers] of [
        [get(personal.client_id), other, {}],
        [get(shared.client_id), individual, {}],
        [get(personal.client_id), individual, { "X-Deny-Client": personal.client_id }],
        [list, member, { "X-Deny-Action": "list" }],
      ]) {
        assert.equal((await call(path, user.cookie, null, headers)).status, 401);
      }
      db.prepare("UPDATE oauthClient SET disabled=1 WHERE clientId=?").run(personal.client_id);
      assert.equal((await ok(get(personal.client_id), individual.cookie)).disabled, true);
      for (const path of [display(personal.client_id), display("absent"), get("absent")]) {
        const r = await call(path, individual.cookie);
        assert.equal(r.status, 404);
        assert.deepEqual(await r.json(), { error: "not_found", error_description: "client not found" });
      }
      for (const path of ["oauth2/get-client", "oauth2/public-client"]) {
        for (const [suffix, kind] of [
          ["", "undefined"],
          ["?client_id=a&client_id=b", "array"],
        ]) {
          const r = await call(path + suffix, individual.cookie);
          assert.equal(r.status, 400);
          assert.deepEqual(await r.json(), {
            code: "VALIDATION_ERROR",
            message: "[query.client_id] Invalid input: expected string, received " + kind,
          });
        }
      }
      const id = "native / + &?";
      db.prepare(
        "INSERT INTO oauthClient(id,clientId,userId,redirectUris,scopes,contacts) VALUES(?,?,?,?,?,?)",
      ).run("old-row", id, individual.id, "[]", "[]", "[]");
      assert.deepEqual(await ok(get(id), individual.cookie), {
        client_id: id,
        user_id: individual.id,
        contacts: [],
        redirect_uris: [],
        scope: "",
      });
      const snapshot = db.prepare("UPDATE oauthClient SET clientDiscoveryId=? WHERE clientId=?");
      snapshot.run("missing-discovery", id);
      assert.equal((await call(get(id), individual.cookie)).status, 404);
      assert.equal((await call(display(id), individual.cookie)).status, 404);
      assert.ok((await ok(list, individual.cookie)).some((c) => c.client_id === id));
      await t.test("owners delete personal and tenant registrations", async () => {
        const remove = (cookie, body, extra) => call("oauth2/delete-client", cookie, body, extra);
        const payload = { client_id: personal.client_id };
        for (const [cookie, body, extra] of [
          [null, payload],
          [other.cookie, { ...payload, user_id: individual.id }],
          [individual.cookie, payload, { "X-Deny-Action": "delete" }],
          [member.cookie, { client_id: shared.client_id }, { "X-Deny-Client": shared.client_id }],
          [individual.cookie, { client_id: shared.client_id, reference_id: "reports-team" }],
        ]) {
          assert.equal((await remove(cookie, body, extra)).status, 401);
        }
        for (const [body, kind] of [[{}, "undefined"], [{ client_id: null }, "null"], [{ client_id: 1 }, "number"]]) {
          const bad = await remove(individual.cookie, body);
          assert.equal(bad.status, 400);
          assert.deepEqual(await bad.json(), {
            code: "VALIDATION_ERROR",
            message: "[body.client_id] Invalid input: expected string, received " + kind,
          });
        }
        const immutable = await remove(individual.cookie, { client_id: "operator-managed" });
        assert.equal(immutable.status, 400);
        assert.deepEqual(await immutable.json(), { error: "invalid_client", error_description: "trusted clients must be updated manually" });
        for (const [cookie, clientID] of [[individual.cookie, personal.client_id], [member.cookie, shared.client_id]]) {
          const deleted = await remove(cookie, { client_id: clientID });
          assert.equal(deleted.status, 200);
          assert.equal(await deleted.text(), "");
          assert.equal((await call(get(clientID), cookie)).status, 404);
          const again = await remove(cookie, { client_id: clientID });
          assert.equal(again.status, 404);
          assert.deepEqual(await again.json(), { error: "not_found", error_description: "client not found" });
        }
        assert.deepEqual((await ok(list, individual.cookie)).map((app) => app.client_id), [id]);
        assert.deepEqual(await ok(list, member.cookie), []);
      });
      await call("sign-out", member.cookie, {});
      assert.equal((await call(list, member.cookie)).status, 401);
    });
  }
}
