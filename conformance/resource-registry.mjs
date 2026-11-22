import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

function sessionHeaders(response) {
  assert.equal(response.ok, true);
  const cookie = response.headers.getSetCookie().map(line => line.split(";")[0]).join("; ");
  assert.ok(cookie);
  return {cookie};
}

function persisted(row) {
  // Both APIs expose these instants with millisecond precision. A reference
  // server method returns Date objects, while an HTTP fixture transports JSON.
  return {...row, createdAt: new Date(row.createdAt).toISOString(), updatedAt: new Date(row.updatedAt).toISOString()};
}

export async function compareResourceRegistry(t, goFixture) {
  const go = await goFixture(t, ["oauth-provider", "jwt"], {CONFORMANCE_RESOURCE_REGISTRY: "1"});
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const reference = betterAuth({
    database: db, baseURL: "http://reference.localhost", secret: "local-conformance-0123456789-abcdefghijk",
    logger: {disabled: true}, telemetry: {enabled: false}, emailAndPassword: {enabled: true},
    plugins: [jwt(), oauthProvider({loginPage: "/login", consentPage: "/consent",
      resourcePrivileges: ({headers}) => headers.get("x-fixture-resource-access") !== "deny"})],
  });
  const api = reference.api;
  const user = {name: "Operator", password: "a local registry fixture password"};
  const refHeaders = sessionHeaders(await api.signUpEmail({body: {...user, email: "reference@registry.example"}, asResponse: true}));
  const goHeaders = sessionHeaders(await fetch(go.baseURL + "/api/auth/sign-up/email", {
    method: "POST", headers: {"content-type": "application/json", origin: go.baseURL},
    body: JSON.stringify({...user, email: "go@registry.example"}),
  }));
  async function call(action, identifier, fields, clientID, headers = goHeaders) {
    const resp = await fetch(go.baseURL + "/__fixture/resource-registry", {
      method: "POST", headers: {"content-type":"application/json", ...headers},
      body: JSON.stringify({action, identifier, fields, clientID}),
    });
    const text = await resp.text();
    assert.notEqual(resp.status, 500, text);
    return {status: resp.status, body: JSON.parse(text)};
  }
  const client = await api.adminCreateOAuthClient({headers: refHeaders, body: {redirect_uris: ["https://app.example.test/cb"]}});
  const params = id => ({identifier: encodeURIComponent(id)});
  const linkedParams = id => ({...params(id), client_id: encodeURIComponent(client.client_id)});
  const rich = {name: "Reporting", accessTokenTtl: 300, refreshTokenTtl: 900, signingAlgorithm: "RS256", signingKeyId: "local",
    allowedScopes: ["read", "download"], customClaims: {region: "west", nested: {trial: true}},
    dpopBoundAccessTokensRequired: true, disabled: true, metadata: {editions: [1, 2]}};
  const patch = {accessTokenTtl: 120, refreshTokenTtl: null, signingKeyId: null, allowedScopes: [], customClaims: null, metadata: {}, disabled: false};
  for (const origin of ["Go", "reference"]) {
    await t.test(origin + " creates the resource and the other service edits it", async () => {
      const id = "https://reports.example.test/" + origin + "/tenant%2Fwest";
      let created, read, updated;
      if (origin === "Go") {
        const result = await call("create", id, rich);
        assert.equal(result.status, 201);
        created = result.body;
        read = await api.adminGetOAuthResource({headers: refHeaders, params: params(id)});
        updated = await api.adminUpdateOAuthResource({headers: refHeaders, params: params(id), body: patch});
      } else {
        created = await api.adminCreateOAuthResource({headers: refHeaders, body: {identifier: id, ...rich}});
        const result = await call("read", id);
        assert.equal(result.status, 200);
        read = result.body;
        const edit = await call("update", id, patch);
        assert.equal(edit.status, 200);
        updated = edit.body;
      }
      assert.deepEqual(persisted(read), persisted(created));
      assert.equal(created.policyVersion, 1);
      assert.ok(created.id);
      for (const [key, value] of Object.entries({...rich, ...patch})) assert.deepEqual(updated[key], value, key);
      const goList = (await call("list")).body;
      const refList = await api.adminListOAuthResources({headers: refHeaders});
      assert.deepEqual(goList.map(persisted), refList.map(persisted));
      assert.deepEqual(persisted(goList.find(r => r.identifier === id)), persisted(updated));
      assert.deepEqual(await call("create", id, {}), {status: 400, body: {error: "invalid_request"}});

      if (origin === "Go") {
        assert.deepEqual((await call("link", id, {}, client.client_id)).body, {linked: true});
        assert.deepEqual(await api.adminLinkClientResource({headers: refHeaders, params: linkedParams(id)}), {linked: true, alreadyLinked: true});
        assert.deepEqual(await api.adminUnlinkClientResource({headers: refHeaders, params: linkedParams(id)}), {unlinked: true});
      } else {
        assert.deepEqual(await api.adminLinkClientResource({headers: refHeaders, params: linkedParams(id)}), {linked: true});
        assert.deepEqual((await call("link", id, {}, client.client_id)).body, {linked: true, alreadyLinked: true});
        assert.deepEqual((await call("unlink", id, {}, client.client_id)).body, {unlinked: true});
      }
      assert.deepEqual((await call("link", id, {}, client.client_id)).body, {linked: true});
      if (origin === "Go") {
        assert.deepEqual(await api.adminDeleteOAuthResource({headers: refHeaders, params: params(id)}), {deleted: true});
      } else {
        assert.deepEqual((await call("delete", id)).body, {deleted: true});
      }
      assert.equal(db.prepare("SELECT count(*) AS n FROM oauthClientResource WHERE resourceId=?").get(id).n, 0);
      assert.deepEqual(await call("read", id), {status: 404, body: {error: "not_found"}});
      await assert.rejects(api.adminGetOAuthResource({headers: refHeaders, params: params(id)}), e => e.statusCode === 404);
    });
  }
  await t.test("privilege checks precede resource existence checks", async () => {
    for (const headers of [{}, {...goHeaders, "x-fixture-resource-access":"deny"}]) {
      for (const action of ["create", "list", "read", "update", "delete", "link", "unlink"]) {
        assert.equal((await call(action, "urn:private:missing", {}, "missing", headers)).status, 401, action);
      }
    }
    for (const headers of [{}, {...refHeaders, "x-fixture-resource-access":"deny"}]) {
      await assert.rejects(api.adminGetOAuthResource({headers, params: {identifier: "urn:private:missing"}}), e => e.statusCode === 401);
    }
  });
  await t.test("invalid targets and invalid policies leave the registry unchanged", async () => {
    for (const identifier of ["local-name", "urn:reports#fragment", "data:reports", "vbscript:reports"]) {
      assert.deepEqual(await call("create", identifier, {}), {status:400, body:{error:"invalid_target"}});
      await assert.rejects(api.adminCreateOAuthResource({headers:refHeaders, body:{identifier}}),
        e => e.statusCode === 400 && e.body?.error === "invalid_target");
    }
    const identifier = "urn:example:validated";
    const created = await call("create", identifier, {});
    assert.equal(created.body.name, identifier);
    for (const invalid of [{accessTokenTtl:-1}, {signingAlgorithm:"HS256"}, {disabled:null}]) {
      const body = {...invalid, name:"discarded"};
      assert.equal((await call("update", identifier, body)).status, 400);
      await assert.rejects(api.adminUpdateOAuthResource({headers:refHeaders, params:params(identifier), body}), e => e.statusCode === 400);
      assert.deepEqual(persisted((await call("read", identifier)).body), persisted(created.body));
    }
    assert.equal((await call("delete", identifier)).status, 200);
  });
  await t.test("server operations stay off both public routers", async () => {
    const base = "/api/auth/admin/oauth2/resources";
    for (const [method,path] of [["GET",base], ["POST",base], ["GET",base+"/id"], ["PATCH",base+"/id"],
      ["DELETE",base+"/id"], ["POST",base+"/id/clients/client"], ["DELETE",base+"/id/clients/client"]]) {
      assert.equal((await fetch(go.baseURL+path, {method, headers:goHeaders})).status, 404);
      assert.equal((await reference.handler(new Request("http://reference.localhost"+path, {method,headers:refHeaders}))).status, 404);
    }
  });
}
