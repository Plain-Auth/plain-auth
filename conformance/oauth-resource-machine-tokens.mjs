import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { symmetricEncrypt } from "better-auth/crypto";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { calculateJwkThumbprint, createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";

export async function compareResourceMachineTokens(t, { reference, goFixture }) {
  for (const runtime of ["reference", "Go"]) {
    for (const opaque of [false, true]) {
      await t.test(runtime + (opaque ? " opaque" : " signed"), async t => {
        const options = {
          loginPage: "/login", consentPage: "/consent", scopes: ["reports", "extra"],
          disableJwtPlugin: opaque, m2mAccessTokenExpiresIn: 600, scopeExpirations: { reports: "90s" },
          prefix: { clientSecret: "fixture_", opaqueAccessToken: "access_" },
        };
        const server = runtime === "Go" ? await goFixture(t, ["jwt", "oauth-provider"], {
          CONFORMANCE_CLIENT_REGISTRATION: "protected", CONFORMANCE_OPAQUE_RESOURCE_TOKENS: opaque ? "1" : "0",
        }) : await reference(t, [jwt(), oauthProvider(options)], { rateLimit: { enabled: false } });
        const db = server.database ?? new DatabaseSync(server.databasePath);
        if (!server.database) t.after(() => db.close());
        const inspector = betterAuth({
          database: db, baseURL: server.baseURL, secret: "local-conformance-0123456789-abcdefghijk",
          telemetry: { enabled: false }, plugins: [jwt(), oauthProvider({ ...options, disableJwtPlugin: opaque && runtime === "reference" })], rateLimit: { enabled: false },
        });
        await checkResourceIssuance(server, inspector, db, opaque, opaque && runtime === "reference");
      });
    }
  }
}

async function checkResourceIssuance(server, inspector, db, opaque, encryptedSecret) {
  const mount = server.baseURL + "/api/auth";
  const a = "urn:plain-auth:reports", b = "https://files.example.test/";
  const raw = "local-machine-secret", secret = "fixture_" + raw;
  const hash = value => createHash("sha256").update(value).digest("base64url");
  const storedSecret = encryptedSecret ? await symmetricEncrypt({ key: "local-conformance-0123456789-abcdefghijk", data: raw }) : hash(raw);
  for (const id of ["machine", "reader"]) {
    db.prepare("INSERT INTO oauthClient(id,clientId,clientSecret,tokenEndpointAuthMethod,grantTypes,clientCredentialsScopes,redirectUris) VALUES (?,?,?,?,?,?,?)")
      .run(randomUUID(), id, storedSecret, "client_secret_post", '["client_credentials"]', '["reports","extra"]', "[]");
  }
  const insert = db.prepare("INSERT INTO oauthResource(id,identifier,name,allowedScopes,accessTokenTtl,customClaims) VALUES(?,?,?,?,?,?)");
  insert.run("A", a, "Reports", '["extra"]', 110, '{"tier":"reports","cnf":{"jkt":"ignored"}}');
  insert.run("B", b, "Files", '["reports","extra"]', 120, '{"tier":"files","sub":"ignored"}');
  const link = (client, resource) => db.prepare("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES(?,?,?)").run(randomUUID(), client, resource);
  link("machine", a);
  link("reader", b);
  const form = (route, params, proof) => new Request(mount + "/oauth2/" + route, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...(proof && { dpop: proof }) }, body: params,
  });
  function issue(resources, scope, proof) {
    const p = new URLSearchParams({ grant_type: "client_credentials", client_id: "machine", client_secret: secret });
    for (const id of resources) p.append("resource", id);
    if (scope !== undefined) p.set("scope", scope);
    return server.send(form("token", p, proof));
  }
  async function expect(result, status, error) {
    const r = await result, body = await r.json();
    assert.equal(r.status, status, JSON.stringify(body));
    if (error) assert.equal(body.error, error, JSON.stringify(body));
    return body;
  }
  const inspect = (token, id = "machine") => expect(inspector.handler(form("introspect",
    new URLSearchParams({ client_id: id, client_secret: secret, token, token_type_hint: "access_token" }))), 200);
  await expect(issue([a, b]), 400, "invalid_target");
  await expect(issue(["urn:missing"], "openid"), 400, "invalid_scope");
  await expect(issue([a + "#wrong"]), 400, "invalid_request");
  await expect(issue([a], "reports"), 400, "invalid_scope");
  link("machine", b);
  db.prepare("UPDATE oauthResource SET signingAlgorithm='ES256',signingKeyId='keyA' WHERE id='A'").run();
  db.prepare("UPDATE oauthResource SET signingAlgorithm='EdDSA',signingKeyId='keyB' WHERE id='B'").run();
  await expect(issue([a, b]), 400, "invalid_request");
  db.prepare("UPDATE oauthResource SET signingAlgorithm=NULL").run();
  await expect(issue([a, b]), 400, "invalid_request");
  db.prepare("UPDATE oauthResource SET signingKeyId=NULL").run();

  const key = await generateKeyPair("ES256"), jwk = await exportJWK(key.publicKey);
  const thumb = await calculateJwkThumbprint(jwk);
  const proof = await new SignJWT({ htm: "POST", htu: mount + "/oauth2/token" }).setIssuedAt().setJti(randomUUID())
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk }).sign(key.privateKey);
  db.prepare("UPDATE oauthResource SET dpopBoundAccessTokensRequired=1,disabled=1 WHERE id='A'").run();
  await expect(issue([a, b], undefined, proof), 400, "invalid_target");
  db.prepare("UPDATE oauthResource SET disabled=0 WHERE id='A'").run();
  await expect(issue([a, b]), 400, "invalid_dpop_proof");
  const requested = [a, a, b], token = await expect(issue(requested, undefined, proof), 200);
  assert.equal(token.scope, "extra");
  assert.equal(token.expires_in, 90); // The dropped reports scope still limits the lifetime.
  assert.equal(token.token_type, "DPoP");
  assert.equal(token.refresh_token, undefined);
  assert.equal(token.id_token, undefined);
  await expect(issue([a, b], undefined, proof), 400, "invalid_dpop_proof");
  const info = await inspect(token.access_token, "reader");
  assert.equal(info.active, true);
  assert.equal(info.exp - info.iat, 90);
  assert.deepEqual(info.cnf, { jkt: thumb });
  assert.equal(info.tier, "files");
  assert.deepEqual(info.aud, opaque ? requested : [a, b]);
  if (opaque) {
    assert.equal(info.sub, undefined);
    assert.match(token.access_token, /^access_/);
    const row = db.prepare("SELECT token,scopes,resources,confirmation FROM oauthAccessToken WHERE clientId='machine'").get();
    assert.equal(row.token, hash(token.access_token.slice("access_".length)));
    assert.deepEqual(JSON.parse(row.resources), requested);
    assert.deepEqual(JSON.parse(row.scopes), ["extra"]);
    assert.deepEqual(JSON.parse(row.confirmation), { jkt: thumb });
  } else {
    const keys = createLocalJWKSet(await (await server.send(new Request(mount + "/jwks"))).json());
    const { payload, protectedHeader } = await jwtVerify(token.access_token, keys, { issuer: mount, audience: b, typ: "at+jwt" });
    assert.ok(protectedHeader.kid);
    assert.equal(payload.sub, "machine");
    assert.equal(payload.azp, "machine");
    assert.equal(payload.client_id, "machine");
    assert.equal(payload.sid, undefined);
    assert.equal(payload.scope, "extra");
    assert.equal(payload.jti.length, 32);
    assert.deepEqual(payload.cnf, { jkt: thumb });
    assert.deepEqual(payload.aud, [a, b]);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM oauthAccessToken").get().n, 0);
    db.prepare("UPDATE oauthResource SET signingAlgorithm=?,signingKeyId=? WHERE id='B'").run(protectedHeader.alg, protectedHeader.kid);
    const second = await expect(issue([b], "extra"), 200);
    const single = await jwtVerify(second.access_token, keys, { issuer: mount, audience: b });
    assert.equal(single.protectedHeader.kid, protectedHeader.kid);
    assert.equal(single.payload.aud, b);
    assert.notEqual(single.payload.jti, payload.jti);
  }
  db.prepare("UPDATE oauthResource SET dpopBoundAccessTokensRequired=0 WHERE id='A'").run();
  const reverse = await expect(issue([b, a], "extra"), 200);
  assert.equal(reverse.expires_in, 110);
  assert.equal((await inspect(reverse.access_token)).tier, "reports");
  const repeat = await expect(issue([b, a, b], "extra"), 200);
  assert.equal((await inspect(repeat.access_token)).tier, opaque ? "files" : "reports");
  db.prepare("UPDATE oauthResource SET disabled=1,customClaims=? WHERE id='B'").run('{"tier":"updated"}');
  await expect(issue([b]), 400, "invalid_target");
  assert.equal((await inspect(token.access_token)).tier, opaque ? "updated" : "files");
  db.prepare("DELETE FROM oauthResource WHERE id='B'").run();
  assert.deepEqual(await inspect(token.access_token), { active: false });
}
