import assert from "node:assert/strict";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { CompactSign, decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";

export async function exerciseSignedIntrospection({ server, db, credentials, config, created, cookie }) {
  const mount = server.baseURL + "/api/auth";
  const owner = { client_id: credentials.client_id, client_secret: credentials.client_secret };
  const other = await created({ grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" }, { cookie });
  const reader = { client_id: other.client_id, client_secret: other.client_secret };
  const user = db.prepare("SELECT id FROM user LIMIT 1").get().id;
  const now = Math.floor(Date.now() / 1000);
  const audience = "urn:signed:" + randomUUID();
  const resource = randomUUID();
  db.prepare("INSERT INTO oauthResource(id,identifier,name,allowedScopes,customClaims) VALUES(?,?,?,?,?)")
    .run(resource, audience, "Reports", '["reports"]', '{"tier":"gold"}');
  const link = db.prepare("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES(?,?,?)");
  link.run(randomUUID(), owner.client_id, audience);
  // The independent issuer owns an ephemeral signing key. Only its public
  // material crosses into the database used by the introspection endpoint.
  const kid = randomUUID(), pair = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = {
    id: kid, alg: "EdDSA", crv: "Ed25519", createdAt: new Date(),
    publicKey: JSON.stringify(await exportJWK(pair.publicKey)), privateKey: JSON.stringify(await exportJWK(pair.privateKey))
  };
  db.prepare("INSERT INTO jwks(id,publicKey,privateKey,createdAt,alg,crv) VALUES(?,?,?,?,?,?)")
    .run(kid, jwk.publicKey, "unused", jwk.createdAt.toISOString(), jwk.alg, jwk.crv);
  const issuer = betterAuth({
    database: db, baseURL: server.baseURL, secret: "fixture-secret-for-signed-introspection-0123456789",
    telemetry: { enabled: false }, plugins: [jwt({ adapter: { getJwks: async () => [jwk] }, jwks: { disablePrivateKeyEncryption: true } }), oauthProvider(config)]
  });
  const request = (route, fields) => new Request(mount + "/oauth2/" + route, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields)
  });
  async function inspect(token, caller = owner, hint) {
    const result = await server.send(request("introspect", { ...caller, token, ...(hint && { token_type_hint: hint }) }));
    const body = await result.json();
    assert.equal(result.status, 200, JSON.stringify(body));
    assert.equal(result.headers.get("cache-control"), "no-store");
    return body;
  }

  const exchange = await issuer.handler(request("token", { ...owner, grant_type: "client_credentials", scope: "reports", resource: audience }));
  const issued = await exchange.json();
  assert.equal(exchange.status, 200, JSON.stringify(issued));
  const signed = decodeJwt(issued.access_token);
  assert.equal(signed.aud, audience);
  assert.equal(signed.tier, "gold");
  const expected = { ...signed, active: true, client_id: owner.client_id, token_type: "Bearer" };
  assert.deepEqual(await inspect(issued.access_token), expected);
  assert.deepEqual(await inspect(issued.access_token, reader), { active: false });
  link.run(randomUUID(), reader.client_id, audience);
  db.prepare("UPDATE oauthResource SET disabled=1,customClaims=? WHERE id=?").run('{"tier":"changed"}', resource);
  assert.deepEqual(await inspect(issued.access_token, reader, "access_token"), expected);

  const sign = extra => new SignJWT({ iss: mount, azp: owner.client_id, exp: now + 600, ...extra })
    .setProtectedHeader({ alg: "EdDSA", kid }).sign(pair.privateKey);
  const raw = text => new CompactSign(new TextEncoder().encode(text)).setProtectedHeader({ alg: "EdDSA", kid }).sign(pair.privateKey);
  const sid = randomUUID(), cookieValue = randomUUID();
  db.prepare("INSERT INTO session(id,userId,token,createdAt,updatedAt,expiresAt) VALUES(?,?,?,?,?,?)")
    .run(sid, user, cookieValue, new Date().toISOString(), new Date().toISOString(), new Date((now + 600) * 1000).toISOString());
  const original = db.prepare("SELECT subjectType,redirectUris FROM oauthClient WHERE clientId=?").get(owner.client_id);
  const sector = "reports.example.test:8443";
  db.prepare("UPDATE oauthClient SET subjectType='pairwise',redirectUris=? WHERE clientId=?").run(JSON.stringify(["https://" + sector + "/return"]), owner.client_id);
  const claims = { sub: user, sid, aud: [audience, mount + "/oauth2/userinfo"], cnf: { jkt: "sender-key" }, active: false, client_id: "ignored", token_type: "ignored" };
  const bound = await sign(claims);
  const subject = createHmac("sha256", "p".repeat(32)).update(sector + "." + user).digest("base64");
  assert.deepEqual(await inspect(bound, reader), { ...decodeJwt(bound), active: true, client_id: owner.client_id, token_type: "DPoP", sub: subject });
  assert.equal((await inspect(await sign({ sub: owner.client_id }))).sub, owner.client_id);
  const timeless = await sign({ exp: undefined, iat: now + 120 });
  assert.deepEqual(await inspect(timeless), { ...decodeJwt(timeless), active: true, client_id: owner.client_id, token_type: "Bearer" });
  db.prepare("UPDATE session SET expiresAt=? WHERE id=?").run(new Date(0).toISOString(), sid);
  assert.deepEqual(await inspect(bound), { active: false });
  db.prepare("UPDATE oauthClient SET disabled=1 WHERE clientId=?").run(owner.client_id);
  assert.deepEqual(await inspect(issued.access_token, reader), { active: false });
  db.prepare("UPDATE oauthClient SET disabled=0 WHERE clientId=?").run(owner.client_id);

  const grant = randomUUID();
  db.prepare("INSERT INTO oauthRefreshToken(id,clientId,userId,token,scopes,createdAt,expiresAt) VALUES(?,?,?,?,?,?,?)")
    .run(grant, owner.client_id, user, randomUUID(), '["reports"]', new Date().toISOString(), new Date((now + 600) * 1000).toISOString());
  async function collision(token, fallsThrough) {
    const digest = createHash("sha256").update(token).digest("base64url");
    db.prepare("UPDATE oauthRefreshToken SET token=? WHERE id=?").run(digest, grant);
    assert.equal((await inspect(token, owner, "refresh_token")).active, true);
    const result = await inspect(token);
    if (fallsThrough) {
      assert.equal(result.active, true);
      assert.equal(result.scope, "reports");
      assert.equal(result.azp, undefined);
    } else {
      assert.deepEqual(result, { active: false });
    }
  }
  const unrelated = await generateKeyPair("EdDSA");
  const otherSignature = await new SignJWT({ iss: mount, azp: owner.client_id, exp: now + 600 })
    .setProtectedHeader({ alg: "EdDSA", kid }).sign(unrelated.privateKey);
  await collision(otherSignature, true);
  for (const payload of [{ iss: "https://elsewhere.example", exp: 1 }, { nbf: now + 300 }, { iat: "yesterday" }, { exp: null }]) {
    await collision(await sign(payload), true);
  }
  for (const token of [await sign({ exp: 1 }), await sign({ azp: undefined }), await sign({ sid }),
  await sign({ aud: Array(65).fill(mount + "/oauth2/userinfo") }), await raw("[]"), await raw("no JSON here")]) {
    await collision(token, false);
  }
  db.prepare("DELETE FROM oauthResource WHERE id=?").run(resource);
  assert.deepEqual(await inspect(issued.access_token), { active: false });
  assert.deepEqual(await inspect(issued.access_token, reader), { active: false });
  db.prepare("DELETE FROM jwks WHERE id=?").run(kid);
  db.prepare("DELETE FROM oauthRefreshToken WHERE id=?").run(grant);
  db.prepare("UPDATE oauthClient SET subjectType=?,redirectUris=? WHERE clientId=?").run(original.subjectType, original.redirectUris, owner.client_id);
}
