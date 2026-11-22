import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { randomUUID } from "node:crypto";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { deriveDpopAth } from "@better-auth/core/oauth2";
import { issueDelegatedGrant } from "./oauth-refresh-introspection.mjs";

export async function compareUserInfo(t, { reference, goFixture }) {
  const settings = {
    loginPage: "/login", consentPage: "/consent", allowDynamicClientRegistration: true,
    scopes: ["openid", "email", "profile", "offline_access"], pairwiseSecret: "p".repeat(32),
    clientRegistrationAllowedScopes: ["openid", "email", "profile", "offline_access"],
    prefix: { clientSecret: "fixture_", opaqueAccessToken: "access_" },
  };
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "Go" ? await goFixture(t, ["oauth-provider", "jwt"], { CONFORMANCE_CLIENT_REGISTRATION: "protected" }) :
        await reference(t, [jwt(), oauthProvider(settings)], { rateLimit: { enabled: false } });
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const issuer = betterAuth({
        database: db, baseURL: server.baseURL, secret: "local-conformance-0123456789-abcdefghijk",
        telemetry: { enabled: false }, emailAndPassword: { enabled: true },
        plugins: [jwt(), oauthProvider(settings)], rateLimit: { enabled: false },
      });
      await exerciseUserInfo({ issuer, db, server });
    });
  }
}

async function exerciseUserInfo({issuer, db, server}) {
  const name = "Anne Marie Chen", email = "userinfo@issuer.test";
  const scopes = ["openid", "email", "profile", "offline_access"];
  const { issued, app } = await issueDelegatedGrant(issuer, db, {
    name, email, scopes, origin: server.baseURL, callback: "https://profile.example.test/return",
  });
  const sub = decodeJwt(issued.id_token).sub;
  assert.ok(sub);
  const row = db.prepare("SELECT * FROM oauthAccessToken WHERE clientId=?").get(app.client_id);
  const url = server.baseURL + "/api/auth/oauth2/userinfo";
  const token = issued.access_token;
  const call = (method, authorization, body, proof) => server.send(new Request(url, {
    method, headers: { ...(authorization && { authorization }), ...(body && { "content-type": "application/x-www-form-urlencoded" }),
      ...(proof && { dpop: proof }) }, body: body && new URLSearchParams(body),
  }));
  async function ok(r, expected) {
    const body = await r.json();
    assert.equal(r.status, 200, JSON.stringify(body));
    assert.match(r.headers.get("cache-control"), /no-store/);
    assert.deepEqual(body, expected);
  }
  async function problem(r, status, code, challenge) {
    const body = await r.json();
    assert.equal(r.status, status, JSON.stringify(body));
    assert.equal(body.error, code);
    if (challenge) {
      assert.match(r.headers.get("www-authenticate"), challenge);
      assert.match(r.headers.get("access-control-expose-headers"), /WWW-Authenticate/i);
    }
  }
  const expected = { sub, name, given_name: "Anne Marie", family_name: "Chen", email, email_verified: false };
  const resource = "urn:reports:userinfo";
  db.prepare("INSERT INTO oauthResource(id,identifier,name,allowedScopes) VALUES(?,?,?,?)").run(randomUUID(), resource, "Reports", JSON.stringify(scopes));
  const signed = await issueDelegatedGrant(issuer, db, {
    name: "Signed User", email: "signed-userinfo@issuer.test", scopes, resource, origin: server.baseURL, callback: "https://signed-profile.example.test/return",
  });
  assert.equal(decodeJwt(signed.issued.access_token).azp, signed.app.client_id);
  await ok(await call("GET", "Bearer " + signed.issued.access_token), {
    sub: decodeJwt(signed.issued.id_token).sub, name: "Signed User", given_name: "Signed", family_name: "User", email: "signed-userinfo@issuer.test", email_verified: false,
  });
  db.prepare("DELETE FROM oauthResource WHERE identifier=?").run(resource);
  await problem(await call("GET", "Bearer " + signed.issued.access_token), 401, "invalid_token", /^Bearer /);

  await ok(await call("GET", "Bearer " + token), expected);
  await ok(await call("POST", null, { access_token: token }), expected);
  await ok(await call("POST", token), expected);
  await problem(await call("POST", "Bearer " + token, { access_token: token }), 400, "invalid_request");
  await problem(await call("GET"), 401, "invalid_request", /^Bearer, DPoP algs=/);
  await problem(await call("GET", "Bearer absent"), 401, "invalid_token", /^Bearer error="invalid_token"/);
  await problem(await call("GET", "DPoP absent"), 401, "invalid_token", /^DPoP error="invalid_token"/);
  await problem(await call("GET", "Bearer " + issued.refresh_token), 401, "invalid_token", /^Bearer /);
  const update = db.prepare("UPDATE oauthAccessToken SET scopes=?,requestedUserInfoClaims=?,confirmation=? WHERE id=?");
  update.run('["openid"]', null, null, row.id);
  await ok(await call("GET", "Bearer " + token), { sub });
  update.run('["openid"]', '["family_name","email_verified"]', null, row.id);
  await ok(await call("GET", "Bearer " + token), { sub, family_name: "Chen", email_verified: false });
  update.run('["profile"]', null, null, row.id);
  await problem(await call("GET", "Bearer " + token), 400, "invalid_scope");
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  update.run('["openid"]', null, JSON.stringify({ jkt }), row.id);
  await problem(await call("POST", null, { access_token: token }), 401, "invalid_token", /^DPoP /);
  await problem(await call("GET", "DPoP " + token), 401, "invalid_dpop_proof", /^DPoP /);
  const proof = await new SignJWT({ htm: "GET", htu: url, ath: await deriveDpopAth(token) })
    .setJti(randomUUID()).setIssuedAt().setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk }).sign(privateKey);
  await ok(await call("GET", "DPoP " + token, null, proof), { sub });
  await problem(await call("GET", "DPoP " + token, null, proof), 401, "invalid_dpop_proof", /^DPoP /);
  update.run(row.scopes, row.requestedUserInfoClaims, row.confirmation, row.id);
  db.prepare("UPDATE session SET expiresAt=? WHERE id=?").run("2020-01-01T00:00:00.000Z", row.sessionId);
  await problem(await call("GET", "Bearer " + token), 401, "invalid_token", /^Bearer /);
}
