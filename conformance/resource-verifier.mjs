import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { createHash, randomUUID } from "node:crypto";
import { verifyAccessTokenRequest, verifyBearerToken } from "@better-auth/core/oauth2";
import { oauthProviderResourceClient } from "@better-auth/oauth-provider/resource-client";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";

// Both runtimes verify the same bearer tokens against a JWKS served on
// loopback and answer the same status, error, description and scopes. A
// token without exp is the documented difference: this runtime refuses it.
export async function compareResourceVerifier(t, goFixture) {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "key", alg: "ES256", use: "sig" };
  const jwks = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  jwks.listen(0, "127.0.0.1");
  await once(jwks, "listening");
  t.after(() => jwks.close());
  const jwksUrl = `http://127.0.0.1:${jwks.address().port}/jwks`;
  const issuer = "https://issuer.example.test/api/auth", audience = "https://api.example.test";
  const now = Math.floor(Date.now() / 1000);
  const sign = (claims, typ = "at+jwt") => {
    const jwt = new SignJWT({ iss: issuer, aud: audience, sub: "user", azp: "app", iat: now, exp: now + 60, scope: "read write", ...claims });
    return jwt.setProtectedHeader({ alg: "ES256", kid: "key", ...(typ && { typ }) }).sign(privateKey);
  };
  const cases = [
    ["valid", await sign({}), ["read"]],
    ["expired", await sign({ exp: now - 10 }), []],
    ["wrong audience", await sign({ aud: "https://other.example.test" }), []],
    ["wrong issuer", await sign({ iss: "https://evil.example.test" }), []],
    ["typ JWT", await sign({}, "JWT"), []],
    ["missing scopes", await sign({}), ["read", "admin", "billing"]],
    ["empty scope", await sign({ scope: "" }), []],
    ["opaque", "access_opaque", []],
    ["bound", await sign({ cnf: { jkt: "thumb" } }), []],
  ];
  const reference = async (token, requiredScopes) => {
    try {
      const payload = await verifyBearerToken(token, { jwksUrl, verifyOptions: { issuer, audience, typ: "at+jwt" }, requiredScopes });
      return { status: 200, payload };
    } catch (error) {
      if (!error.statusCode) throw error;
      const scope = error.body?.scope;
      return { status: error.statusCode, error: error.body?.error, error_description: error.body?.error_description, scopes: scope ? scope.split(" ") : undefined };
    }
  };
  const server = await goFixture(t, [], { CONFORMANCE_RESOURCE_VERIFIER: JSON.stringify({ Issuer: issuer, Audience: [audience], JWKSURL: jwksUrl }) });
  const go = async (token, scopes) => {
    const res = await server.send(new Request(server.baseURL + "/__fixture/verify-bearer", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, scopes }),
    }));
    const body = await res.json();
    return { ...body, scopes: body.scopes ?? undefined };
  };
  for (const [name, token, scopes] of cases) {
    const [want, got] = [await reference(token, scopes), await go(token, scopes)];
    assert.equal(got.status, want.status, name + " " + JSON.stringify([want, got]));
    if (want.status === 200) {
      assert.equal(got.payload.sub, want.payload.sub, name);
      assert.equal(got.payload.client_id, want.payload.client_id, name);
      assert.equal(got.payload.scope, want.payload.scope, name);
      continue;
    }
    assert.equal(got.error, want.error, name);
    assert.deepEqual(got.scopes, want.scopes, name);
    // The bound-token text names request verification instead of a function.
    if (name !== "bound") assert.equal(got.error_description, want.error_description, name);
  }
  // Requests: both runtimes check the scheme and the sender binding alike,
  // each with its own replay store.
  const proofKeys = await generateKeyPair("ES256");
  const proofJwk = await exportJWK(proofKeys.publicKey);
  const jkt = await calculateJwkThumbprint(proofJwk);
  const bearer = await sign({}), bound = await sign({ cnf: { jkt } });
  const target = server.baseURL + "/__fixture/verified-resource";
  const proof = (token, { method = "GET", url = target, ath = createHash("sha256").update(token).digest("base64url") } = {}) =>
    new SignJWT({ htm: method, htu: url, jti: randomUUID(), ath }).setIssuedAt()
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: proofJwk }).sign(proofKeys.privateKey);
  const requests = [
    ["bearer", "Bearer " + bearer],
    ["bound", "DPoP " + bound, () => proof(bound)],
    ["bound as bearer", "Bearer " + bound, () => proof(bound)],
    ["unbound as DPoP", "DPoP " + bearer],
    ["no proof", "DPoP " + bound],
    ["wrong method", "DPoP " + bound, () => proof(bound, { method: "POST" })],
    ["wrong token", "DPoP " + bound, () => proof(bound, { ath: createHash("sha256").update("other").digest("base64url") })],
    ["basic", "Basic " + Buffer.from("a:b").toString("base64")],
    ["missing", ""],
  ];
  const referenceRequest = async (authorizationHeader, dpopProofJwt) => {
    try {
      const payload = await verifyAccessTokenRequest({ authorizationHeader, dpopProofJwt, method: "GET", url: target }, { jwksUrl, verifyOptions: { issuer, audience, typ: "at+jwt" } });
      return { status: 200, payload };
    } catch (error) {
      if (!error.statusCode) throw error;
      return { status: error.statusCode, error: error.body?.error, error_description: error.body?.error_description, message: error.body?.message };
    }
  };
  const goRequest = async (authorization, dpop) => {
    const headers = {};
    if (authorization) headers.authorization = authorization;
    if (dpop) headers.dpop = dpop;
    return (await server.send(new Request(target, { headers }))).json();
  };
  for (const [name, authorization, makeProof] of requests) {
    const want = await referenceRequest(authorization, makeProof ? await makeProof() : undefined);
    const got = await goRequest(authorization, makeProof ? await makeProof() : undefined);
    assert.equal(got.status, want.status, name + " " + JSON.stringify([want, got]));
    if (want.status === 200) {
      assert.equal(got.payload.sub, want.payload.sub, name);
      continue;
    }
    assert.equal(got.error || undefined, want.error, name);
    assert.equal(got.error_description || undefined, want.error_description, name);
    assert.equal(got.message, want.message, name);
  }
  // A proof is spent once on each runtime.
  const spent = await proof(bound);
  assert.equal((await referenceRequest("DPoP " + bound, spent)).status, 200);
  const replayed = await referenceRequest("DPoP " + bound, spent);
  assert.equal((await goRequest("DPoP " + bound, spent)).status, 200);
  const goReplayed = await goRequest("DPoP " + bound, spent);
  assert.equal(goReplayed.status, replayed.status);
  assert.equal(goReplayed.error, replayed.error);
  assert.equal(goReplayed.error_description, replayed.error_description);

  // A protected route answers each failure with the same challenge and
  // body, and passes a verified request through.
  const actions = oauthProviderResourceClient().getActions();
  const route = "https://api.example.test/__fixture/protected";
  const routeProof = (token, extra = {}) => proof(token, { url: route, ...extra });
  const routes = [
    ["no credentials", ""],
    ["expired bearer", "Bearer " + await sign({ exp: now - 10 })],
    ["unbound DPoP", "DPoP " + bearer],
    ["bound as bearer", "Bearer " + bound, () => routeProof(bound)],
    ["bearer scope", "Bearer " + await sign({ scope: "other" })],
    ["DPoP scope", "DPoP " + await sign({ scope: "other", cnf: { jkt } }), () => routeProof(bound)],
    ["valid bearer", "Bearer " + bearer],
    ["valid DPoP", "DPoP " + bound, () => routeProof(bound)],
  ];
  for (const [name, authorization, makeProof] of routes) {
    const headers = {};
    if (authorization) headers.authorization = authorization;
    let want;
    try {
      const referenceHeaders = { ...headers };
      if (makeProof) referenceHeaders.dpop = await makeProof();
      const payload = await actions.verifyAccessTokenRequest(new Request(route, { headers: referenceHeaders }), { verifyOptions: { issuer, audience, typ: "at+jwt" }, jwksUrl, requiredScopes: ["read"] });
      want = { status: 200, payload };
    } catch (error) {
      if (!error.statusCode) throw error;
      const h = new Headers(error.headers);
      want = { status: error.statusCode, challenge: h.get("www-authenticate"), expose: h.get("access-control-expose-headers"), body: error.body };
    }
    const goHeaders = { ...headers };
    if (makeProof) goHeaders.dpop = await makeProof();
    const res = await server.send(new Request(server.baseURL + "/__fixture/protected", { headers: goHeaders }));
    const got = { status: res.status, challenge: res.headers.get("www-authenticate"), expose: res.headers.get("access-control-expose-headers"), body: await res.json() };
    assert.equal(got.status, want.status, name + " " + JSON.stringify([want, got]));
    if (want.status === 200) {
      assert.equal(got.body.payload.sub, want.payload.sub, name);
      continue;
    }
    assert.equal(got.challenge, want.challenge, name);
    assert.equal(got.expose, want.expose, name);
    assert.deepEqual(got.body, want.body, name);
  }

  // A token without exp passes the other runtime but not this one.
  const endless = await sign({ exp: undefined });
  assert.equal((await reference(endless, [])).status, 200);
  assert.deepEqual(await go(endless, []), { status: 401, error: "invalid_token", error_description: "invalid access token", message: "invalid access token", scopes: undefined });
}

// Both runtimes introspect tokens at the same scripted endpoint with the
// same form and headers, and answer each response alike.
export async function compareRemoteVerifier(t, goFixture) {
  const issuer = "https://issuer.example.test/api/auth", audience = "https://api.example.test";
  const now = Math.floor(Date.now() / 1000);
  const active = extra => ({ active: true, iss: issuer, aud: audience, sub: "user", client_id: "app", exp: now + 60, scope: "read", ...extra });
  const answers = {
    "access_active": [200, active({})],
    "access_inactive": [200, { active: false }],
    "access_no_audience": [200, active({ aud: undefined })],
    "access_other_audience": [200, active({ aud: "https://other.example.test" })],
    "access_expired": [200, active({ exp: now - 10 })],
    "access_other_issuer": [200, active({ iss: "https://evil.example.test" })],
    "access_failing": [500, { error: "server_error" }],
  };
  const recorded = [];
  const stub = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    const form = new URLSearchParams(body);
    recorded.push({ form: Object.fromEntries(form), accept: req.headers.accept, type: req.headers["content-type"] });
    const [status, answer] = answers[form.get("token")] ?? [200, { active: false }];
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(answer));
  });
  stub.listen(0, "127.0.0.1");
  await once(stub, "listening");
  t.after(() => stub.close());
  const introspectUrl = `http://127.0.0.1:${stub.address().port}/introspect`;
  const remote = { introspectUrl, clientId: "api", clientSecret: "api-secret" };
  const reference = async token => {
    try {
      const payload = await verifyBearerToken(token, { verifyOptions: { issuer, audience }, remoteVerify: remote });
      return { status: 200, payload };
    } catch (error) {
      if (!error.statusCode) throw error;
      return { status: error.statusCode, error: error.body?.error, error_description: error.body?.error_description };
    }
  };
  const server = await goFixture(t, [], { CONFORMANCE_RESOURCE_VERIFIER: JSON.stringify({
    Issuer: issuer, Audience: [audience], Remote: { IntrospectionURL: introspectUrl, ClientID: "api", ClientSecret: "api-secret" },
  }) });
  const go = async token => (await server.send(new Request(server.baseURL + "/__fixture/verify-bearer", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, scopes: [] }),
  }))).json();
  for (const token of Object.keys(answers)) {
    recorded.length = 0;
    const want = await reference(token);
    const got = await go(token);
    assert.equal(got.status, want.status, token + " " + JSON.stringify([want, got]));
    if (want.status === 200) {
      assert.equal(got.payload.sub, want.payload.sub, token);
    } else if (want.status !== 500) {
      assert.equal(got.error, want.error, token);
      assert.equal(got.error_description, want.error_description, token);
    }
    assert.equal(recorded.length, 2, token);
    assert.deepEqual(recorded[1], recorded[0], token);
    assert.deepEqual(recorded[0].form, { client_id: "api", client_secret: "api-secret", token, token_type_hint: "access_token" });
  }
}
