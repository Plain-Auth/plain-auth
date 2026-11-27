import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { createHash, randomUUID } from "node:crypto";
import { requestToResourceInput, verifyAccessTokenRequest } from "@better-auth/core/oauth2";
import { createResourceServerChallenge } from "@better-auth/oauth-provider";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";

// The reference MCP package's protected handler (packages/mcp/src/handler.ts)
// is verifyAccessTokenRequest followed by a challenge with a JSON-RPC body.
// The package is not installed here, so this composes the same two calls.
function referenceMcpHandler(options, handler) {
  const resource = options.audience;
  const challengeOptions = { challengeScopes: options.challengeScopes ?? options.requiredScopes, dpopSigningAlgorithms: options.dpop?.signingAlgorithms };
  const toChallengeResponse = (error, request) => {
    const challenge = createResourceServerChallenge(error, resource, { ...challengeOptions, request });
    if (!challenge) throw error;
    const headers = new Headers(challenge.headers);
    headers.set("Content-Type", "application/json");
    return new Response(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: challenge.message }, id: null }), { status: challenge.statusCode, headers });
  };
  return async request => {
    let claims;
    try {
      claims = await verifyAccessTokenRequest(requestToResourceInput(request), {
        verifyOptions: { ...options.jwtVerifyOptions, issuer: options.issuer, audience: options.audience },
        jwksUrl: options.jwksUrl, requiredScopes: options.requiredScopes, dpop: options.dpop,
      });
    } catch (error) {
      return toChallengeResponse(error, request);
    }
    return handler(request, claims);
  };
}

// A protected MCP route answers each request with the same status,
// challenge, expose header, content type and JSON-RPC body on both runtimes.
export async function compareMcpHandler(t, goFixture) {
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
  const issuer = "https://issuer.example.test/api/auth", resource = "https://mcp.example.test/mcp";
  const now = Math.floor(Date.now() / 1000);
  const sign = (claims, typ = "at+jwt") => new SignJWT({ iss: issuer, aud: resource, sub: "user", azp: "app", iat: now, exp: now + 60, scope: "mcp:read", ...claims })
    .setProtectedHeader({ alg: "ES256", kid: "key", ...(typ && { typ }) }).sign(privateKey);
  const proofKeys = await generateKeyPair("ES256");
  const proofJwk = await exportJWK(proofKeys.publicKey);
  const jkt = await calculateJwkThumbprint(proofJwk);
  const bound = await sign({ cnf: { jkt } });
  const proof = token => new SignJWT({ htm: "POST", htu: resource, jti: randomUUID(), ath: createHash("sha256").update(token).digest("base64url") })
    .setIssuedAt().setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: proofJwk }).sign(proofKeys.privateKey);
  const reference = referenceMcpHandler({
    issuer, audience: resource, jwksUrl, requiredScopes: ["mcp:read"], challengeScopes: ["mcp:read", "mcp:write"],
    jwtVerifyOptions: { typ: "at+jwt", requiredClaims: ["azp"] }, dpop: { signingAlgorithms: ["ES256"] },
  }, async (_request, claims) => Response.json({ sub: claims.sub }));
  const server = await goFixture(t, [], { CONFORMANCE_MCP_HANDLER: JSON.stringify({
    Issuer: issuer, Audience: [resource], JWKSURL: jwksUrl, RequiredClaims: ["azp"], RequiredScopes: ["mcp:read"], ChallengeScopes: ["mcp:read", "mcp:write"],
    DPoP: { SigningAlgorithms: ["ES256"] },
  }) });
  const replayed = await proof(bound);
  const cases = [
    ["no token", ""],
    ["basic", "Basic " + Buffer.from("a:b").toString("base64")],
    ["expired", "Bearer " + await sign({ exp: now - 10 })],
    ["wrong issuer", "Bearer " + await sign({ iss: "https://evil.example.test" })],
    ["wrong audience", "Bearer " + await sign({ aud: "https://other.example.test/mcp" })],
    ["typ mismatch", "Bearer " + await sign({}, "JWT")],
    ["missing azp", "Bearer " + await sign({ azp: undefined })],
    ["insufficient scope", "Bearer " + await sign({ scope: "other" })],
    ["bound as bearer", "Bearer " + bound],
    ["DPoP fresh proof", "DPoP " + bound, () => proof(bound)],
    ["DPoP replayed proof", "DPoP " + bound, () => replayed],
    ["DPoP replayed again", "DPoP " + bound, () => replayed],
    ["success", "Bearer " + await sign({})],
  ];
  const read = async res => ({ status: res.status, challenge: res.headers.get("www-authenticate"), expose: res.headers.get("access-control-expose-headers"),
    type: res.headers.get("content-type")?.split(";")[0], body: await res.json() });
  for (const [name, authorization, makeProof] of cases) {
    const headers = {};
    if (authorization) headers.authorization = authorization;
    const dpop = makeProof ? await makeProof() : undefined;
    const want = await read(await reference(new Request(resource, { method: "POST", headers: dpop ? { ...headers, dpop } : headers })));
    const got = await read(await server.send(new Request(server.baseURL + "/mcp", { method: "POST", headers: dpop ? { ...headers, dpop } : headers })));
    assert.deepEqual(got, want, name);
  }
}
