import assert from "node:assert/strict";
import { APIError } from "better-auth/api";
import { createInsufficientScopeError } from "better-auth/oauth2";
import { createResourceServerChallenge } from "@better-auth/oauth-provider";

export async function compareResourceChallenges(t, goFixture) {
  const resources = ["https://api.example.test/files/?tenant=west", "urn:service:billing", "files-app"];
  const mappings = {
    "urn:service:billing": "https://billing.example.test/.well-known/oauth-protected-resource",
    "files-app": "https://files.example.test/.well-known/oauth-protected-resource",
  };
  const scopes = ["files:read", "files:read", "reports:view"];
  const algs = ["ES256", "EdDSA"];
  const go = await goFixture(t, [], {
    CONFORMANCE_RESOURCE_CHALLENGES: JSON.stringify({
      Resources: resources, Options: {MetadataMappings: mappings, Scopes: scopes, DPoPSigningAlgorithms: algs},
    }),
  });
  const denied = {status: 403, message: "Organization membership required"};
  const expired = {status: 401, code: "invalid_token", message: "Expired credential", description: "The credential has expired"};
  const missing = {status: 401, message: "Missing authorization header"};
  const proof = {status: 401, code: "invalid_dpop_proof", message: "Invalid proof"};
  const bound = {...expired, description: "DPoP proof required"};
  const scope = {status: 403, code: "insufficient_scope", missingScopes: ["files:write", "billing:read", "files:write"]};
  for (const [name, authHeader, failure] of [
    ["no credentials", "", missing],
    ["expired bearer", "Bearer sample", expired],
    ["expired proof-bound token", "dPoP sample", expired],
    ["presented DPoP with a generic authentication failure", "DPoP sample", missing],
    ["bearer presentation of a bound token", "Bearer sample", bound],
    ["unsupported presentation", "Basic sample", bound],
    ["proof error without credentials", "", proof],
    ["detached proof error", null, proof],
    ["bearer scope step-up", "Bearer sample", scope],
    ["DPoP scope step-up", "DPoP sample", scope],
    ["permission denial", "Bearer sample", denied],
    ["server failure", "DPoP sample", {status: 500, message: "Internal failure"}],
    ["public description with punctuation", "Bearer sample", {...expired, description: 'Expired "session"\nfor\\team'}],
    ["description outside HTTP character set", "Bearer sample", {...expired, description: "éß"}],
  ]) {
    await t.test(name, async () => {
      const failures = {401: "UNAUTHORIZED", 403: "FORBIDDEN", 500: "INTERNAL_SERVER_ERROR"};
      const error = failure.missingScopes
        ? createInsufficientScopeError(failure.missingScopes)
        : new APIError(failures[failure.status], {message: failure.message, error: failure.code, error_description: failure.description});
      const expected = createResourceServerChallenge(error, resources, {
        resourceMetadataMappings: mappings, challengeScopes: scopes, dpopSigningAlgorithms: algs,
        request: authHeader === null ? undefined : {authorizationHeader: authHeader},
      });
      const path = "/__fixture/resource-challenge" + (authHeader === null ? "?detached" : "");
      const response = await fetch(go.baseURL + path, {
        method: "POST", headers: authHeader ? {authorization: authHeader} : {},
        body: JSON.stringify(failure),
      });
      assert.equal(response.status, expected?.statusCode ?? failure.status);
      const headers = new Headers(expected?.headers);
      for (const key of ["www-authenticate", "access-control-expose-headers"]) {
        assert.equal(response.headers.get(key), headers.get(key));
      }
      if (expected) assert.deepEqual(await response.json(), expected.body);
      else assert.equal(await response.text(), "");
    });
  }
}

// A loopback HTTP resource gets the same challenge on both runtimes, with
// an HTTP metadata link.
export async function compareLoopbackChallenge(t, goFixture) {
  const resources = ["http://localhost:3000/mcp"];
  const go = await goFixture(t, [], { CONFORMANCE_RESOURCE_CHALLENGES: JSON.stringify({ Resources: resources, Options: {} }) });
  const error = new APIError("UNAUTHORIZED", { message: "token expired", error: "invalid_token", error_description: "token expired" });
  const expected = createResourceServerChallenge(error, resources, { request: { authorizationHeader: "Bearer sample" } });
  const response = await fetch(go.baseURL + "/__fixture/resource-challenge", {
    method: "POST", headers: { authorization: "Bearer sample" },
    body: JSON.stringify({ status: 401, code: "invalid_token", message: "token expired", description: "token expired" }),
  });
  assert.equal(response.status, expected.statusCode);
  assert.equal(response.headers.get("www-authenticate"), new Headers(expected.headers).get("www-authenticate"));
  assert.match(response.headers.get("www-authenticate"), /resource_metadata="http:\/\/localhost:3000\/\.well-known\/oauth-protected-resource\/mcp"/);
}
