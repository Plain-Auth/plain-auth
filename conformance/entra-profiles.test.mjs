import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { microsoftEntraId } from "better-auth/plugins/generic-oauth";

test("single-tenant Entra binds directory object IDs and merges only matching Graph subjects", async (t) => {
  const tenantId = "363368ff-7777-452f-886c-a111d48741bb";
  const config = microsoftEntraId({ tenantId: tenantId.toUpperCase(), clientId: "client", clientSecret: "secret" });
  assert.equal(config.discoveryUrl, "https://login.microsoftonline.com/" + tenantId + "/v2.0/.well-known/openid-configuration");
  assert.deepEqual(config.scopes, ["openid", "profile", "email"]);
  assert.equal(config.requireIdTokenVerification, true);
  assert.throws(() => microsoftEntraId({tenantId: "common", clientId: "client", clientSecret: "secret"}));
  const cases = JSON.parse(readFileSync(new URL("../providers/testdata/entra_profiles.json", import.meta.url)));
  for (const sample of cases) {
    await t.test(sample.name, async (t) => {
      t.mock.method(globalThis, "fetch", async (resource, init) => {
        const request = new Request(resource, init);
        assert.equal(request.url, "https://graph.microsoft.com/oidc/userinfo");
        assert.equal(request.headers.get("Authorization"), "Bearer access");
        return Response.json(sample.graph);
      });
      // The mapper receives the claims after the SDK's signature-verification step.
      const payload = Buffer.from(JSON.stringify({sub: "pairwise-id", ...sample.token})).toString("base64url");
      const profile = await config.getUserInfo({ accessToken: "access", idToken: "e30." + payload + ".fixture" });
      assert.equal(config.accountSubject({profile}), "object-id");
      assert.equal(profile.email, sample.wantEmail);
      assert.equal(profile.name, sample.wantName);
      assert.equal(profile.emailVerified, sample.wantVerified);
    });
  }
});
