import assert from "node:assert/strict";
import {generateKeyPair, exportJWK, SignJWT} from "jose";

export async function compareAppleNative(t, {reference, goFixture, instrument}) {
  const {privateKey, publicKey} = await generateKeyPair("RS256", {extractable: true});
  const kid = "apple-test-key";
  const keys = {keys: [{...await exportJWK(publicKey), use:"sig", alg:"RS256", kid}]};
  const realFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (resource, init) => {
    const url = new URL(resource instanceof Request ? resource.url : resource);
    if (url.href === "https://appleid.apple.com/auth/keys") return Promise.resolve(Response.json(keys));
    assert.equal(url.hostname, "127.0.0.1", "provider fixture must stay local");
    return realFetch(resource, init);
  });

  const web = "org.example.web", mobile = "org.example.mobile", watch = "org.example.watch";
  for (const explicit of [false, true]) {
    const apple = {clientId: web, clientSecret: "local-client-assertion", appBundleIdentifier: mobile};
    if (explicit) apple.audience = [web, watch];
    const servers = [
      await reference(t, [], {socialProviders: {apple}}),
      await goFixture(t, [], {CONFORMANCE_APPLE_JWKS: JSON.stringify(keys), CONFORMANCE_APPLE_AUDIENCES: explicit ? [web, watch].join(",") : ""}),
    ];
    for (const server of servers) {
      for (const audience of [web, mobile, watch, "org.example.unrelated"]) {
        const {client} = instrument(server);
        const nonce = crypto.randomUUID();
        const email = audience + "@example.test";
        const token = await new SignJWT({email, email_verified: true, name: "Apple user", nonce})
          .setProtectedHeader({alg: "RS256", kid}).setSubject(audience)
          .setIssuer("https://appleid.apple.com").setAudience(audience).setIssuedAt().setExpirationTime("5m").sign(privateKey);
        const result = await client.signIn.social({provider:"apple", idToken:{token,nonce}});
        if (explicit ? [web,watch].includes(audience) : audience === mobile) {
          assert.equal(result.error, null);
          assert.ok(result.data.token);
          assert.equal((await client.getSession()).data.user.email, email);
        } else {
          assert.equal(result.error?.status, 401);
          assert.equal((await client.getSession()).data, null);
        }
      }
    }
  }
}
