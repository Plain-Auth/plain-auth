import assert from "node:assert/strict";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

// The metadata contributor both runtimes register.
export function extensionMetadata({ type }) {
  return { credential_issuer: "https://wallet.example.test/" + type, issuer: "forged", token_endpoint: "forged" };
}

// An extension adds discovery fields to each served document and cannot
// replace the provider's own.
export async function compareExtensionMetadata(t, { reference, goFixture }) {
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "reference" ? await reference(t, [jwt(), oauthProvider({
        loginPage: "/login", consentPage: "/consent", scopes: ["openid", "email", "reports", "extra"],
        extensions: [{ metadata: input => extensionMetadata({ type: input.type }) }],
      })], { rateLimit: { enabled: false } }) : await goFixture(t, ["oauth-provider", "jwt"], {
        CONFORMANCE_CLIENT_REGISTRATION: "protected", CONFORMANCE_OAUTH_EXTENSIONS: "1",
      });
      const res = await server.send(new Request(server.baseURL + "/api/auth/.well-known/openid-configuration"));
      assert.equal(res.status, 200);
      const doc = await res.json();
      assert.equal(doc.credential_issuer, "https://wallet.example.test/openid-configuration");
      assert.equal(doc.issuer, server.baseURL + "/api/auth");
      assert.equal(doc.token_endpoint, server.baseURL + "/api/auth/oauth2/token");
    });
  }
}
