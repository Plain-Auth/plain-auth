import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { auth0, keycloak, okta } from "better-auth/plugins/generic-oauth";

test("enterprise OIDC discovery and scopes match the configured provider presets", () => {
  const cases = JSON.parse(readFileSync(new URL("../providers/testdata/enterprise_oidc.json", import.meta.url)));
  const presets = { auth0, keycloak, okta };
  for (const { preset, input, issuer } of cases) {
    const key = preset === "auth0" ? "domain" : "issuer";
    const config = presets[preset]({ [key]: input, clientId: "client", clientSecret: "secret" });
    assert.equal(config.providerId, preset);
    assert.equal(config.discoveryUrl, issuer.replace(/\/$/, "") + "/.well-known/openid-configuration");
    assert.deepEqual(config.scopes, ["openid", "profile", "email"]);
  }
});
