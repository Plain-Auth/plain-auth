import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oauthProviderResourceClient } from "@better-auth/oauth-provider/resource-client";

export async function compareResourceDiscovery(t, goFixture) {
  const publicURL = "https://accounts.example.test/gateway/auth";
  const issuer = "https://issuer.example.test/tenant";
  const resource = "https://api.example.test/reports/v1/?tenant=west";
  const scopes = ["read:reports", "write:reports"];
  const externalScopes = ["finance:view"];
  const allFields = {
    resource, authorization_servers: [issuer, "https://billing.example.test/issuer"],
    jwks_uri: "https://api.example.test/keys",
    scopes_supported: ["read:reports", "finance:view"], bearer_methods_supported: ["header"],
    resource_signing_alg_values_supported: ["ES256"], resource_name: "Reports",
    resource_documentation: "https://docs.example.test/reports",
    resource_policy_uri: "https://docs.example.test/privacy", resource_tos_uri: "https://docs.example.test/terms",
    tls_client_certificate_bound_access_tokens: false, authorization_details_types_supported: ["report"],
    dpop_signing_alg_values_supported: ["ES256"], dpop_bound_access_tokens_required: true,
    "resource_name#fr": "Rapports", report_versions: [1, 2],
  };
  for (const [label, local, jwtIssuer, doc, external] of [
    ["separate resource server", false, "", { resource }, undefined],
    ["default to the public auth mount", true, "", {}, undefined],
    ["explicit signing issuer", true, issuer, { resource, scopes_supported: [scopes[0]] }, undefined],
    ["multiple issuers and all declared metadata", true, issuer, allFields, externalScopes],
    ["explicit empty capabilities", false, "", {resource, scopes_supported: [], authorization_servers: [], bearer_methods_supported: [], dpop_signing_alg_values_supported: []}, undefined],
  ]) {
    await t.test(label, async t => {
      const auth = local ? betterAuth({
        baseURL: publicURL, basePath: "/gateway/auth", secret: "discovery-fixture-local-secret-123456789",
        logger: { disabled: true }, telemetry: { enabled: false },
        plugins: [jwt({ jwt: { issuer: jwtIssuer || undefined } }),
          oauthProvider({ loginPage: "/login", consentPage: "/consent", scopes, dpop: { signingAlgorithms: ["ES512"] } })],
      }) : undefined;
      const actions = oauthProviderResourceClient(auth).getActions();
      const expected = await actions.getProtectedResourceMetadata(doc, { externalScopes: external });
      const go = await goFixture(t, local ? ["jwt"] : [], {
        CONFORMANCE_DISCOVERY_ISSUER: jwtIssuer,
        CONFORMANCE_RESOURCE_DISCOVERY: JSON.stringify({
          UseAuth: local, Metadata: doc, Options: {
            ProviderScopes: local ? scopes : undefined, ExternalScopes: external,
            DefaultDPoPSigningAlgorithms: local ? ["ES512"] : undefined,
            Extra: doc === allFields ? {"resource_name#fr": doc["resource_name#fr"], report_versions: doc.report_versions} : undefined,
          },
        }),
      });
      const published = new URL(expected.resource);
      const path = "/.well-known/oauth-protected-resource" + published.pathname.replace(/\/$/, "") + published.search;
      const response = await fetch(go.baseURL + path, { headers: { Origin: "https://client.example.test" } });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-type"), "application/json");
      assert.equal(response.headers.get("access-control-allow-origin"), "*");
      assert.deepEqual(await response.json(), JSON.parse(JSON.stringify(expected)));
    });
  }
}
