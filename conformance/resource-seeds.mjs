import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

export async function compareResourceSeeds(t, goFixture) {
  const go = await goFixture(t, ["oauth-provider", "jwt"], { CONFORMANCE_RESOURCE_REGISTRY: "1" });
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const lookup = id => db.prepare("SELECT * FROM oauthResource WHERE identifier = ?").get(id);
  const run = {
    async Go(config) {
      const response = await fetch(go.baseURL + "/__fixture/seed-resources", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(config),
      });
      assert.equal(response.status, 204, await response.text());
    },
    async reference(config) {
      const instance = betterAuth({
        baseURL: "http://reference.localhost",
        database: db,
        secret: "local-conformance-0123456789-abcdefghijk",
        telemetry: { enabled: false },
        logger: { disabled: true },
        plugins: [jwt(), oauthProvider({ loginPage: "/login", consentPage: "/consent", ...config })],
      });
      await instance.$context;
    },
  };

  for (const [runtime, boot] of Object.entries(run)) {
    await t.test(runtime + " applies insert-only, merge and overwrite on boot", async () => {
      const id = "urn:seed:" + runtime;
      const initial = {
        identifier: id,
        name: "Reports",
        accessTokenTtl: 900,
        refreshTokenTtl: 1200,
        signingAlgorithm: "ES256",
        signingKeyId: "primary",
        allowedScopes: ["read"],
        customClaims: { edition: "v1" },
        dpopBoundAccessTokensRequired: true,
        disabled: true,
        metadata: { trial: true },
      };
      await boot({ resources: [id + ":simple", initial] });
      assert.equal(lookup(id + ":simple").name, id + ":simple");
      const first = lookup(id);
      assert.equal(first.name, "Reports");
      assert.equal(first.accessTokenTtl, 900);
      assert.equal(first.refreshTokenTtl, 1200);
      assert.equal(first.signingAlgorithm, "ES256");
      assert.equal(first.signingKeyId, "primary");
      assert.deepEqual(JSON.parse(first.allowedScopes), ["read"]);
      assert.deepEqual(JSON.parse(first.customClaims), { edition: "v1" });
      assert.equal(first.dpopBoundAccessTokensRequired, 1);
      assert.equal(first.disabled, 1);
      assert.deepEqual(JSON.parse(first.metadata), { trial: true });

      db.prepare("UPDATE oauthResource SET name = 'Operator edit', policyVersion = 4 WHERE identifier = ?").run(id);
      await boot({ resources: [{ identifier: id, name: "Ignored" }] });
      assert.equal(lookup(id).name, "Operator edit");
      assert.equal(lookup(id).updatedAt, first.updatedAt);

      await boot({
        resourceSeedMode: "merge",
        resources: [{ identifier: id, accessTokenTtl: 125, disabled: false, allowedScopes: [] }],
      });
      const merged = lookup(id);
      assert.equal(merged.name, "Operator edit");
      assert.equal(merged.accessTokenTtl, 125);
      assert.equal(merged.refreshTokenTtl, 1200);
      assert.equal(merged.policyVersion, 4);
      assert.equal(merged.disabled, 0);
      assert.deepEqual(JSON.parse(merged.allowedScopes), []);
      assert.deepEqual(JSON.parse(merged.customClaims), { edition: "v1" });

      await boot({
        resourceSeedMode: "merge",
        resources: [{ identifier: id, signingKeyId: null, customClaims: null }],
      });
      const cleared = lookup(id);
      assert.equal(cleared.signingKeyId, null);
      assert.equal(JSON.parse(cleared.customClaims), null);
      assert.equal(cleared.refreshTokenTtl, 1200);

      await boot({ resourceSeedMode: "overwrite", resources: [id] });
      const replaced = lookup(id);
      assert.equal(replaced.id, first.id);
      assert.equal(replaced.createdAt, first.createdAt);
      assert.equal(replaced.name, id);
      assert.equal(replaced.policyVersion, 1);
      for (const field of ["accessTokenTtl", "refreshTokenTtl", "signingAlgorithm", "signingKeyId"]) {
        assert.equal(replaced[field], null, field);
      }
      // SQLite adapters can store SQL NULL or the JSON literal null for a cleared JSON field.
      for (const field of ["allowedScopes", "customClaims", "metadata"]) {
        assert.equal(JSON.parse(replaced[field]), null, field);
      }
      assert.equal(replaced.disabled, 0);
      assert.equal(replaced.dpopBoundAccessTokensRequired, 0);

      const invalid = "relative-" + runtime;
      await boot({
        resources: [invalid, { identifier: id + ":valid", signingAlgorithm: "unsupported", accessTokenTtl: 100 }],
      });
      assert.equal(lookup(invalid), undefined);
      assert.equal(lookup(id + ":valid").signingAlgorithm, null);
      assert.equal(lookup(id + ":valid").accessTokenTtl, 100);
    });

    await t.test(runtime + " shares successful entries across short-lived managers", async () => {
      const id = "urn:seed:shared:" + runtime;
      const config = {
        resourceSeedMode: "merge",
        resourceSeedScope: "process",
        resources: [{ identifier: id, name: "Original" }],
      };
      await boot(config);
      db.prepare("UPDATE oauthResource SET name = ? WHERE identifier = ?").run("Saved by operator", id);
      await boot({ ...config, resources: [...config.resources, id + ":new"] });
      assert.equal(lookup(id).name, "Saved by operator");
      assert.equal(lookup(id + ":new").name, id + ":new");

      await boot({ ...config, resources: [{ identifier: id, name: "Updated declaration" }] });
      assert.equal(lookup(id).name, "Updated declaration");
      await boot({ ...config, resourceSeedScope: "adapter" });
      assert.equal(lookup(id).name, "Original");
    });
  }
}
