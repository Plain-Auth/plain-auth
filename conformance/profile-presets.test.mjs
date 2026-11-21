import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { gumroad, hubspot, patreon, slack, yandex } from "better-auth/plugins/generic-oauth";

test("OAuth profile presets match published endpoints, scopes, subjects and verified email", async (t) => {
  const cases = JSON.parse(readFileSync(new URL("../providers/testdata/profile_presets.json", import.meta.url)));
  const presets = { gumroad, hubspot, patreon, slack, yandex };
  for (const [name, sample] of Object.entries(cases)) {
    await t.test(name, async (t) => {
      const config = presets[name]({ clientId: "fixture", clientSecret: "secret" });
      assert.equal(config.providerId, name);
      assert.equal(config.authorizationUrl, sample.authorize);
      assert.equal(config.tokenUrl, sample.referenceToken ?? sample.token);
      assert.deepEqual(config.scopes, sample.scopes);
      const fetch = t.mock.method(globalThis, "fetch", async (resource, init) => {
        const request = new Request(resource, init);
        const expectedURL = new URL(sample.referenceUserInfo ?? sample.userInfo);
        const actualURL = new URL(request.url);
        assert.deepEqual([...actualURL.searchParams], [...expectedURL.searchParams]);
        actualURL.search = expectedURL.search = "";
        assert.equal(actualURL.href, expectedURL.href);
        if (name === "hubspot") assert.equal(request.headers.get("Authorization"), null);
        else assert.equal(request.headers.get("Authorization"), (name === "yandex" ? "OAuth" : "Bearer") + " access");
        return Response.json(sample.input);
      });
      const profile = await config.getUserInfo({accessToken: "access"});
      assert.equal(fetch.mock.callCount(), 1);
      assert.deepEqual(JSON.parse(JSON.stringify(profile)), sample.expected);
      assert.equal(config.accountSubject({ profile }), sample.expected.id ?? sample.expected.sub);
    });
  }
});
