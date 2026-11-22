import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareOrganizationProfileHooks(t, { reference, goFixture, instrument }) {
  const events = [];
  const plugin = organization({ organizationHooks: {
    async beforeUpdateOrganization(event) {
      events.push({ stage: "before", ...structuredClone(event) });
      if (event.organization.name === "before-failure") throw new Error("private organization fixture");
      if (event.organization.name === "normalize") return { data: { name: "normalized", logo: null } };
    },
    async afterUpdateOrganization(event) {
      events.push({ stage: "after", ...structuredClone(event) });
      if (event.organization.name === "after-failure") throw new Error("private organization fixture");
    },
  } });
  const referenceServer = await reference(t, [plugin], { logger: { disabled: true } });
  const go = await goFixture(t, ["organization"], { CONFORMANCE_ORG_PROFILE_HOOKS: "1" });
  const readEvents = async server => {
    if (server === referenceServer) return events;
    try {
      const data = await readFile(go.databasePath + ".org-profile-events", "utf8");
      return data.trim().split("\n").map(line => JSON.parse(line));
    } catch (err) {
      if (err.code === "ENOENT") return [];
      throw err;
    }
  };
  for (const server of [referenceServer, go]) {
    const make = () => instrument(server, [organizationClient()]).client;
    const owner = make(), outsider = make();
    const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
    const account = ok(await owner.signUp.email({ email: "owner@hooks.test", name: "Owner", password: "local observer test" })).user;
    ok(await outsider.signUp.email({ email: "guest@hooks.test", name: "Guest", password: "local observer test" }));
    const original = ok(await owner.organization.create({ name: "Before", slug: "initial-org", logo: "/first" }));
    const taken = ok(await outsider.organization.create({ name: "Other", slug: "taken-org" }));
    const apply = (browser, data) => browser.organization.update({ organizationId: original.id, data });
    const get = async () => ok(await owner.organization.getOrganization({ query: { organizationId: original.id } }));
    assert.equal((await apply(outsider, { name: "unused" })).error?.status, 400);
    assert.equal((await apply(owner, { slug: taken.slug })).error?.code, "ORGANIZATION_SLUG_ALREADY_TAKEN");
    assert.equal((await apply(owner, { name: "" })).error?.status, 400);
    assert.equal((await readEvents(server)).length, 0);
    const input = { name: "normalize", slug: "custom-slug", metadata: { region: "west" } };
    const updated = ok(await apply(owner, input));
    assert.equal(updated.name, "normalized");
    assert.equal(updated.logo, null);
    assert.equal(updated.slug, input.slug);
    assert.deepEqual(updated.metadata, input.metadata);
    const [before, after] = await readEvents(server);
    assert.deepEqual(before.organization, input);
    assert.equal(before.stage, "before");
    assert.equal(after.stage, "after");
    assert.equal(after.organization.id, original.id);
    assert.equal(after.organization.name, "normalized");
    for (const step of [before, after]) {
      assert.equal(step.user.id, account.id);
      assert.equal(step.user.email, account.email);
      assert.equal(step.member.userId, account.id);
      assert.equal(step.member.organizationId, original.id);
      assert.equal(step.member.role, "owner");
    }
    const rejected = await apply(owner, { name: "before-failure" });
    assert.equal(rejected.error?.status, 500);
    assert.doesNotMatch(JSON.stringify(rejected.error), /private organization fixture/);
    assert.equal((await get()).name, "normalized");
    const committed = await apply(owner, { name: "after-failure" });
    assert.equal(committed.error?.status, 500);
    assert.doesNotMatch(JSON.stringify(committed.error), /private organization fixture/);
    assert.equal((await get()).name, "after-failure");
    assert.deepEqual((await readEvents(server)).map(e => e.stage), ["before", "after", "before", "before", "after"]);
  }

  const sharedDB = new DatabaseSync(go.databasePath);
  t.after(() => sharedDB.close());
  const sharedReference = await reference(t, [plugin], { database: sharedDB, logger: { disabled: true } });
  for (const [issuer, updater, suffix] of [[sharedReference, go, "reference"], [go, sharedReference, "go"]]) {
    const address = suffix + "@exchange.test";
    const credentials = { email: address, password: "local handoff fixture" };
    const origin = instrument(issuer, [organizationClient()]).client;
    assert.equal((await origin.signUp.email({ ...credentials, name: "Owner" })).error, null);
    const group = await origin.organization.create({ name: "Initial", slug: suffix + "-handoff" });
    assert.equal(group.error, null);
    const login = await issuer.send(new Request(issuer.baseURL + "/api/auth/sign-in/email", {
      method: "POST", headers: { origin: issuer.baseURL, "content-type": "application/json" },
      body: JSON.stringify(credentials),
    }));
    assert.equal(login.status, 200);
    const cookie = login.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    assert.ok(cookie);
    const receiver = instrument({
      ...updater,
      send(request) {
        if (!request.headers.has("cookie")) request.headers.set("cookie", cookie);
        return updater.send(request);
      },
    }, [organizationClient()]).client;
    const { data, error } = await receiver.organization.update({
      organizationId: group.data.id, data: { name: "normalize", metadata: { source: suffix } },
    });
    assert.equal(error, null, JSON.stringify(error));
    assert.equal(data.name, "normalized");
    assert.deepEqual(data.metadata, { source: suffix });
    const observed = await origin.organization.getOrganization({ query: { organizationId: group.data.id } });
    assert.equal(observed.error, null);
    assert.equal(observed.data.name, "normalized");
    // The reference SQLite get-organization route returns the stored JSON text.
    // Its update endpoint and callback both parse this field.
    if (issuer === sharedReference) assert.deepEqual(JSON.parse(observed.data.metadata), { source: suffix });
    else assert.deepEqual(observed.data.metadata, { source: suffix });
    const latest = updater === go ? await readEvents(go) : events;
    assert.equal(latest.at(-1).stage, "after");
    assert.equal(latest.at(-1).organization.id, group.data.id);
    assert.deepEqual(latest.at(-1).organization.metadata, { source: suffix });
    assert.equal(latest.at(-1).user.email, address);
  }
}
