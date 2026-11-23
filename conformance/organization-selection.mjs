import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareOrganizationSelection(t, { reference, goFixture, instrument }) {
  for (const teams of [false, true]) {
    const options = teams ? { teams: { enabled: true } } : {};
    const servers = [
      ["reference", await reference(t, [organization(options)])],
      ["Go", await goFixture(t, [teams ? "organization-teams" : "organization"])],
    ];
    for (const [name, server] of servers) await t.test(name + (teams ? " with teams" : " without teams"), async () => {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [first, second, outside, anonymous] = [connect(), connect(), connect(), connect()];
      const ok = reply => {
        assert.equal(reply.error, null, JSON.stringify(reply.error));
        return reply.data;
      };
      const select = (who, body) => who.$fetch("/organization/set-active", { method: "POST", body });
      const current = async client => ok(await client.getSession()).session;
      const denied = (reply, status, code) => {
        assert.equal(reply.error?.status, status, JSON.stringify(reply));
        assert.equal(reply.error.code, code);
      };
      const invalid = { organizationId: 1, organizationSlug: null };
      const invalidMessage = "[body.organizationId] Invalid input: expected string, received number; [body.organizationSlug] Invalid input: expected string, received null";
      const validation = await select(anonymous, invalid);
      denied(validation, 400, "VALIDATION_ERROR");
      assert.equal(validation.error.message, invalidMessage);
      assert.equal((await select(anonymous, {})).error?.status, 401);

      const login = { name: "Owner", email: "selector@example.test", password: "local-selector-fixture" };
      ok(await first.signUp.email(login));
      ok(await second.signIn.email({email: login.email, password: login.password}));
      ok(await outside.signUp.email({...login, email: "outside@example.test"}));
      const home = ok(await first.organization.create({name: "Home", slug: "home"}));
      const foreign = ok(await outside.organization.create({name: "Foreign", slug: "foreign"}));
      const restore = async client => {
        assert.equal(ok(await select(client, {organizationId: "", organizationSlug: home.slug})).id, home.id);
        if (teams) {
          const [team] = ok(await client.organization.listUserTeams({query: {organizationId: home.id}}));
          ok(await client.organization.setActiveTeam({teamId: team.id}));
        }
      };
      await restore(first);
      await restore(second);
      const sibling = await current(second);
      const initial = await current(first);
      const unknownSlug = await select(first, {organizationSlug: "unknown"});
      denied(unknownSlug, 400, "ORGANIZATION_NOT_FOUND");
      assert.equal((await select(first, invalid)).error.message, invalidMessage);
      assert.equal(ok(await select(first, {organizationId: home.id, organizationSlug: foreign.slug})).id, home.id);
      assert.equal((await current(first)).activeTeamId, initial.activeTeamId);
      assert.equal(ok(await select(first, {})).id, home.id);

      for (const destination of [{organizationId: foreign.id}, {organizationSlug: foreign.slug}, {organizationId: "unknown", organizationSlug: home.slug}]) {
        await restore(first);
        denied(await select(first, destination), 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
        assert.equal((await current(first)).activeOrganizationId ?? null, null);
        assert.equal(ok(await select(first, {})), null);
        if (name === "Go" && teams) assert.equal((await current(first)).activeTeamId ?? null, null);
        const other = await current(second);
        assert.equal(other.activeOrganizationId, sibling.activeOrganizationId);
        assert.equal(other.activeTeamId, sibling.activeTeamId);
      }
      await restore(first);
      assert.equal(ok(await select(first, {organizationId: null, organizationSlug: home.slug})), null);
      assert.equal((await current(first)).activeOrganizationId ?? null, null);
    });
  }
}
