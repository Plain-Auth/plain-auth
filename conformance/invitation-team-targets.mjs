import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationTeamTargets(t, { reference, goFixture, instrument }) {
  for (const enabled of [false, true]) {
    const drafts = [];
    const ref = await reference(t, [organization({ teams: { enabled }, organizationHooks: {
      beforeCreateInvitation: async ({ invitation }) => { drafts.push(structuredClone(invitation)); },
    } })]);
    const go = await goFixture(t, [enabled ? "organization-teams" : "organization"], { CONFORMANCE_INVITATION_CREATION: "prepare" });
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient({ teams: { enabled } })]).client;
      const owner = connect();
      const ok = result => { assert.equal(result.error, null, JSON.stringify(result.error)); return result.data; };
      const signup = (client, name) => client.signUp.email({ name, email: name+"@example.test", password: "local-team-target-test" });
      ok(await signup(owner, "owner"));
      const group = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const team = enabled ? ok(await owner.organization.createTeam({ name: "Design", organizationId: group.id })).id : "design";
      for (const teamId of [null, 42, {}, ["ok", 3]]) {
        const bad = await owner.organization.inviteMember({ email: "invalid@example.test", role: "member", teamId });
        assert.equal(bad.error?.code, "VALIDATION_ERROR");
      }
      const cases = [
        ["omitted", undefined, null], ["empty-string", "", ""], ["empty-list", [], null],
        ["single", team, team], ["single-list", [team], team], ["duplicate", [team, team], team+","+team],
        ["blank-element", [""], "TEAM_NOT_FOUND"], ["missing", ["absent"], "TEAM_NOT_FOUND"],
        ["delimiter", [team+",other"], "INVALID_TEAM_ID"],
      ];
      for (const [name, target, expected] of cases) {
        const email = name+"@example.test";
        const invite = (teamId, resend=false) => owner.organization.inviteMember({ email, role:"member", organizationId: group.id, teamId, resend });
        const out = await invite(target);
        if (enabled && ["TEAM_NOT_FOUND","INVALID_TEAM_ID"].includes(expected)) {
          assert.equal(out.error?.code, expected);
          continue;
        }
        const grant = ok(out);
        if (enabled) assert.equal(grant.teamId, expected);
        else assert.equal("teamId" in grant, false);
        // A live resend preserves the saved targets even if the new request names another team.
        const renewed = ok(await invite([team+",other"], true));
        assert.equal(renewed.id, grant.id);
        assert.equal(renewed.teamId, grant.teamId);
        if (["empty-string","duplicate"].includes(name)) {
          const recipient = connect();
          ok(await signup(recipient, name));
          const accepted = ok(await recipient.organization.acceptInvitation({ invitationId: grant.id }));
          assert.equal(accepted.invitation.teamId, grant.teamId);
          const session = ok(await recipient.getSession()).session;
          assert.equal(session.activeOrganizationId, group.id);
          assert.equal(session.activeTeamId ?? null, null);
          if (enabled) {
            const memberships = ok(await recipient.organization.listUserTeams({ query: { organizationId: group.id } }));
            assert.deepEqual(memberships.map(t => t.id), name === "duplicate" ? [team] : []);
          }
        }
      }
      const seen = server === ref ? drafts : (await readFile(go.databasePath+".creation-events", "utf8")).trim().split("\n").map(line=>JSON.parse(line)).filter(e=>e.phase==="before").map(e=>e.invitation);
      for (const [name, target, expected] of cases) {
        const matching = seen.filter(d => d.email === name+"@example.test");
        if (enabled && ["TEAM_NOT_FOUND","INVALID_TEAM_ID"].includes(expected)) {
          assert.equal(matching.length,0);
        } else {
          assert.equal(matching.length,1);
          const ids = target === undefined ? [] : Array.isArray(target) ? target : [target];
          assert.deepEqual(matching[0].teamIds, ids);
          assert.equal(matching[0].teamId, ids[0]);
        }
      }
    }
  }
}
