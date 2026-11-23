import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareOrganizationInvitations(t, { reference, goFixture, instrument }) {
  for (const teams of [false, true]) {
    const options = teams ? { teams: { enabled: true } } : {};
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, [teams ? "organization-teams" : "organization"]);
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [owner, admin, member] = [connect(), connect(), connect()];
      const list = (client, organizationId) => client.organization.listInvitations({ query: { organizationId } });
      const ok = result => {
        assert.equal(result.error, null, JSON.stringify(result.error));
        return result.data;
      };
      const denied = (res, status, message, code) => {
        assert.equal(res.error?.status, status, JSON.stringify(res));
        assert.equal(res.error.message, message);
        assert.equal(res.error.code, code);
      };
      assert.equal((await list(owner)).error.status, 401);
      for (const [c, name] of [[owner, "Owner"], [admin, "Admin"], [member, "Member"]]) {
        ok(await c.signUp.email({ name, email: name.toLowerCase() + "@example.test", password: "invitation-directory-password" }));
      }
      denied(await list(owner), 400, "Organization ID is required");
      const studio = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const annex = ok(await owner.organization.create({ name: "Annex", slug: "annex" }));
      assert.deepEqual(ok(await list(owner)), []);
      const invite = async (email, role, teamId) => ok(await owner.organization.inviteMember({ organizationId: studio.id, email, role, teamId }));
      for (const [client, role] of [[admin, "admin"], [member, "member"]]) {
        ok(await client.organization.acceptInvitation({ invitationId: (await invite(role + "@example.test", role)).id }));
      }
      const groupGrant = await invite("outside@example.test", "member");
      const ownerGrant = await invite("lead@example.test", "owner");
      let teamGrant, team, secondTeam;
      if (teams) {
        team = ok(await owner.organization.createTeam({ name: "Workshop", organizationId: studio.id }));
        secondTeam = ok(await owner.organization.createTeam({ name: "Design", organizationId: studio.id }));
        teamGrant = await invite("team@example.test", "member", [team.id, secondTeam.id]);
      }
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        db.prepare('UPDATE invitation SET role=? WHERE id=?').run("admin, owner", ownerGrant.id);
        db.prepare('UPDATE invitation SET expiresAt=? WHERE id=?').run("2020-01-01T00:00:00Z", groupGrant.id);
        for (const status of ["rejected", "canceled"]) {
          const row = await invite(status + "@example.test", "member");
          db.prepare('UPDATE invitation SET status=? WHERE id=?').run(status, row.id);
        }
        const all = ok(await list(owner, studio.id));
        assert.deepEqual([...new Set(all.map(inv => inv.status))].sort(), ["accepted", "canceled", "pending", "rejected"]);
        const byId = new Map(all.map(inv => [inv.id, inv]));
        assert.equal(byId.get(ownerGrant.id).role, "admin, owner");
        const orgWide = byId.get(groupGrant.id);
        assert.equal(orgWide.email, "outside@example.test");
        assert.equal("organizationName" in orgWide, false);
        assert.equal("teamId" in orgWide, teams);
        if (teams) {
          assert.equal(orgWide.teamId, null);
          assert.equal(byId.get(teamGrant.id).teamId, [team.id, secondTeam.id].join(","));
        }
        const adminList = ok(await list(admin, studio.id));
        assert.equal(adminList.some(inv => inv.id === ownerGrant.id), false);
        assert.equal(adminList.length, all.length - 1);
        denied(await list(member, studio.id), 403, "You are not allowed to list invitations for this organization", "YOU_ARE_NOT_ALLOWED_TO_LIST_INVITATIONS");
        for (const unknown of [annex.id, "missing"]) {
          denied(await list(member, unknown), 403, "You are not a member of this organization");
        }
        assert.equal(ok(await owner.getSession()).session.activeOrganizationId, annex.id);
        assert.deepEqual(ok(await list(owner)), []);
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}
