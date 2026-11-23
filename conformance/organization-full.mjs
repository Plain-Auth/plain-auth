import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareFullOrganization(t, { reference, goFixture, instrument }) {
  for (const teams of [false, true]) {
    const options = teams ? { teams: { enabled: true } } : {};
    const implementations = [await reference(t, [organization(options)]), await goFixture(t, [teams ? "organization-teams" : "organization"])];
    for (const server of implementations) {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [owner, admin, member, stranger] = [connect(), connect(), connect(), connect()];
      const full = (client, query = {}) => client.organization.getFullOrganization({ query });
      const ok = reply => {
        assert.equal(reply.error, null, JSON.stringify(reply.error));
        return reply.data;
      };
      const denied = (reply, status, code) => {
        assert.equal(reply.error?.status, status, JSON.stringify(reply));
        assert.equal(reply.error.code, code);
      };
      denied(await full(owner), 401, "UNAUTHORIZED");
      for (const [client, name] of [[owner, "Owner"], [admin, "Admin"], [member, "Member"], [stranger, "Stranger"]]) {
        ok(await client.signUp.email({ name, email: name.toLowerCase() + "@example.test", password: "full-directory-password" }));
      }
      assert.equal(ok(await full(owner)), null);
      const group = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const other = ok(await owner.organization.create({ name: "School", slug: "school" }));
      const privateGroup = ok(await stranger.organization.create({ name: "Private", slug: "private" }));
      const invite = async (email, role) => ok(await owner.organization.inviteMember({ organizationId: group.id, email, role }));
      for (const [client, role] of [[admin, "admin"], [member, "member"]]) {
        const inv = await invite(role + "@example.test", role);
        ok(await client.organization.acceptInvitation({ invitationId: inv.id }));
      }
      const ownerInvite = await invite("future-owner@example.test", "owner");
      const normalInvite = await invite("future-member@example.test", "member");
      let team;
      if (teams) team = ok(await owner.organization.createTeam({ name: "Back office", organizationId: group.id }));
      const page = ok(await full(owner, { organizationSlug: group.slug, organizationId: privateGroup.id, membersLimit: "1tail" }));
      assert.equal(page.id, group.id);
      assert.equal(page.members.length, 1);
      assert.equal(page.invitations.length, 4);
      assert.equal(page.invitations.some(inv => inv.id === ownerInvite.id), true);
      assert.equal(page.invitations.some(inv => inv.status === "accepted"), true);
      assert.equal(ok(await owner.getSession()).session.activeOrganizationId, other.id);
      const adminPage = ok(await full(admin, { organizationId: group.id, membersLimit: 1 }));
      assert.equal(adminPage.members.length, 1);
      assert.equal(adminPage.invitations.some(inv => inv.id === ownerInvite.id), false);
      assert.equal(adminPage.invitations.some(inv => inv.id === normalInvite.id), true);
      const basic = ok(await full(member, { organizationId: group.id, membersLimit: 0 }));
      assert.deepEqual(basic.invitations, []);
      assert.equal(basic.members.length, 3);
      assert.equal("total" in basic, false);
      for (const row of basic.members) {
        assert.equal(row.user.id, row.userId);
        assert.deepEqual(Object.keys(row.user).sort(), ["email", "id", "image", "name"]);
      }
      assert.equal("teams" in basic, teams);
      if (teams) {
        assert.equal(basic.teams.some(item => item.id === team.id), true);
        // Plain Auth exposes the same public team fields as its list-teams endpoint.
        if (server === implementations[1]) assert.equal(basic.teams.some(item => "memberCount" in item), false);
      }
      denied(await full(owner, { organizationId: "absent" }), 400, "ORGANIZATION_NOT_FOUND");
      assert.equal(ok(await owner.getSession()).session.activeOrganizationId, other.id);
      const otherSession = connect();
      ok(await otherSession.signIn.email({ email: "owner@example.test", password: "full-directory-password" }));
      ok(await otherSession.organization.setActive({ organizationId: group.id }));
      denied(await full(owner, { organizationId: privateGroup.id }), 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
      assert.equal(ok(await full(owner)), null);
      assert.equal(ok(await full(otherSession)).id, group.id);
      assert.equal(ok(await full(stranger)).id, privateGroup.id);

      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        // Simulate a membership revoked by a separate server before this session reads again.
        const active = ok(await member.organization.setActive({ organizationId: group.id }));
        assert.equal(active.id, group.id);
        const current = ok(await member.getSession());
        db.prepare('DELETE FROM "member" WHERE "organizationId"=? AND "userId"=?').run(group.id, current.user.id);
        denied(await full(member), 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
        assert.equal(db.prepare('SELECT "activeOrganizationId" AS active FROM "session" WHERE id=?').get(current.session.id).active, null);
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}
