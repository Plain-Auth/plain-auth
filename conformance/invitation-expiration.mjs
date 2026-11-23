import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationExpiration(t, { reference, goFixture, instrument }) {
  for (const seconds of [0, 90, -1]) {
    const options = { invitationExpiresIn: seconds };
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, ["organization"], { CONFORMANCE_INVITATION_DURATION: seconds+"s" });
    for (const server of [ref, go]) {
      const owner = instrument(server, [organizationClient()]).client;
      const guest = instrument(server, [organizationClient()]).client;
      const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
      const email = "guest@example.test";
      const credentials = { password: "invitation-duration-password" };
      ok(await owner.signUp.email({ name: "Owner", email: "owner@example.test", ...credentials }));
      ok(await guest.signUp.email({ name: "Guest", email, ...credentials }));
      ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const validFor = (seconds || 48*60*60) * 1000;
      async function issue(resend, role) {
        const start = Date.now();
        const row = ok(await owner.organization.inviteMember({ email, role, resend }));
        const time = new Date(row.expiresAt).getTime();
        assert.ok(time >= start + validFor && time <= Date.now() + validFor, "issued deadline outside the host policy");
        return row;
      }
      const original = await issue(false, "member");
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        if (seconds < 0) {
          const result = await guest.organization.acceptInvitation({ invitationId: original.id });
          assert.equal(result.error?.code, "INVITATION_NOT_FOUND");
          assert.notEqual((await issue(true, "member")).id, original.id);
          continue;
        }
        // Change the deadline on disk to distinguish renewal from replaying the old response.
        db.prepare("UPDATE invitation SET expiresAt=? WHERE id=?").run(new Date(Date.now()+86400000).toISOString(), original.id);
        const renewed = await issue(true, "admin");
        assert.equal(renewed.id, original.id);
        assert.equal(renewed.role, "member");
        assert.equal(new Date(renewed.createdAt).getTime(), new Date(original.createdAt).getTime());
        const stored = db.prepare("SELECT expiresAt FROM invitation WHERE id=?").get(original.id);
        assert.equal(new Date(stored.expiresAt).getTime(), new Date(renewed.expiresAt).getTime());
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}

export async function compareInvitationReplacement(t, { reference, goFixture, instrument }) {
  for (const replace of [false, true]) {
    const options = { cancelPendingInvitationsOnReInvite: replace, teams: { enabled: true } };
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, ["organization-teams"], { CONFORMANCE_REPLACE_INVITATION: replace ? "1" : "" });
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [owner, guest] = [connect(), connect()];
      const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
      const credentials = { password: "replacement-invitation" };
      const email = "guest@example.test";
      ok(await owner.signUp.email({ name: "Owner", email: "owner@example.test", ...credentials }));
      ok(await guest.signUp.email({ name: "Guest", email, ...credentials }));
      const group = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const team = ok(await owner.organization.createTeam({ organizationId: group.id, name: "New team" }));
      const other = ok(await owner.organization.create({ name: "Other", slug: "other" }));
      const issue = (organizationId, role, resend, teamId) => owner.organization.inviteMember({ email, role, organizationId, resend, teamId });
      const original = ok(await issue(group.id, "member", false));
      const unrelated = ok(await issue(other.id, "member", false));
      const renewed = ok(await issue(group.id, "admin", true, team.id));
      assert.equal(renewed.id, original.id);
      assert.equal(renewed.role, "member");
      const replacement = await issue(group.id, "admin", false, team.id);
      if (!replace) {
        assert.equal(replacement.error?.code, "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION");
        assert.equal(ok(await guest.organization.getInvitation({ query: { id: original.id } })).status, "pending");
        continue;
      }
      const fresh = ok(replacement);
      assert.notEqual(fresh.id, original.id);
      assert.equal(fresh.role, "admin");
      assert.equal(fresh.teamId, team.id);
      assert.equal((await guest.organization.acceptInvitation({ invitationId: original.id })).error?.code, "INVITATION_NOT_FOUND");
      const list = ok(await owner.organization.listInvitations({ query: { organizationId: group.id } }));
      assert.equal(list.find(i => i.id === original.id).status, "canceled");
      assert.equal(ok(await guest.organization.getInvitation({ query: { id: unrelated.id } })).status, "pending");
      const grant = ok(await guest.organization.acceptInvitation({ invitationId: fresh.id }));
      assert.equal(grant.member.role, "admin");
      assert.equal(ok(await guest.getSession()).session.activeTeamId, team.id);
    }
  }
}
