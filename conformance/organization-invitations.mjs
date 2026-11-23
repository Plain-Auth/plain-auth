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

export async function compareRecipientInbox(t, { reference, goFixture, instrument }) {
  for (const teams of [false, true]) {
    const options = teams ? { teams: { enabled: true } } : {};
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, [teams ? "organization-teams" : "organization"]);
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [creator, recipient, other] = [connect(), connect(), connect()];
      const ok = result => {
        assert.equal(result.error, null, JSON.stringify(result.error));
        return result.data;
      };
      const inbox = (client, email) => client.organization.listUserInvitations({ query: { email } });
      const email = "recipient@example.test";
      const unauth = await inbox(recipient);
      assert.equal(unauth.error.status, 400);
      assert.equal(unauth.error.message, "Missing session headers, or email query parameter.");
      for (const [client, email] of [[creator, "owner@example.test"], [recipient, "recipient@example.test"], [other, "other@example.test"]]) {
        ok(await client.signUp.email({ name: email, email, password: "recipient-directory-password" }));
      }
      for (const selector of [email, "other@example.test"]) {
        const rejected = await inbox(recipient, selector);
        assert.equal(rejected.error.status, 400);
        assert.equal(rejected.error.message, "User email cannot be passed for client side API calls.");
      }
      assert.equal((await inbox(recipient)).error.code, "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION");
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        db.prepare('UPDATE "user" SET "emailVerified"=1 WHERE email IN (?,?)').run(email, "other@example.test");
        const sent = [];
        for (const [slug, role] of [["alpha", "owner"], ["beta", "admin"], ["gamma", "member"]]) {
          const org = ok(await creator.organization.create({ name: slug.toUpperCase(), slug }));
          let teamId;
          if (teams && slug === "gamma") teamId = ok(await creator.organization.createTeam({ organizationId: org.id, name: "Gamma team" })).id;
          sent.push(ok(await creator.organization.inviteMember({ organizationId: org.id, email, role, teamId })));
        }
        db.prepare("UPDATE invitation SET status='rejected' WHERE id=?").run(sent[1].id);
        db.prepare("UPDATE invitation SET expiresAt=? WHERE id=?").run("2020-01-01T00:00:00Z", sent[0].id);
        const records = ok(await inbox(recipient, ""));
        assert.deepEqual(records.map(row => row.organizationName).sort(), ["ALPHA", "GAMMA"]);
        const first = records.find(row => row.id === sent[0].id);
        assert.equal(first.role, "owner");
        assert.equal(first.status, "pending");
        assert.equal("organization" in first, false);
        assert.equal("teamId" in first, teams);
        if (teams) {
          assert.equal(first.teamId, null);
          assert.equal(records.find(row => row.id === sent[2].id).teamId, sent[2].teamId);
        }
        assert.deepEqual(ok(await inbox(other)), []);
        if (server === ref) {
          const trusted = await ref.api.listUserInvitations({ query: { email: email.toUpperCase() } });
          assert.deepEqual(trusted.map(row => row.id).sort(), records.map(row => row.id).sort());
        }
        db.prepare('UPDATE "user" SET "emailVerified"=0 WHERE email=?').run(email);
        assert.equal((await inbox(recipient)).error.code, "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION");
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}
