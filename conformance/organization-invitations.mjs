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

export async function compareInvitationDetails(t, { reference, goFixture, instrument }) {
  for (const verified of [false, true]) {
    const options = { requireEmailVerificationOnInvitation: verified, teams: { enabled: verified } };
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, [verified ? "organization-teams" : "organization"], { CONFORMANCE_VERIFY_INVITATION_EMAIL: verified ? "1" : "" });
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [sender, recipient, anonymous] = [connect(), connect(), connect()];
      const ok = result => {
        assert.equal(result.error, null, JSON.stringify(result.error));
        return result.data;
      };
      const get = (client, id) => client.organization.getInvitation({ query: { id } });
      const code = (res, status, name) => {
        assert.equal(res.error?.status, status, JSON.stringify(res));
        assert.equal(res.error.code, name);
      };
      code(await get(anonymous, "absent"), 401, undefined);
      code(await get(anonymous), 400, "VALIDATION_ERROR");
      for (const [client, email] of [[sender, "host@example.test"], [recipient, "person@example.test"]]) {
        ok(await client.signUp.email({ name: email, email, password: "invitation-details-password" }));
      }
      const group = ok(await sender.organization.create({ name: "Workspace", slug: "workspace" }));
      const inv = ok(await sender.organization.inviteMember({ email: "person@example.test", role: "member" }));
      code(await get(sender, inv.id), 403, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION");
      code(await get(recipient, "absent"), 400, "INVITATION_NOT_FOUND");
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        if (verified) {
          code(await get(recipient, inv.id), 403, "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION");
          db.prepare('UPDATE "user" SET "emailVerified"=1 WHERE email=?').run("person@example.test");
        }
        db.prepare('UPDATE "user" SET "email"=? WHERE "id"=?').run("changed@example.test", inv.inviterId);
        db.prepare('UPDATE organization SET name=?, slug=? WHERE id=?').run("Renamed", "renamed", group.id);
        const view = ok(await get(recipient, inv.id));
        assert.equal(view.organizationName, "Renamed");
        assert.equal(view.organizationSlug, "renamed");
        assert.equal(view.inviterEmail, "changed@example.test");
        assert.equal(view.id, inv.id);
        assert.equal(view.organizationId, group.id);
        assert.equal(view.email, "person@example.test");
        assert.equal("teamId" in view, verified);
        if (verified) assert.equal(view.teamId, null);
        const originalExpiry = db.prepare("SELECT expiresAt FROM invitation WHERE id=?").get(inv.id).expiresAt;
        for (const state of ["accepted", "rejected", "canceled"]) {
          db.prepare('UPDATE invitation SET status=? WHERE id=?').run(state, inv.id);
          code(await get(recipient, inv.id), 400, "INVITATION_NOT_FOUND");
        }
        db.prepare("UPDATE invitation SET status='pending',expiresAt=? WHERE id=?").run("2020-01-01T00:00:00Z", inv.id);
        code(await get(recipient, inv.id), 400, "INVITATION_NOT_FOUND");
        db.prepare("UPDATE invitation SET expiresAt=? WHERE id=?").run(originalExpiry, inv.id);
        assert.equal(ok(await get(recipient, inv.id)).id, inv.id);
        db.prepare('DELETE FROM member WHERE organizationId=? AND userId=?').run(group.id, inv.inviterId);
        code(await get(recipient, inv.id), 400, "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION");
        assert.equal(ok(await recipient.getSession()).session.activeOrganizationId ?? null, null);
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}

export async function compareInvitationRejection(t, { reference, goFixture, instrument }) {
  for (const teams of [false, true]) {
    const options = { requireEmailVerificationOnInvitation: teams, teams: { enabled: teams } };
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, [teams ? "organization-teams" : "organization"], { CONFORMANCE_VERIFY_INVITATION_EMAIL: teams ? "1" : "" });
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [owner, recipient, signedOut] = [connect(), connect(), connect()];
      const ok = result => {
        assert.equal(result.error, null, JSON.stringify(result.error));
        return result.data;
      };
      const error = (result, status, code) => {
        assert.equal(result.error?.status, status, JSON.stringify(result));
        assert.equal(result.error.code, code);
      };
      const reject = (caller, invitationId) => caller.organization.rejectInvitation({ invitationId });
      const email = "recipient@example.test";
      const creds = { password: "invitation-rejection-password" };
      error(await reject(signedOut, "none"), 401, "UNAUTHORIZED");
      for (const invalid of [undefined, null, 123, ["id"], {}]) {
        error(await reject(signedOut, invalid), 400, "VALIDATION_ERROR");
      }
      ok(await owner.signUp.email({ ...creds, name: "Owner", email: "owner@example.test" }));
      ok(await recipient.signUp.email({ ...creds, name: "Recipient", email }));
      const other = ok(await recipient.organization.create({ name: "Personal", slug: "personal" }));
      const group = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const invite = async teamId => ok(await owner.organization.inviteMember({ email, role: "admin", teamId }));
      const team = teams && ok(await owner.organization.createTeam({ name: "Design", organizationId: group.id }));
      if (teams) {
        const personal = ok(await recipient.organization.listTeams({ query: { organizationId: other.id } }))[0];
        ok(await recipient.organization.setActiveTeam({ teamId: personal.id }));
      }
      const selection = async () => {
        const s = ok(await recipient.getSession()).session;
        return [s.activeOrganizationId, s.activeTeamId ?? null];
      };
      const original = await selection();
      const first = await invite(undefined);
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        error(await reject(owner, first.id), 403, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION");
        error(await reject(recipient, ""), 400, "INVITATION_NOT_FOUND");
        if (teams) {
          error(await reject(recipient, first.id), 403, "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION");
          db.prepare('UPDATE "user" SET "emailVerified"=1 WHERE email=?').run(email);
        }
        db.prepare('UPDATE invitation SET email=?, expiresAt=? WHERE id=?').run(email.toUpperCase(), "2020-01-01T00:00:00Z", first.id);
        const declined = ok(await reject(recipient, first.id));
        assert.equal(declined.member, null);
        assert.equal(declined.invitation.id, first.id);
        assert.equal(declined.invitation.email, email.toUpperCase());
        assert.equal(declined.invitation.status, "rejected");
        assert.equal("teamId" in declined.invitation, teams);
        if (teams) {
          assert.equal(declined.invitation.teamId, null);
          const targeted = await invite(team.id);
          assert.equal(ok(await reject(recipient, targeted.id)).invitation.teamId, team.id);
        }
        error(await reject(recipient, first.id), 400, "INVITATION_NOT_FOUND");
        error(await recipient.organization.acceptInvitation({ invitationId: first.id }), 400, "INVITATION_NOT_FOUND");
        assert.deepEqual(await selection(), original);
        assert.equal(db.prepare("SELECT COUNT(*) AS n FROM member WHERE organizationId=?").get(group.id).n, 1);
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}

export async function compareInvitationCancellation(t, { reference, goFixture, instrument }) {
  for (const teams of [false, true]) {
    const options = { teams: { enabled: teams } };
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, [teams ? "organization-teams" : "organization"]);
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const [owner, admin, member, guest] = [connect(), connect(), connect(), connect()];
      const ok = result => {
        assert.equal(result.error, null, JSON.stringify(result.error));
        return result.data;
      };
      const error = (result, status, code) => {
        assert.equal(result.error?.status, status, JSON.stringify(result));
        assert.equal(result.error.code, code);
      };
      const cancel = (caller, invitationId) => caller.organization.cancelInvitation({ invitationId });
      error(await cancel(guest, "absent"), 401, "UNAUTHORIZED");
      for (const invalid of [null, undefined, {}]) error(await cancel(guest, invalid), 400, "VALIDATION_ERROR");
      for (const [client, name] of [[owner, "Owner"], [admin, "Admin"], [member, "Member"], [guest, "Guest"]]) {
        ok(await client.signUp.email({ name, email: name.toLowerCase()+"@example.test", password: "invitation-cancel-password" }));
      }
      const org = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const team = teams && ok(await owner.organization.createTeam({ name: "Workshop", organizationId: org.id }));
      const invite = async (name, role) => ok(await owner.organization.inviteMember({ email: name+"@example.test", role, organizationId: org.id, teamId: teams ? team.id : undefined }));
      const adminInvite = await invite("admin", "admin");
      const memberInvite = await invite("member", "member");
      ok(await admin.organization.acceptInvitation({ invitationId: adminInvite.id }));
      const joined = ok(await member.organization.acceptInvitation({ invitationId: memberInvite.id }));
      const other = ok(await admin.organization.create({ name: "Elsewhere", slug: "elsewhere" }));
      const pending = await invite("guest", "owner");
      error(await cancel(member, pending.id), 403, "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION");
      error(await cancel(guest, pending.id), 400, "MEMBER_NOT_FOUND");
      error(await cancel(owner, ""), 400, "INVITATION_NOT_FOUND");
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        db.prepare("UPDATE invitation SET expiresAt=? WHERE id=?").run("2020-01-01T00:00:00Z", pending.id);
        const canceled = ok(await cancel(admin, pending.id));
        assert.equal(canceled.id, pending.id);
        assert.equal(canceled.status, "canceled");
        assert.equal(canceled.role, "owner");
        assert.equal("invitation" in canceled, false);
        assert.equal("teamId" in canceled, teams);
        if (teams) assert.equal(canceled.teamId, team.id);
        assert.deepEqual(ok(await cancel(owner, pending.id)), canceled);
        error(await guest.organization.acceptInvitation({ invitationId: pending.id }), 400, "INVITATION_NOT_FOUND");
        const declined = await invite("guest", "member");
        ok(await guest.organization.rejectInvitation({ invitationId: declined.id }));
        assert.equal(ok(await cancel(owner, declined.id)).status, "canceled");
        assert.equal(ok(await cancel(admin, memberInvite.id)).status, "canceled");
        const membership = ok(await member.organization.getActiveMember());
        assert.equal(membership.id, joined.member.id);
        assert.equal(membership.role, "member");
        const recipientSession = ok(await member.getSession()).session;
        assert.equal(recipientSession.activeOrganizationId, org.id);
        if (teams) {
          assert.equal(recipientSession.activeTeamId, team.id);
          assert.equal(db.prepare('SELECT COUNT(*) AS n FROM teamMember WHERE teamId=? AND userId=?').get(team.id, membership.userId).n, 1);
        }
        assert.equal(ok(await admin.getSession()).session.activeOrganizationId, other.id);
        db.prepare("UPDATE member SET role='member' WHERE userId=? AND organizationId=?").run(adminInvite.inviterId, org.id);
        error(await cancel(owner, pending.id), 403, "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION");
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}
