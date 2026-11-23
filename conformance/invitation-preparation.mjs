import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationPreparation(t, { reference, goFixture, instrument }) {
  const events = [];
  const record = (phase, invitation, organization, actor) =>
    events.push(structuredClone({ phase, invitation, organization, actor }));
  const deadline = new Date(Date.UTC(new Date().getUTCFullYear() + 1, 0, 5, 12));
  const ref = await reference(t, [organization({
    teams: { enabled: true },
    sendInvitationEmail: async ({ invitation, organization, inviter }) => record("mail", invitation, organization, inviter.user),
    organizationHooks: {
      beforeCreateInvitation: async ({ invitation, organization, inviter }) => {
        record("before", invitation, organization, inviter);
        if (invitation.email === "veto@example.test") throw Error("private preparation fixture");
        if (invitation.email === "wide@example.test") return { data: { teamIds: [] } };
        if (invitation.email === "custom@example.test") return { data: {
          email: "processed@example.test", role: "member", teamIds: [...invitation.teamIds].reverse(), expiresAt: deadline,
        } };
      },
      afterCreateInvitation: async ({ invitation, organization, inviter }) => record("created", invitation, organization, inviter),
    },
  })], { logger: { disabled: true } });
  const go = await goFixture(t, ["organization-teams"], { CONFORMANCE_INVITATION_CREATION: "prepare" });
  for (const server of [ref, go]) {
    const read = () => server === ref ? [...events] : readFile(go.databasePath+".creation-events", "utf8").then(text => text.trim().split("\n").map(line => JSON.parse(line)));
    const connect = () => instrument(server, [organizationClient({ teams: { enabled: true } })]).client;
    const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
    const owner = connect(), guest = connect();
    const signup = (client, name, email) => client.signUp.email({ name, email, password: "local-invitation-preparation" });
    const actor = ok(await signup(owner, "Issuer", "owner@example.test")).user;
    ok(await signup(guest, "Recipient", "processed@example.test"));
    const group = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
    const team = async name => ok(await owner.organization.createTeam({ name, organizationId: group.id })).id;
    const teams = [await team("Design"), await team("Operations")];
    const issue = fields => owner.organization.inviteMember({ email: "CUSTOM@example.test", role: ["admin, member", "admin"], teamId: teams, ...fields });
    const grant = ok(await issue({}));
    const phases = rows => rows.map(e => e.phase);
    let rows = await read();
    assert.deepEqual(phases(rows), ["before", "mail", "created"]);
    const first = rows[0];
    assert.equal(first.actor.id, actor.id);
    assert.equal(first.actor.name, "Issuer");
    assert.equal(first.organization.id, group.id);
    assert.deepEqual(JSON.parse(JSON.stringify(first.invitation)), {
      email: "custom@example.test", role: "admin,member,admin", organizationId: group.id, inviterId: actor.id,
      teamId: teams[0], teamIds: teams,
    });
    assert.equal(grant.email, "processed@example.test");
    assert.equal(grant.role, "member");
    assert.equal(grant.teamId, [...teams].reverse().join(","));
    assert.equal(new Date(grant.expiresAt).getTime(), deadline.getTime());
    for (const e of rows.slice(1)) {
      assert.equal(e.invitation.id, grant.id);
      assert.equal(e.invitation.email, grant.email);
      assert.equal(new Date(e.invitation.expiresAt).getTime(), deadline.getTime());
    }
    const renewed = ok(await issue({ email: grant.email, resend: true }));
    assert.equal(renewed.id, grant.id);
    assert.deepEqual(phases(await read()), ["before", "mail", "created", "mail"]);
    const joined = ok(await guest.organization.acceptInvitation({ invitationId: grant.id }));
    assert.equal(joined.member.role, "member");
    const receivedTeams = ok(await guest.organization.listUserTeams({ query: { organizationId: group.id } }));
    assert.deepEqual(receivedTeams.map(t => t.id).sort(), [...teams].sort());
    const wide = ok(await issue({ email: "wide@example.test" }));
    assert.equal(wide.teamId, null);
    const unchanged = ok(await issue({ email: "unchanged@example.test", teamId: undefined }));
    assert.equal(unchanged.role, "admin,member,admin");
    assert.equal(unchanged.teamId, null);
    rows = await read();
    const wideInput = rows.find(e => e.phase === "before" && e.invitation.email === unchanged.email);
    assert.deepEqual(wideInput.invitation.teamIds, []);
    assert.equal(wideInput.invitation.teamId, undefined);
    const denied = await issue({ email: "veto@example.test" });
    assert.equal(denied.error?.status, 500);
    assert.doesNotMatch(JSON.stringify(denied.error), /private preparation fixture/);
    assert.deepEqual(phases((await read()).slice(rows.length)), ["before"]);
    const saved = ok(await owner.organization.listInvitations({ query: { organizationId: group.id } }));
    assert.equal(saved.some(i => i.email === "veto@example.test"), false);
  }
}
