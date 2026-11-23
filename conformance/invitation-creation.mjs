import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationCreation(t, { reference, goFixture, instrument }) {
  for (const withMail of [true, false]) {
    const events = [];
    const record = (phase, invitation, group, actor) => events.push(structuredClone({ phase, invitation, organization: group, actor }));
    const options = { teams: { enabled: true }, cancelPendingInvitationsOnReInvite: true, organizationHooks: {
      afterCreateInvitation: async ({ invitation, organization, inviter }) => {
        record("created", invitation, organization, inviter);
        if (invitation.email === "hook-failure@example.test") throw Error("private creation fixture");
      },
    } };
    if (withMail) options.sendInvitationEmail = async ({ invitation, organization, inviter }) => {
      record("mail", invitation, organization, inviter.user);
      if (invitation.email === "mail-failure@example.test") throw Error("fixture delivery failed");
    };
    const ref = await reference(t, [organization(options)], { logger: { disabled: true } });
    const go = await goFixture(t, ["organization-teams"], { CONFORMANCE_INVITATION_CREATION: withMail ? "with-mail" : "no-mail", CONFORMANCE_REPLACE_INVITATION: "1" });
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient({ teams: { enabled: true } })]).client;
      const owner = connect(), outsider = connect();
      const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
      const signup = (client, name) => client.signUp.email({ name, email: name+"@example.test", password: "invitation-creation-order" });
      const user = ok(await signup(owner, "owner")).user;
      ok(await signup(outsider, "outsider"));
      const group = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const team = ok(await owner.organization.createTeam({ name: "Research", organizationId: group.id }));
      const invite = (client, email, resend = false) => client.organization.inviteMember({ organizationId: group.id, role: "member", teamId: team.id, email, resend });
      const read = async () => server === ref ? events : (await readFile(go.databasePath+".creation-events", "utf8")).trim().split("\n").map(s => JSON.parse(s));
      let position = 0;
      const check = async (grant, fresh) => {
        const all = await read(), batch = all.slice(position);
        position = all.length;
        const expected = [...(withMail ? ["mail"] : []), ...(fresh ? ["created"] : [])];
        assert.deepEqual(batch.map(e => e.phase), expected);
        for (const e of batch) {
          assert.equal(e.invitation.id, grant.id);
          assert.equal(e.invitation.status, "pending");
          assert.equal(e.invitation.teamId, team.id);
          assert.equal(e.invitation.email, grant.email);
          assert.equal(e.organization.id, group.id);
          assert.equal(e.actor.id, user.id);
          assert.equal(e.actor.email, user.email);
        }
      };
      const initial = ok(await invite(owner, "guest@example.test", true));
      await check(initial, true);
      assert.ok((await invite(outsider, initial.email)).error);
      assert.equal(ok(await invite(owner, initial.email, true)).id, initial.id);
      await check(initial, false);
      const replacement = ok(await invite(owner, initial.email));
      assert.notEqual(replacement.id, initial.id);
      await check(replacement, true);
      await check(ok(await invite(owner, "mail-failure@example.test")), true);
      const failure = await invite(owner, "hook-failure@example.test");
      assert.equal(failure.error?.status, 500);
      assert.doesNotMatch(JSON.stringify(failure.error), /private creation fixture/);
      const saved = ok(await owner.organization.listInvitations({ query: { organizationId: group.id } })).find(i => i.email === "hook-failure@example.test");
      assert.equal(saved.status, "pending");
      await check(saved, true);
      assert.equal(ok(await invite(owner, saved.email, true)).id, saved.id);
      await check(saved, false);
    }
  }
}
