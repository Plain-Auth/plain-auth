import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationHooks(t, { reference, goFixture, instrument }) {
  const events = [];
  const record = phase => async ({ invitation, organization: group, user, cancelledBy }) => {
    events.push(structuredClone({ phase, invitation, organization: group, actor: user ?? cancelledBy }));
    if (group.slug === phase) throw Error("private invitation fixture");
  };
  const hooks = {
    beforeRejectInvitation: record("before-reject"), afterRejectInvitation: record("after-reject"),
    beforeCancelInvitation: record("before-cancel"), afterCancelInvitation: record("after-cancel"),
  };
  const ref = await reference(t, [organization({ organizationHooks: hooks, teams: { enabled: true } })], { logger: { disabled: true } });
  const go = await goFixture(t, ["organization-teams"], { CONFORMANCE_INVITATION_HOOKS: "1" });
  const read = async server => {
    if (server === ref) return events;
    try {
      return (await readFile(go.databasePath + ".invitation-events", "utf8")).trim().split("\n").map(row => JSON.parse(row));
    } catch (err) {
      if (err.code === "ENOENT") return [];
      throw err;
    }
  };
  for (const server of [ref, go]) {
    const connect = () => instrument(server, [organizationClient({ teams: { enabled: true } })]).client;
    const [owner, guest] = [connect(), connect()];
    const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
    const signUp = async (client, name) => ok(await client.signUp.email({ name, email: name.toLowerCase()+"@example.test", password: "organization-observer" })).user;
    const host = await signUp(owner, "Host"), recipient = await signUp(guest, "Guest");
    for (const [action, method, caller, actor, outcome] of [
      ["reject", "rejectInvitation", guest, recipient, "rejected"], ["cancel", "cancelInvitation", owner, host, "canceled"],
    ]) {
      for (const failure of ["", "before", "after"]) {
        const start = (await read(server)).length;
        const slug = (failure || "success") + "-" + action;
        const group = ok(await owner.organization.create({ name: slug, slug }));
        const team = ok(await owner.organization.createTeam({ name: "Researchers", organizationId: group.id }));
        const invite = ok(await owner.organization.inviteMember({ email: recipient.email, role: "member", teamId: team.id }));
        const body = { invitationId: invite.id };
        const foreign = await (caller === owner ? guest : owner).organization[method](body);
        assert.ok(foreign.error);
        assert.equal((await read(server)).length, start);
        const result = await caller.organization[method](body);
        if (failure) {
          assert.equal(result.error?.status, 500);
          assert.doesNotMatch(JSON.stringify(result.error), /private invitation fixture/);
        } else ok(result);
        const steps = (await read(server)).slice(start);
        assert.deepEqual(steps.map(e => e.phase), failure === "before" ? ["before-"+action] : ["before-"+action, "after-"+action]);
        for (const [i, e] of steps.entries()) {
          assert.equal(e.invitation.status, i === 0 ? "pending" : outcome);
          assert.equal(e.invitation.id, invite.id);
          assert.equal(e.invitation.teamId, team.id);
          assert.equal(e.actor.email, actor.email);
          assert.equal(e.actor.id, actor.id);
          assert.equal(e.organization.id, group.id);
          assert.equal(e.organization.slug, group.slug);
        }
        const saved = ok(await owner.organization.listInvitations({ query: { organizationId: group.id } })).find(v => v.id === invite.id);
        assert.equal(saved.status, failure === "before" ? "pending" : outcome);
      }
    }
  }
}
