import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareMemberRoles(t, { reference, goFixture, instrument }) {
  for (const server of [await reference(t, [organization()]), await goFixture(t, ["organization"])]) {
    let lastReply;
    const observed = { ...server, send: async request => {
      const response = await server.send(request);
      lastReply = await response.clone().text();
      return response;
    }};
    const make = () => instrument(observed, [organizationClient()]).client;
    const ok = outcome => {
      assert.equal(outcome.error, null, JSON.stringify(outcome.error));
      return outcome.data;
    };
    const denied = (outcome, status, code) => {
      assert.equal(outcome.error?.status, status, JSON.stringify(outcome));
      assert.equal(outcome.error?.code, code);
    };
    const owner = make(), admin = make(), peer = make(), outsider = make();
    const users = [];
    for (const [i, c] of [owner, admin, peer, outsider].entries()) {
      users.push(ok(await c.signUp.email({email: `role${i}@example.test`, name: `Role ${i}`, password: "local-role-fixture-password"})).user);
    }
    const main = ok(await owner.organization.create({name:"Main",slug:"main"}));
    const ownerMember = main.members[0];
    async function grant(actor, user, role, group) {
      const invitation = ok(await owner.organization.inviteMember({organizationId:group.id, email:user.email, role}));
      return ok(await actor.organization.acceptInvitation({invitationId:invitation.id})).member;
    }
    const administrator = await grant(admin, users[1], "admin", main);
    const member = await grant(peer, users[2], "member", main);
    const second = ok(await owner.organization.create({name:"Second",slug:"second"}));
    const foreign = await grant(peer, users[2], "member", second);
    const role = (c, target, roles, group=main.id) => c.organization.updateMemberRole({memberId:target, role:roles, ...(group===null?{}:{organizationId:group})});
    const forbidden = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER";
    denied(await role(outsider, member.id, "admin", null), 400, "NO_ACTIVE_ORGANIZATION");
    denied(await role(outsider, member.id, "admin"), 400, "MEMBER_NOT_FOUND");
    denied(await role(admin, "absent", "member"), 400, "MEMBER_NOT_FOUND");
    denied(await role(owner, foreign.id, "admin"), 403, forbidden);
    denied(await role(peer, member.id, "admin"), 403, forbidden);
    denied(await role(admin, member.id, "owner"), 403, forbidden);
    denied(await role(admin, ownerMember.id, "admin"), 403, forbidden);
    denied(await role(owner, ownerMember.id, "admin"), 400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER");
    const invalid = await role(owner, member.id, ["unlisted","also-unlisted"]);
    denied(invalid, 400, "ROLE_NOT_FOUND");
    assert.equal(invalid.error.message, "ROLE_NOT_FOUND: unlisted, also-unlisted");
    const empty = (await role(owner, member.id, ["  ",","])).error;
    assert.equal(empty.status, 400);
    assert.equal(empty.code, undefined);
    assert.equal(empty.message, undefined);
    assert.equal(lastReply, "");
    ok(await admin.organization.setActive({organizationId:main.id}));
    const updated = ok(await role(admin, member.id, [" admin,member ", "", "admin"], null));
    assert.equal(updated.role, "admin,member,admin");
    assert.equal(updated.id, member.id);
    assert.equal(updated.userId, users[2].id);
    assert.equal(updated.organizationId, main.id);
    assert.deepEqual(updated.createdAt, member.createdAt);
    assert.equal("member" in updated, false);
    assert.equal(ok(await role(peer, administrator.id, "member")).role,"member");
    denied(await role(admin, member.id, "admin"),403, forbidden);
    assert.equal(ok(await role(owner, member.id, "owner, member")).role,"owner,member");
    assert.equal(ok(await role(owner, ownerMember.id, "member")).role,"member");
    denied(await role(owner, member.id, "member"),403, forbidden);
    denied(await role(peer, member.id, "admin"),400,"YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER");
    assert.equal(ok(await role(peer, ownerMember.id, "admin")).role,"admin");
  }
}
