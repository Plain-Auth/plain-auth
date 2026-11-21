import assert from "node:assert/strict";
import {organization} from "better-auth/plugins";
import {organizationClient} from "better-auth/client/plugins";

export async function compareOrganizationRemoval(t,{reference,goFixture,instrument}) {
  const teamOptions = {teams:{enabled:true}};
  const targets = [
    ["reference", await reference(t,[organization(teamOptions)])],
    ["go", await goFixture(t,["organization-teams"])],
    ["go", await goFixture(t,["organization"])],
  ];
  for (const [runtime, server] of targets) {
    const make = () => instrument(server,[organizationClient(teamOptions)]).client;
    const ok = r => { assert.equal(r.error,null,JSON.stringify(r.error)); return r.data; };
    const denial = (r,code,status) => { assert.equal(r.error?.code,code); assert.equal(r.error?.status,status); };
    const owner = make(), admin = make(), member = make();
    const signup = async (client,name) => ok(await client.signUp.email({
      name,email:name+"@example.test",password:"local-org-fixture-password",
    })).user;
    await signup(owner,"owner");
    const adminUser = await signup(admin,"admin");
    const user = await signup(member,"member");
    const main = ok(await owner.organization.create({name:"Main",slug:"main"}));
    async function grant(target, email, role, organizationId) {
      const invite=ok(await owner.organization.inviteMember({email,role,organizationId}));
      return ok(await target.organization.acceptInvitation({invitationId:invite.id})).member;
    }
    const peer = await grant(member,user.email,"member",main.id);
    await grant(admin,adminUser.email,"admin",main.id);
    denial(await member.organization.removeMember({memberIdOrEmail:peer.id,organizationId:main.id}),"YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",401);
    denial(await admin.organization.removeMember({memberIdOrEmail:main.members[0].id,organizationId:main.id}),"YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",400);
    const second = ok(await owner.organization.create({name:"Second",slug:"second"}));
    const elsewhere = await grant(member,user.email,"member",second.id);
    denial(await owner.organization.removeMember({memberIdOrEmail:elsewhere.id,organizationId:main.id}),"MEMBER_NOT_FOUND",400);
    ok(await member.organization.setActive({organizationId:main.id}));
    const removed = ok(await admin.organization.removeMember({memberIdOrEmail:user.email.toUpperCase()})).member;
    assert.equal(removed.id,peer.id);
    assert.equal(removed.organizationId,main.id);
    assert.equal(removed.user.id,user.id);
    assert.equal(removed.user.email,user.email);
    assert.deepEqual(ok(await member.organization.list()).map(v=>v.id),[second.id]);
    const activeAfterRemoteRemoval=ok(await member.getSession()).session.activeOrganizationId;
    if(runtime==="go") assert.ok(activeAfterRemoteRemoval==null,"Go clears every session selecting the removed organization");
    else assert.equal(activeAfterRemoteRemoval,main.id);
    const left=ok(await member.organization.leave({organizationId:second.id}));
    assert.equal(left.id,elsewhere.id);
    assert.equal(left.user.email,user.email);
    assert.deepEqual(ok(await member.organization.list()),[]);
    denial(await member.organization.leave({organizationId:second.id}),"MEMBER_NOT_FOUND",400);
    denial(await owner.organization.leave({organizationId:main.id}),"YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",400);
    const byId = await grant(member,user.email,"member",main.id);
    const withoutUser=ok(await owner.organization.removeMember({organizationId:main.id,memberIdOrEmail:byId.id})).member;
    assert.equal(withoutUser.id,byId.id);
    assert.equal("user" in withoutUser,false);
  }
}
