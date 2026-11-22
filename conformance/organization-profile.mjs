import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareOrganizationProfiles(t, { reference, goFixture, instrument }) {
  for (const server of [await reference(t,[organization()]), await goFixture(t,["organization"])]) {
    const make = () => instrument(server,[organizationClient()]).client;
    const ok = result => {assert.equal(result.error,null,JSON.stringify(result.error));return result.data;};
    const problem = (res,status,code) => {assert.equal(res.error?.status,status);if(code)assert.equal(res.error.code,code);};
    const owner=make(), peer=make(), outsider=make(), anonymous=make();
    for(const [name,c] of [["owner",owner],["peer",peer],["outsider",outsider]]) {
      ok(await c.signUp.email({name,email:name+"@example.org",password:"organization test password"}));
    }
    const group=ok(await owner.organization.create({name:"Before",slug:"org-early",logo:"/first.svg",metadata:{source:"first"}}));
    const other=ok(await outsider.organization.create({name:"Other",slug:"org-other"}));
    const patch=(c,data,organizationId)=>c.organization.update({organizationId,data});
    const check=(c,slug)=>c.organization.checkSlug({slug});
    assert.deepEqual(ok(await check(outsider,"org-late")),{status:true});
    problem(await check(owner,"org-early"),400,"ORGANIZATION_SLUG_ALREADY_TAKEN");
    problem(await check(anonymous,"org-late"),401);
    problem(await patch(anonymous,{name:"x"},group.id),401);
    problem(await patch(outsider,{name:"x"},group.id),400,"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
    problem(await patch(peer,{name:"x"}),400,"ORGANIZATION_NOT_FOUND");
    const inv=ok(await owner.organization.inviteMember({email:"peer@example.org",role:"member",organizationId:group.id}));
    const accepted=ok(await peer.organization.acceptInvitation({invitationId:inv.id}));
    problem(await patch(peer,{name:"x"},group.id),403,"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION");
    const member=accepted.member;
    assert.ok(member.id);
    ok(await owner.organization.updateMemberRole({memberId:member.id,organizationId:group.id,role:"admin"}));
    const updated=ok(await patch(owner,{name:"After",slug:"org-late",logo:null,metadata:{nested:{seats:4}}}));
    assert.equal(updated.id,group.id);
    assert.equal(updated.name,"After");assert.equal(updated.slug,"org-late");assert.equal(updated.logo,null);
    assert.deepEqual(updated.metadata,{nested:{seats:4}});
    const kept=ok(await patch(peer,{name:"Second"},group.id));
    assert.equal(kept.slug,"org-late");assert.deepEqual(kept.metadata,{nested:{seats:4}});
    problem(await patch(owner,{name:"Rolled back",slug:other.slug}),400,"ORGANIZATION_SLUG_ALREADY_TAKEN");
    const confirmed=ok(await patch(owner,{slug:"org-late"}));
    assert.equal(confirmed.name,"Second");
    assert.deepEqual(ok(await check(owner,"org-early")),{status:true});
    problem(await check(owner,"org-late"),400,"ORGANIZATION_SLUG_ALREADY_TAKEN");
  }
}
