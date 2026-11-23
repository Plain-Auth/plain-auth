import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { defaultAc } from "better-auth/plugins/organization/access";

export async function compareOrganizationRoleUpdates(t,{reference,goFixture,instrument}) {
  const options = {ac:defaultAc,teams:{enabled:true},dynamicAccessControl:{enabled:true}};
  const servers = [await reference(t,[organization(options)],{logger:{disabled:true}}),await goFixture(t,["organization-roles","organization-teams"])];
  for (const [index,server] of servers.entries()) await t.test(index===0?"reference":"Go",async () => {
    const connect = () => instrument(server,[organizationClient(options)]).client;
    const owner=connect(), reader=connect(), outside=connect();
    const ok = result => {assert.equal(result.error,null,JSON.stringify(result.error));return result.data;};
    const denied = (result,status,code) => {assert.equal(result.error?.status,status);assert.equal(result.error.code,code);return result.error;};
    const update = (client,query,data) => client.organization.updateRole({...query,data});
    const get = (q) => owner.organization.getRole({query:q});
    const permits = async (group,actions) => ok(await reader.organization.hasPermission({organizationId:group.id,permissions:actions})).success;
    denied(await update(outside,{roleName:"desk"},{}),401,"UNAUTHORIZED");
    for (const [body,message] of [
      [{roleName:"desk"},"[body.data] Invalid input: expected object, received undefined"],
      [{data:{permission:null}},"[body.data.permission] Invalid input: expected record, received null; [body] Invalid input"],
      [{roleName:"",data:{roleName:1}},"[body.data.roleName] Invalid input: expected string, received number; [body.roleName] Too small: expected string to have >=1 characters"],
    ]) {
      const response=await server.send(new Request(server.baseURL+"/api/auth/organization/update-role",{method:"POST",headers:{origin:server.baseURL,"content-type":"application/json"},body:JSON.stringify(body)}));
      assert.equal(response.status,400);
      assert.deepEqual(await response.json(),{message,code:"VALIDATION_ERROR"});
    }
    for (const [client,name] of [[owner,"owner"],[reader,"reader"],[outside,"outsider"]]) ok(await client.signUp.email({name,email:name+"@example.test",password:"local-role-change-password"}));
    denied(await update(owner,{roleId:"x"},{}),400,"NO_ACTIVE_ORGANIZATION");
    const north=ok(await owner.organization.create({name:"North",slug:"north"})), south=ok(await owner.organization.create({name:"South",slug:"south"}));
    const selected=ok(await owner.organization.listTeams())[0];
    ok(await owner.organization.setActiveTeam({teamId:selected.id}));
    const scope={organizationId:north.id};
    const define=async (group,role,permission)=>ok(await owner.organization.createRole({organizationId:group.id,role,permission})).roleData;
    const desk=await define(north,"desk",{team:["create"]}), other=await define(south,"desk",{ac:["read"]});
    await define(north,"manager",{ac:["update"]});
    const invited=ok(await owner.organization.inviteMember({...scope,email:"reader@example.test",role:"desk"}));
    const membership=ok(await reader.organization.acceptInvitation({invitationId:invited.id})).member;
    const pending=ok(await owner.organization.inviteMember({...scope,email:"pending@example.test",role:"desk"}));
    const byId={...scope,roleId:desk.id};
    denied(await update(owner,{organizationId:"",roleId:desk.id},{}),400,"NO_ACTIVE_ORGANIZATION");
    const implicit=ok(await update(owner,{roleId:other.id},{}));
    assert.equal(implicit.roleData.organizationId,south.id);
    denied(await update(outside,byId,{}),403,"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION");
    denied(await update(reader,byId,{}),403,"YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE");
    denied(await update(owner,{...scope,roleId:other.id},{}),400,"ROLE_NOT_FOUND");
    denied(await update(owner,{...scope,roleName:"absent",roleId:desk.id},{}),400,"ROLE_NOT_FOUND");
    for (const name of ["desk","MANAGER","owner"]) denied(await update(owner,byId,{roleName:name}),400,"ROLE_NAME_IS_ALREADY_TAKEN");
    denied(await update(owner,byId,{permission:{other:[]}}),400,"INVALID_RESOURCE");
    assert.equal(await permits(north,{team:["create"]}),true);
    const applied=ok(await update(owner,{...scope,roleName:"desk",roleId:other.id},{permission:{organization:["update"]}}));
    assert.deepEqual(Object.keys(applied).sort(),["roleData","success"]);
    assert.equal(applied.success,true);
    assert.equal(applied.roleData.id,desk.id);
    assert.equal(applied.roleData.updatedAt,null);
    assert.deepEqual(applied.roleData.permission,{organization:["update"]});
    assert.equal(await permits(north,{team:["create"]}),false);
    assert.equal(await permits(north,{organization:["update"]}),true);
    const saved=ok(await get(byId));
    assert.ok(saved.updatedAt instanceof Date);
    const empty=ok(await update(owner,byId,{roleName:""}));
    assert.deepEqual(empty.roleData,saved);
    ok(await owner.organization.updateMemberRole({...scope,memberId:membership.id,role:["manager","desk"]}));
    const refusal=denied(await update(reader,byId,{roleName:"new desk",permission:{team:["delete"]}}),403,"YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE");
    assert.deepEqual(refusal.missingPermissions,["team:delete"]);
    assert.equal(ok(await get(byId)).role,"desk");
    const renamed=ok(await update(owner,{...scope,roleName:"",roleId:desk.id},{roleName:"New Desk"})).roleData;
    assert.equal(renamed.role,"new desk");
    assert.deepEqual(renamed.permission,{organization:["update"]});
    const active=ok(await reader.organization.getActiveMember());
    assert.equal(active.role,"manager,desk");
    const invitations=ok(await owner.organization.listInvitations({query:scope}));
    assert.equal(invitations.find(r=>r.id===pending.id).role,"desk");
    assert.equal(await permits(north,{organization:["update"]}),false);
    assert.deepEqual(ok(await update(owner,byId,{permission:{}})).roleData.permission,{});
    assert.equal(ok(await get({roleId:other.id})).role,"desk");
    const session=ok(await owner.getSession()).session;
    assert.equal(session.activeOrganizationId,south.id);
    assert.equal(session.activeTeamId,selected.id);
  });
}
