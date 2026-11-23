import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { defaultAc } from "better-auth/plugins/organization/access";

export async function compareOrganizationRoleCreation(t, {reference,goFixture,instrument}) {
  for (const setting of ["standard","one","unconfigured"]) {
    const options = {dynamicAccessControl:{enabled:true}};
    if (setting !== "unconfigured") options.ac = defaultAc;
    if (setting === "one") options.dynamicAccessControl.maximumRolesPerOrganization = 1;
    const servers = [
      await reference(t,[organization(options)],{logger:{disabled:true}}),
      await goFixture(t,["organization-roles"],{CONFORMANCE_ROLE_LIMIT:setting,CONFORMANCE_ROLE_CONTROL:setting === "unconfigured" ? "none" : "default"}),
    ];
    for (const [index, server] of servers.entries()) await t.test(setting+" "+(index===0?"reference":"Go"),async () => {
      const connect = () => instrument(server,[organizationClient(options)]).client;
      const owner = connect(), contributor = connect();
      const ok = result => { assert.equal(result.error,null,JSON.stringify(result.error)); return result.data; };
      const denied = (result,status,code) => { assert.equal(result.error?.status,status); assert.equal(result.error.code,code); return result.error; };
      const make = (client,role,permission,other={}) => client.organization.createRole({role,permission,...other});
      const register = (client,name) => client.signUp.email({name,email:name+"@example.test",password:"local-role-management-password"});
      denied(await make(owner,"Desk",{}),401,"UNAUTHORIZED");
      if (setting === "standard") {
        for (const [body,message] of [
          [{role:12,permission:[]}, "[body.role] Invalid input: expected string, received number; [body.permission] Invalid input: expected record, received array"],
          [{role:"typed",permission:{ac:[false]}}, "[body.permission.ac.0] Invalid input: expected string, received boolean"],
          [{role:"typed",permission:{},additionalFields:null}, "[body.additionalFields] Invalid input: expected object, received null"],
        ]) {
          const response = await server.send(new Request(server.baseURL+"/api/auth/organization/create-role", {
            method:"POST",headers:{origin:server.baseURL,"content-type":"application/json"},body:JSON.stringify(body),
          }));
          assert.equal(response.status,400);
          assert.deepEqual(await response.json(), {code:"VALIDATION_ERROR",message});
        }
      }
      ok(await register(owner,"owner"));
      if (setting==="unconfigured") {
        denied(await make(owner,"Desk",{}),501,"MISSING_AC_INSTANCE");
        return;
      }
      denied(await make(owner,"Desk",{}),400,"YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE");
      const north = ok(await owner.organization.create({name:"North",slug:"north"}));
      const south = ok(await owner.organization.create({name:"South",slug:"south"}));
      const scope = {organizationId:north.id};
      const created = ok(await make(owner,"Desk",{team:["create","create"]},scope));
      assert.equal(created.success,true);
      assert.equal(created.roleData.role,"desk");
      assert.equal(created.roleData.organizationId,north.id);
      assert.equal(created.roleData.updatedAt,null);
      assert.ok(created.roleData.id && Number.isFinite(+created.roleData.createdAt));
      assert.deepEqual(created.statements,{team:["create","create"]});
      assert.deepEqual(created.roleData.permission,created.statements);
      assert.deepEqual(ok(await owner.organization.getRole({query:{...scope,roleName:"desk"}})),created.roleData);
      const unrelated = ok(await make(owner,"Desk",{}));
      assert.notEqual(unrelated.roleData.id,created.roleData.id);
      assert.equal(unrelated.roleData.organizationId,south.id);
      if (setting==="one") {
        denied(await make(owner,"another",{},scope),400,"TOO_MANY_ROLES");
        ok(await owner.organization.deleteRole({...scope,roleName:"desk"}));
        assert.equal(ok(await make(owner,"replacement",{},scope)).roleData.role,"replacement");
        return;
      }
      denied(await make(owner,"DeSk",{},scope),400,"ROLE_NAME_IS_ALREADY_TAKEN");
      denied(await make(owner,"OWNER",{},scope),400,"ROLE_NAME_IS_ALREADY_TAKEN");
      denied(await make(owner,"invalid",{fiction:[]},scope),400,"INVALID_RESOURCE");
      const missing = denied(await make(owner,"new",{team:["ungranted","another"]},scope),403,"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE");
      assert.deepEqual(missing.missingPermissions,["team:ungranted","team:another"]);
      const vacant = ok(await make(owner,"İdea",{team:[]},{...scope,additionalFields:{ignored:"value"}}));
      assert.equal(vacant.roleData.role,"i\u0307dea");
      assert.deepEqual(vacant.roleData.permission,{team:[]});
      assert.equal(Object.hasOwn(vacant.roleData,"ignored"),false);
      denied(await make(owner,"no-selection",{}, {organizationId:""}),400,"YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE");
      ok(await register(contributor,"delegate"));
      denied(await make(contributor,"absent",{},scope),403,"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION");
      const creator = ok(await make(owner,"creator",{ac:["create"],team:["create"]},scope));
      ok(await make(owner,"writer",{organization:["update"]},scope));
      const pending = ok(await owner.organization.inviteMember({...scope,email:"delegate@example.test",role:["creator","writer"]}));
      ok(await contributor.organization.acceptInvitation({invitationId:pending.id}));
      const delegated = ok(await make(contributor,"combined",{team:["create"],organization:["update"]}));
      assert.deepEqual(delegated.statements,{team:["create"],organization:["update"]});
      denied(await make(contributor,"too-wide",{team:["delete"]}),403,"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE");
      assert.equal(ok(await owner.getSession()).session.activeOrganizationId,south.id);
      assert.ok(creator.roleData.id);
    });
  }
}
