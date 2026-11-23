import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { defaultAc } from "better-auth/plugins/organization/access";

export async function compareOrganizationRoleDeletion(t, {reference, goFixture, instrument}) {
  const options = {ac:defaultAc, teams:{enabled:true}, dynamicAccessControl:{enabled:true}};
  const servers = [await reference(t, [organization(options)], {logger:{disabled:true}}), await goFixture(t, ["organization-teams","organization-roles"])];
  for (const [index, server] of servers.entries()) {
    await t.test(index === 0 ? "reference" : "Go", async t => {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const owner = connect(), guest = connect(), outside = connect();
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const ok = result => { assert.equal(result.error, null, JSON.stringify(result.error)); return result.data; };
      const remove = (actor, body) => actor.organization.deleteRole(body);
      const denied = (result, status, code) => {
        assert.equal(result.error?.status,status);
        assert.equal(result.error.code,code);
      };
      denied(await remove(outside,{fetchOptions:{method:"POST"}}), 400, "VALIDATION_ERROR");
      denied(await remove(outside,{roleName:"desk"}), 401, "UNAUTHORIZED");
      for (const [body, message] of [
        [{roleName:null}, "[body] Invalid input"],
        [{roleName:"",roleId:""}, "[body] Invalid input"],
        [{organizationId:null,roleId:""}, "[body.organizationId] Invalid input: expected string, received null; [body.roleId] Too small: expected string to have >=1 characters"],
      ]) {
        const response = await server.send(new Request(server.baseURL+"/api/auth/organization/delete-role", {
          method:"POST", headers:{"content-type":"application/json",origin:server.baseURL}, body:JSON.stringify(body),
        }));
        assert.equal(response.status,400);
        assert.deepEqual(await response.json(), {code:"VALIDATION_ERROR",message});
      }
      for (const [actor, name] of [[owner,"owner"],[guest,"guest"],[outside,"outside"]]) {
        ok(await actor.signUp.email({name, email:name+"@example.test", password:"local-role-retirement-password"}));
      }
      denied(await remove(owner,{roleName:"desk"}), 400, "NO_ACTIVE_ORGANIZATION");
      const north = ok(await owner.organization.create({name:"North",slug:"north"}));
      const south = ok(await owner.organization.create({name:"South",slug:"south"}));
      const team = ok(await owner.organization.listTeams())[0];
      ok(await owner.organization.setActiveTeam({teamId:team.id}));
      const scope = {organizationId:north.id};
      const save = db.prepare('INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt") VALUES (?,?,?,?,?)');
      for (const [group,id,role] of [[north,"n","desk"],[north,"candidate","editor"],[north,"curator","curator"],[south,"s","desk"]]) {
        save.run(id,group.id,role,role === "curator" ? '{"ac":["delete"]}' : '{}',"2026-01-02T03:04:05.000Z");
      }
      denied(await remove(owner,{...scope,roleName:"owner"}),400,"CANNOT_DELETE_A_PRE_DEFINED_ROLE");
      denied(await remove(owner,{...scope,roleId:"s"}),400,"ROLE_NOT_FOUND");
      denied(await remove(owner,{...scope,roleName:"Desk"}),400,"ROLE_NOT_FOUND");
      denied(await remove(owner,{...scope,roleName:"missing",roleId:"n"}),400,"ROLE_NOT_FOUND");
      denied(await remove(owner,{roleName:"desk",organizationId:""}),400,"NO_ACTIVE_ORGANIZATION");
      denied(await remove(outside,{...scope,roleName:"desk"}),403,"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION");
      const invite = ok(await owner.organization.inviteMember({...scope, email:"guest@example.test",role:["desk","editor"]}));
      const member = ok(await guest.organization.acceptInvitation({invitationId:invite.id})).member;
      denied(await remove(guest,{roleId:"n"}),403,"YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE");
      denied(await remove(owner,{...scope,roleId:"n"}),400,"ROLE_IS_ASSIGNED_TO_MEMBERS");
      db.prepare('UPDATE "member" SET "role"=? WHERE "id"=?').run("editorial, desk ,curator",member.id);
      denied(await remove(guest,{roleName:"desk"}),400,"ROLE_IS_ASSIGNED_TO_MEMBERS");
      assert.deepEqual(ok(await remove(guest,{roleName:"editor",roleId:"n"})),{success:true});
      ok(await owner.organization.updateMemberRole({...scope,memberId:member.id,role:"member"}));
      assert.deepEqual(ok(await remove(owner,{...scope,roleName:"",roleId:"n"})),{success:true});
      denied(await remove(owner,{...scope,roleId:"n"}),400,"ROLE_NOT_FOUND");
      assert.equal(ok(await owner.organization.getRole({query:{roleName:"desk"}})).id,"s");
      assert.deepEqual(ok(await remove(owner,{roleName:"desk"})),{success:true});
      assert.deepEqual(ok(await owner.organization.listRoles()),[]);
      const session = ok(await owner.getSession()).session;
      assert.equal(session.activeOrganizationId,south.id);
      assert.equal(session.activeTeamId,team.id);
    });
  }
}
