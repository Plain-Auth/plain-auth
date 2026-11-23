import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { defaultAc } from "better-auth/plugins/organization/access";

export async function compareOrganizationRoleDirectory(t, {reference, goFixture, instrument}) {
  const options = {ac: defaultAc, teams: {enabled: true}, dynamicAccessControl: {enabled: true}};
  const servers = [await reference(t, [organization(options)], {logger:{disabled:true}}), await goFixture(t, ["organization-teams", "organization-roles"])];
  for (const [index, server] of servers.entries()) {
    await t.test(index === 0 ? "reference" : "Go", async t => {
      const connect = () => instrument(server, [organizationClient(options)]).client;
      const owner = connect(), reader = connect(), outside = connect();
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const ok = result => { assert.equal(result.error, null, JSON.stringify(result.error)); return result.data; };
      const denied = (result, status, code, message) => {
        assert.equal(result.error?.status, status);
        assert.equal(result.error.code, code);
        if (message) assert.equal(result.error.message, message);
      };
      const list = (actor, query = {}) => actor.organization.listRoles({query});
      const get = (actor, query) => actor.organization.getRole({query});
      denied(await get(outside, {}), 400, "VALIDATION_ERROR", "[query] Invalid input");
      denied(await get(outside, {roleName:"desk"}), 401, "UNAUTHORIZED");
      denied(await list(outside), 401, "UNAUTHORIZED");
      for (const [actor, name] of [[owner, "Owner"], [reader, "Reader"], [outside, "Outside"]]) {
        ok(await actor.signUp.email({name, email:name.toLowerCase()+"@example.test", password:"local-role-directory-password"}));
      }
      denied(await list(owner), 400, "NO_ACTIVE_ORGANIZATION");
      const north = ok(await owner.organization.create({name:"North", slug:"north"}));
      const south = ok(await owner.organization.create({name:"South", slug:"south"}));
      const team = ok(await owner.organization.listTeams())[0];
      ok(await owner.organization.setActiveTeam({teamId: team.id}));
      assert.deepEqual(ok(await list(owner)), []);
      const createdAt = "2024-01-02T03:04:05.000Z", updatedAt = "2025-03-04T05:06:07.120Z";
      const save = db.prepare('INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt","updatedAt") VALUES (?,?,?,?,?,?)');
      save.run("north-desk", north.id, "desk", JSON.stringify({reports:["draft","review"]}), createdAt, null);
      save.run("south-desk", south.id, "desk", JSON.stringify({ac:["read"]}), createdAt, updatedAt);
      const expected = {id:"south-desk", organizationId:south.id, role:"desk", permission:{ac:["read"]}, createdAt:new Date(createdAt), updatedAt:new Date(updatedAt)};
      assert.deepEqual(ok(await get(owner, {roleName:"desk"})), expected);
      assert.deepEqual(ok(await list(owner)), [expected]);
      const explicit = {organizationId:north.id};
      const northern = {id:"north-desk", organizationId:north.id, role:"desk", permission:{reports:["draft","review"]}, createdAt:new Date(createdAt), updatedAt:null};
      assert.deepEqual(ok(await get(owner, {...explicit, roleName:"desk", roleId:"south-desk"})), northern);
      assert.deepEqual(ok(await get(owner, {...explicit, roleName:"", roleId:"north-desk"})), northern);
      assert.deepEqual(ok(await list(owner, explicit)), [northern]);
      for (const query of [{roleName:"DESK"}, {roleName:"owner"}, {roleId:"south-desk"}, {roleName:"missing",roleId:"north-desk"}]) {
        denied(await get(owner, {...explicit, ...query}), 400, "ROLE_NOT_FOUND");
      }
      for (const key of ["roleId","roleName"]) {
        denied(await get(owner, {[key]:""}), 400, "VALIDATION_ERROR", "[query."+key+"] Too small: expected string to have >=1 characters");
      }
      denied(await get(owner, {roleName:"desk",organizationId:""}), 400, "NO_ACTIVE_ORGANIZATION");
      denied(await list(owner, {organizationId:""}), 400, "NO_ACTIVE_ORGANIZATION");
      denied(await get(outside, {...explicit,roleId:"missing"}), 403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION");
      denied(await list(outside, explicit), 403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION");
      const invite = ok(await owner.organization.inviteMember({...explicit,email:"reader@example.test",role:"desk"}));
      ok(await reader.organization.acceptInvitation({invitationId:invite.id}));
      denied(await get(reader, {roleName:"desk"}), 403, "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE");
      denied(await list(reader), 403, "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE");
      db.prepare('UPDATE "organizationRole" SET "permission"=? WHERE "id"=?').run('{"ac":["read"]}', "north-desk");
      assert.equal(ok(await get(reader, {roleId:"north-desk"})).id, "north-desk");
      assert.equal(ok(await list(reader))[0].role, "desk");
      for (let i=0; i<103; i++) save.run("extra-"+i, north.id, "extra-"+i, "{}", createdAt, null);
      const page = ok(await list(reader));
      assert.equal(page.length, 100);
      assert.ok(page.every(row => row.organizationId === north.id));
      const hidden = Array.from({length:103}, (_,i) => "extra-"+i).find(id => !page.some(row => row.id === id));
      assert.equal(ok(await get(reader, {roleId:hidden})).id, hidden);
      const session = ok(await owner.getSession()).session;
      assert.equal(session.activeOrganizationId, south.id);
      assert.equal(session.activeTeamId, team.id);
      for (const [query, message] of [
        ["roleName=a&roleName=b", "[query] Invalid input"],
        ["roleId=&roleName=", "[query] Invalid input"],
        ["organizationId=a&organizationId=b&roleId=", "[query.organizationId] Invalid input: expected string, received array; [query.roleId] Too small: expected string to have >=1 characters"],
      ]) {
        const res = await server.send(new Request(server.baseURL+"/api/auth/organization/get-role?"+query));
        assert.equal(res.status,400);
        assert.deepEqual(await res.json(), {message, code:"VALIDATION_ERROR"});
      }
    });
  }
}
