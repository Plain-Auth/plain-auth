import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements } from "better-auth/plugins/organization/access";

export async function compareStoredOrganizationRoles(t, {goFixture, instrument}) {
  const go = await goFixture(t, ["organization-teams","organization-roles"]);
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const options = {ac:createAccessControl(defaultStatements), teams:{enabled:true}, dynamicAccessControl:{enabled:true}};
  const baseURL = "http://reference.localhost";
  const reference = betterAuth({baseURL,database:db,secret:"local-conformance-0123456789-abcdefghijk",
    emailAndPassword:{enabled:true},telemetry:{enabled:false},rateLimit:{enabled:false},plugins:[organization(options)]});
  const ref = {baseURL,send:req=>reference.handler(req)};
  const connect = server => instrument(server,[organizationClient(options)]).client;
  const boss = connect(ref), host = connect(go), reporter = connect(go), peer = connect(ref);
  const ok = res => { assert.equal(res.error,null,JSON.stringify(res.error)); return res.data; };
  const password = "local-persisted-grants-password";
  for (const [create,login,name] of [[boss,host,"owner"],[reporter,peer,"reporter"]]) {
    const email = name+"@example.test";
    ok(await create.signUp.email({name,email,password}));
    ok(await login.signIn.email({email,password}));
  }
  const north = ok(await boss.organization.create({name:"North",slug:"north"}));
  const south = ok(await boss.organization.create({name:"South",slug:"south"}));
  const setup = (group,role,permission) => boss.organization.createRole({organizationId:group.id, role, permission});
  const query = async (client,group,permissions) => ok(await client.organization.hasPermission({organizationId:group.id,permissions})).success;
  const northRole = ok(await setup(north,"desk",{team:["create"],invitation:["create"]})).roleData;
  ok(await setup(north,"profile",{organization:["update"]}));
  ok(await setup(south,"desk",{team:["update"]}));
  let member;
  for (const [group,role] of [[north,["desk","profile"]],[south,"desk"]]) {
    const grant = ok(await host.organization.inviteMember({organizationId:group.id, email:"reporter@example.test",role}));
    const accepted = ok(await reporter.organization.acceptInvitation({invitationId:grant.id}));
    if (group === north) member = accepted.member;
  }
  for (const client of [peer,reporter]) {
    assert.equal(await query(client,north,{team:["create"]}),true);
    assert.equal(await query(client,north,{organization:["update"]}),true);
    assert.equal(await query(client,north,{team:["create"],organization:["update"]}),false);
    assert.equal(await query(client,south,{team:["create"]}),false);
    assert.equal(await query(client,south,{team:["update"]}),true);
  }
  const formed = ok(await reporter.organization.createTeam({organizationId:north.id,name:"Desk A"}));
  assert.equal(formed.organizationId,north.id);
  assert.equal((await reporter.organization.createTeam({organizationId:south.id,name:"Desk B"})).error.code,"YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION");
  ok(await reporter.organization.update({organizationId:north.id,data:{name:"North desk"}}));
  const invite = ok(await reporter.organization.inviteMember({organizationId:north.id,email:"extra@example.test",role:"profile"}));
  assert.ok(ok(await reporter.organization.listInvitations({query:{organizationId:north.id}})).some(r => r.id === invite.id));
  ok(await boss.organization.updateRole({organizationId:north.id,roleId:northRole.id,data:{permission:{invitation:["cancel"]}}}));
  assert.equal(await query(reporter,north,{team:["create"]}),false);
  assert.equal(await query(reporter,south,{team:["update"]}),true);
  ok(await reporter.organization.cancelInvitation({invitationId:invite.id}));
  ok(await host.organization.updateMemberRole({organizationId:north.id,memberId:member.id,role:"desk"}));
  assert.equal(await query(reporter,north,{organization:["update"]}),false);
  assert.equal(ok(await reporter.getSession()).session.activeOrganizationId,south.id);
}
