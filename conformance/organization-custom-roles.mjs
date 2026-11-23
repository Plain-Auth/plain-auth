import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements } from "better-auth/plugins/organization/access";

export async function compareCustomOrganizationRoles(t, {reference, goFixture, instrument}) {
  const ac = createAccessControl({...defaultStatements, reports: ["read", "publish"]});
  const roles = {
    founder: ac.newRole({invitation: ["create"]}),
    editor: ac.newRole({organization: ["update"], invitation: ["create"], reports: ["read"]}),
    supervisor: ac.newRole({team: ["create", "update", "delete"], member: ["update", "delete"], invitation: ["cancel"], reports: ["publish"]}),
  };
  const options = {ac, roles, creatorRole: "founder", teams: {enabled: true}};
  const ref = await reference(t, [organization(options)], {rateLimit: {enabled: false}});
  const go = await goFixture(t, ["organization-teams"], {CONFORMANCE_ORG_ROLE_POLICY: "editorial"});
  const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
  const denied = (res, code) => assert.equal(res.error?.code, code, JSON.stringify(res));
  for (const [name,server] of [["reference",ref],["Go",go]]) {
    await t.test(name, async () => {
      const account = async name => {
        const client = instrument(server, [organizationClient(options)]).client;
        const user = ok(await client.signUp.email({name,email:name+"@example.test",password:"organization-role-fixture"})).user;
        return {api:client.organization, user};
      };
      const founder = await account("founder"), editor = await account("editor"), supervisor = await account("supervisor");
      const group = ok(await founder.api.create({name:"Editorial", slug:"editorial"}));
      const organizationId = group.id;
      assert.equal(group.members[0].role, "founder");
      const invite = (actor,email,role) => actor.api.inviteMember({organizationId,email,role});
      const check = async (actor,permissions) => ok(await actor.api.hasPermission({organizationId,permissions})).success;
      const change = (actor,memberId,role) => actor.api.updateMemberRole({organizationId,memberId,role});
      async function join(actor,role) {
        const inv = ok(await invite(founder,actor.user.email,role));
        return ok(await actor.api.acceptInvitation({invitationId:inv.id})).member;
      }
      const editorMember = await join(editor,"editor");
      const supervisorMember = await join(supervisor,"supervisor");
      assert.equal(await check(founder,{member:["update"]}), false);
      denied(await founder.api.createTeam({organizationId,name:"Restricted"}),"YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION");
      ok(await editor.api.update({organizationId,data:{name:"Newsroom"}}));
      const team = ok(await supervisor.api.createTeam({organizationId,name:"Review"}));
      ok(await supervisor.api.updateTeam({organizationId,teamId:team.id,data:{name:"Desk"}}));
      ok(await supervisor.api.addTeamMember({organizationId,teamId:team.id,userId:editor.user.id}));
      const listed = ok(await supervisor.api.listUserTeams({query:{organizationId,userId:editor.user.id}}));
      assert.ok(listed.some(row => row.id === team.id));
      ok(await supervisor.api.removeTeamMember({organizationId,teamId:team.id,userId:editor.user.id}));
      ok(await supervisor.api.removeTeam({organizationId,teamId:team.id}));
      denied(await invite(editor,"candidate@example.test","founder"),"YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE");
      const protectedGrant = ok(await invite(founder,"new-founder@example.test","founder"));
      const ordinaryGrant = ok(await invite(editor,"candidate@example.test","editor"));
      const visible = ok(await editor.api.listInvitations({query:{organizationId}}));
      assert.ok(visible.some(inv => inv.id === ordinaryGrant.id));
      assert.ok(!visible.some(inv => inv.id === protectedGrant.id));
      const full = ok(await supervisor.api.getFullOrganization({query:{organizationId}}));
      assert.deepEqual(full.invitations, []);
      ok(await supervisor.api.cancelInvitation({invitationId:ordinaryGrant.id}));
      denied(await change(supervisor,group.members[0].id,"editor"),"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER");
      denied(await change(founder,group.members[0].id,"editor"),"YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER");
      assert.equal(ok(await change(founder,editorMember.id,["editor","supervisor"])).role,"editor,supervisor");
      assert.equal(await check(editor,{reports:["read"]}), true);
      assert.equal(await check(editor,{reports:["publish"]}), true);
      assert.equal(await check(editor,{reports:["read","publish"]}), false);
      assert.equal(ok(await change(founder,editorMember.id,"admin")).role,"admin");
      assert.equal(await check(editor,{organization:["update"]}), false);
      denied(await invite(editor,"late@example.test","member"),"YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION");
      ok(await supervisor.api.removeMember({organizationId,memberIdOrEmail:editorMember.id}));
      assert.equal(ok(await change(founder,supervisorMember.id,"founder")).role,"founder");
      ok(await change(founder,group.members[0].id,"member"));
    });
  }
}
