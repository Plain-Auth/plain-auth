import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareServerGrantRoles(t, {reference, goFixture, instrument, fixtureBinary}) {
  const options = {teams:{enabled:true}};
  const ref = await reference(t, [organization(options)], {rateLimit:{enabled:false}});
  const go = await goFixture(t, ["organization-teams"]);
  const binary = await fixtureBinary();
  const ok = res => {assert.equal(res.error, null, JSON.stringify(res.error)); return res.data;};
  for (const [name,server] of [["reference",ref],["Go",go]]) {
    await t.test(name, async () => {
      const account = async name => {
        const client = instrument(server,[organizationClient(options)]).client;
        const user = ok(await client.signUp.email({name,email:name+"@example.test",password:"local-trusted-grant-password"})).user;
        return {user,client};
      };
      const host = await account("host");
      const group = ok(await host.client.organization.create({name:"Studio",slug:"studio"}));
      const team = ok(await host.client.organization.createTeam({name:"Editorial"}));
      const cases = [
        [["news, editor"," news "," , "],"news,editor,news"],
        [" news, featured, news ","news,featured,news"],
        [[], ""],
        ["", ""],
      ];
      for (const [index,[role,expected]] of cases.entries()) {
        const {user,client} = await account("writer"+index);
        const body = {organizationId:group.id, userId:user.id, role, teamId:team.id};
        let grant;
        if (server === ref) {
          grant = await ref.api.addMember({body});
        } else {
          const child = spawnSync(binary, ["add-organization-member",go.databasePath], {
            input:JSON.stringify({...body, roles:Array.isArray(role) ? role : [role]}), encoding:"utf8",
          });
          assert.equal(child.status, 0, child.stderr);
          grant = JSON.parse(child.stdout);
        }
        assert.equal(grant.role, expected);
        assert.equal(grant.userId, user.id);
        assert.equal(ok(await client.organization.getActiveMemberRole({query:{organizationId:group.id}})).role, expected);
        assert.equal(ok(await client.organization.hasPermission({organizationId:group.id,permissions:{team:["create"]}})).success,false);
        const teams = ok(await client.organization.listUserTeams({query:{organizationId:group.id}}));
        assert.ok(teams.some(row => row.id === team.id));
        ok(await client.organization.setActive({organizationId:group.id}));
        ok(await client.organization.setActiveTeam({teamId:team.id}));
        assert.equal(ok(await client.getSession()).session.activeTeamId,team.id);
        const refused = await client.organization.createTeam({organizationId:group.id,name:"Another"});
        assert.equal(refused.error.code,"YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION");
      }
    });
  }
}
