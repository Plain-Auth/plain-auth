import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareTeamLimits(t, { reference, goFixture, instrument, fixtureBinary }) {
  const options = {teams: {enabled: true, maximumTeams: ({organizationId, session}, ctx) => {
    if (!session) return 4;
    assert.ok(session.session.token && session.user.id === session.session.userId && ctx.request);
    if (session.user.email === "unlimited@example.test") return 0;
    return session.session.activeOrganizationId === organizationId ? 2 : 3;
  }}};
  const ref = await reference(t, [organization(options)], { logger: { disabled: true } });
  const go = await goFixture(t, ["organization-teams"], { CONFORMANCE_TEAM_LIMIT: "resolve" });
  const binary = await fixtureBinary();
  for (const server of [ref, go]) await t.test(server === go ? "Go" : "reference", async () => {
    const connect = () => instrument(server, [organizationClient({ teams: { enabled: true } })]).client;
    function ok(result) { assert.equal(result.error, null, JSON.stringify(result.error)); return result.data; }
    const limit = "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS";
    const owner = connect(), other = connect(), outsider = connect();
    const make = (client, name, organizationId) => client.organization.createTeam({name, organizationId});
    assert.equal((await make(outsider,"Anonymous","absent")).error?.status, 401);
    for (const [client, email] of [[owner,"owner@example.test"], [other,"unlimited@example.test"]]) {
      ok(await client.signUp.email({name:email,email,password:"team-capacity-local-password"}));
    }
    assert.equal((await make(owner, "Unselected")).error?.code, "NO_ACTIVE_ORGANIZATION");
    const north = ok(await owner.organization.create({name:"North",slug:"north"}));
    const created = ok(await make(owner, "", ""));
    assert.equal(created.name, "");
    assert.equal(created.organizationId, north.id);
    assert.equal((await make(owner,"Third")).error?.code, limit);
    const south = ok(await owner.organization.create({name:"South",slug:"south"}));
    const team = ok(await owner.organization.listTeams({query:{organizationId:south.id}}))[0];
    ok(await owner.organization.setActiveTeam({teamId:team.id}));
    assert.equal(ok(await make(owner,"Explicit",north.id)).organizationId,north.id);
    assert.equal((await make(owner,"Overflow",north.id)).error?.status,400);
    assert.equal((await make(other,"Foreign",north.id)).error?.status,403);
    const active = ok(await owner.getSession()).session;
    assert.equal(active.activeOrganizationId,south.id);
    assert.equal(active.activeTeamId,team.id);
    const free = ok(await other.organization.create({name:"Free",slug:"free"}));
    for (let i=0;i<5;i++) assert.equal(ok(await make(other,"Team "+i)).organizationId,free.id);
    const trusted = {organizationId:north.id,name:"From trusted code"};
    if (server === ref) {
      assert.equal((await ref.api.createTeam({body:trusted})).organizationId,north.id);
      await assert.rejects(ref.api.createTeam({body:trusted}), e => e.body?.code === limit);
    } else {
      const run = () => spawnSync(binary, ["create-organization-team",go.databasePath], {
        input:JSON.stringify(trusted),encoding:"utf8",env:{...process.env,CONFORMANCE_TEAM_LIMIT:"resolve"},
      });
      const result = run();
      assert.equal(result.status,0,result.stderr);
      assert.equal(JSON.parse(result.stdout).organizationId,north.id);
      assert.match(run().stderr,/reached the maximum number of teams/i);
    }
    assert.equal(ok(await owner.organization.listTeams({query:{organizationId:north.id}})).length,4);
    for (const [body, message] of [
      [{}, "[body.name] Invalid input: expected string, received undefined"],
      [{name:14,organizationId:null},"[body.name] Invalid input: expected string, received number; [body.organizationId] Invalid input: expected string, received null"],
    ]) {
      const response=await server.send(new Request(server.baseURL+"/api/auth/organization/create-team",{
        method:"POST", headers:{origin:server.baseURL,"content-type":"application/json"},body:JSON.stringify(body),
      }));
      assert.equal(response.status,400);
      assert.deepEqual(await response.json(),{code:"VALIDATION_ERROR",message});
    }
  });
}
