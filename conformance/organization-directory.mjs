import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareMemberDirectory(t, { reference, goFixture, instrument }) {
  for (const server of [await reference(t, [organization()]), await goFixture(t, ["organization"])]) {
    const connect = () => instrument(server, [organizationClient()]).client;
    const owner = connect(), member = connect(), guest = connect();
    const ok = res => {
      assert.equal(res.error, null, JSON.stringify(res.error));
      return res.data;
    };
    const denied = (res, status, code) => {
      assert.equal(res.error?.status, status, JSON.stringify(res));
      assert.equal(res.error?.code, code);
    };
    const list = (client, query = {}) => client.organization.listMembers({query});
    denied(await list(owner), 401, "UNAUTHORIZED");
    denied(await list(owner, {sortDirection: "sideways"}), 400, "VALIDATION_ERROR");
    const signup = async (c, name) => ok(await c.signUp.email({name, email: name+"@example.test", password: "directory-fixture-password"})).user;
    await signup(owner, "owner");
    const peer = await signup(member, "peer");
    await signup(guest, "guest");
    denied(await list(owner), 400, "NO_ACTIVE_ORGANIZATION");
    const group = ok(await owner.organization.create({name: "Studio", slug: "studio"}));
    const other = ok(await owner.organization.create({name: "Shop", slug: "shop"}));
    const invite = ok(await owner.organization.inviteMember({organizationId: group.id, email: peer.email, role: "member"}));
    const joined = ok(await member.organization.acceptInvitation({invitationId: invite.id})).member;
    ok(await member.organization.setActive({organizationId: group.id}));
    const core = ok(await list(member, {sortBy: "role", sortDirection: "desc"}));
    assert.deepEqual(core.members.map(m => m.role), ["owner", "member"]);
    assert.equal(core.total, 2);
    for (const limit of ["0x1", "1e0", "1.0"]) {
      assert.equal(ok(await list(member, {limit})).members.length, 1);
    }
    assert.equal(ok(await list(member, {limit:"invalid", offset:"invalid"})).members.length, 2);
    assert.deepEqual(Object.keys(core.members[1]).sort(), ["createdAt","id","organizationId","role","user","userId"]);
    assert.deepEqual(core.members[1].user, {id: peer.id, email: peer.email, name: peer.name, image: null});
    const scoped = ok(await list(owner, {organizationId: other.id, organizationSlug: group.slug, sortBy: "role", limit: 1, offset: 1}));
    assert.deepEqual(scoped, {members: [core.members[0]], total: 2});
    assert.deepEqual(ok(await list(member, {offset: 90})), {members: [], total: 2});
    assert.equal(ok(await list(owner, {organizationId: other.id})).total, 1);
    assert.equal(ok(await owner.getSession()).session.activeOrganizationId, other.id);
    for (const [filterOperator, filterValue, wanted] of [
      ["eq","member",["member"]], ["ne","member",["owner"]], ["gt","member",["owner"]],
      ["gte","owner",["owner"]], ["lt","owner",["member"]], ["lte","member",["member"]],
      ["contains","wn",["owner"]], ["starts_with","me",["member"]], ["ends_with","er",["member","owner"]],
      ["in",["member","owner"],["member","owner"]], ["not_in",["owner"],["member"]], ["contains","m_m%",["member"]],
    ]) {
      const page = ok(await list(member, {filterField:"role", filterOperator, filterValue, sortBy:"role"}));
      assert.deepEqual(page.members.map(m => m.role), wanted, filterOperator);
      assert.equal(page.total, wanted.length);
    }
    assert.equal(ok(await list(member, {filterField:"createdAt", filterOperator:"gt", filterValue:"2000-01-01T00:00:00.000Z"})).total, 2);
    assert.deepEqual(ok(await list(member, {filterField:"organizationId", filterValue:other.id})), {members: [], total: 0});
    const forbidden = "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION";
    denied(await list(guest, {organizationId:group.id, offset:500}), 403, forbidden);
    denied(await list(guest, {organizationId:"unknown"}), 403, forbidden);
    denied(await list(member, {organizationId:group.id, organizationSlug:"absent"}), 400, "ORGANIZATION_NOT_FOUND");
    const db = server.database ?? new DatabaseSync(server.databasePath);
    try {
      const at = "2020-01-02T01:02:03.123Z";
      const userRow = db.prepare('INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,0,?,?)');
      const memberRow = db.prepare('INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)');
      for (let i=0; i<104; i++) {
        const id = "imported-" + String(i).padStart(3,"0");
        userRow.run(id,id,id+"@example.test",at,at);
        memberRow.run("m-"+id,group.id,id,"member",at);
      }
      for (const limit of [undefined, 0, 105, 500]) {
        const page = ok(await list(member, {limit, sortBy:"userId"}));
        assert.equal(page.total, 106);
        assert.equal(page.members.length, Math.min(limit || 100, 106));
        assert.ok(page.members.every(m => m.user.id === m.userId && m.organizationId === group.id));
      }
    } finally {
      if (!server.database) db.close();
    }
    ok(await owner.organization.removeMember({organizationId:group.id, memberIdOrEmail:joined.id}));
    denied(await list(member, {organizationId:group.id}), 403, forbidden);
  }
}
