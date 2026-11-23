import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareMembershipLimits(t, { reference, goFixture, instrument, fixtureBinary }) {
  for (const mode of ["fixed", "dynamic"]) {
    const limit = mode === "fixed" ? 2 : async (user, org) =>
      org.slug === "studio" && user.name === "Guest" ? 0 : 2;
    const ref = await reference(t, [organization({ membershipLimit: limit })]);
    const go = await goFixture(t, ["organization"], { CONFORMANCE_ORG_CAPACITY: mode });
    const binary = await fixtureBinary();
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient()]).client;
      const [owner, peer, guest] = [connect(), connect(), connect()];
      const ok = reply => {
        assert.equal(reply.error, null, JSON.stringify(reply.error));
        return reply.data;
      };
      const users = {};
      for (const [client, name] of [[owner, "Owner"], [peer, "Peer"], [guest, "Guest"]]) {
        users[name] = ok(await client.signUp.email({
          name, email: name.toLowerCase() + "@example.test", password: "capacity-fixture-password",
        })).user;
      }
      const create = async slug => ok(await owner.organization.create({ name: slug, slug }));
      const invite = async (org, user) => ok(await owner.organization.inviteMember({
        organizationId: org.id, email: user.email, role: "member",
      }));
      const accept = (client, invitation) => client.organization.acceptInvitation({ invitationId: invitation.id });
      function atCapacity(reply) {
        assert.equal(reply.error?.status, 403, JSON.stringify(reply));
        assert.equal(reply.error.code, "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED");
      }
      const studio = await create("studio");
      const room = await create("room");
      const guestInvite = await invite(studio, users.Guest);
      if (mode === "dynamic") atCapacity(await accept(guest, guestInvite));
      ok(await accept(peer, await invite(studio, users.Peer)));
      atCapacity(await accept(guest, guestInvite));
      ok(await accept(guest, await invite(room, users.Guest)));
      const third = await invite(room, users.Peer);
      atCapacity(await accept(peer, third));
      ok(await guest.organization.leave({ organizationId: room.id }));
      ok(await accept(peer, third));

      const direct = await create("direct");
      const grant = async (user, denied) => {
        const body = { organizationId: direct.id, userId: user.id, role: "member" };
        if (server === ref) {
          const attempt = ref.api.addMember({ body });
          if (denied) await assert.rejects(attempt, error => error.body?.code === "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED");
          else assert.equal((await attempt).userId, user.id);
        } else {
          const child = spawnSync(binary, ["add-organization-member", go.databasePath], {
            encoding: "utf8", input: JSON.stringify({ ...body, roles: [body.role] }),
            env: { ...process.env, CONFORMANCE_ORG_CAPACITY: mode },
          });
          if (denied) {
            assert.notEqual(child.status, 0);
            assert.match(child.stderr, /Organization membership limit reached/);
          } else {
            assert.equal(child.status, 0, child.stderr);
            assert.equal(JSON.parse(child.stdout).userId, user.id);
          }
        }
      };
      await grant(users.Peer, false);
      await grant(users.Guest, true);

      // An imported organization may already exceed today's admission limit.
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        const at = "2024-01-01T00:00:00.000Z";
        db.prepare('INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,0,?,?)')
          .run("imported", "Imported", "imported@example.test", at, at);
        db.prepare('INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)')
          .run("m-imported", studio.id, "imported", "member", at);
      } finally {
        if (!server.database) db.close();
      }
      const page = async limit => ok(await owner.organization.listMembers({ query: { organizationId: studio.id, limit } }));
      const directory = await page(0);
      assert.equal(directory.total, 3);
      assert.equal(directory.members.length, mode === "fixed" ? 2 : 3);
      assert.equal((await page(3)).members.length, 3);
    }
  }
}
