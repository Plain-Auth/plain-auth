import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { scim } from "@better-auth/scim";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export async function managedCatalog(t, goFixture, { retirement = false } = {}) {
  const go = await goFixture(t, ["scim-managed"]);
  const dir = await mkdtemp(join(tmpdir(), "scim-server-fixture-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const binary = join(dir, "scimfixture");
  execFileSync("go", ["build", "-o", binary, "./conformance/scimfixture"], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
  });

  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const options = {
    baseURL: "http://reference.localhost",
    secret: "local-conformance-0123456789-abcdefghijk",
    database: { dialect: new NodeSqliteDialect({ database: db }), type: "sqlite", transaction: true },
    plugins: [scim({ connections: [], managedConnections: {
      credentialHashSecret: "managed-local-fixture-credential-digest-secret", maxActiveCredentials: 3,
    } })],
    telemetry: { enabled: false },
  };
  await (await getMigrations(options)).runMigrations();
  const reference = betterAuth(options);
  const operations = {
    create: "createSCIMManagedConnection",
    rotate: "rotateSCIMManagedCredential",
    revoke: "revokeSCIMManagedCredential",
    get: "getSCIMManagedConnection",
    events: "listSCIMManagedConnectionEvents",
    list: "listSCIMManagedConnections",
    retire: "decommissionSCIMManagedConnection",
    retireDirectory: "decommissionSCIMConnection",
  };
  const refAdmin = (op, body) => reference.api[operations[op]]({ body });
  const goAdmin = (op, body) => JSON.parse(execFileSync(binary, [go.databasePath], {
    input: JSON.stringify({ op, ...body }), encoding: "utf8",
  }));
  const runtimes = [
    { base: options.baseURL, send: request => reference.handler(request) },
    { base: go.baseURL, send: go.send },
  ];

  async function request(runtime, token, status) {
    const response = await runtime.send(new Request(runtime.base + "/api/auth/scim/v2/Users", {
      headers: { authorization: "Bearer " + token },
    }));
    assert.equal(response.status, status);
    assert.equal((await response.json()).status, status === 401 ? "401" : undefined);
  }

  for (const [i, [issuer, peer]] of [[goAdmin, refAdmin], [refAdmin, goAdmin]].entries()) {
    const domain = "catalog-domain-" + i;
    const actorId = "tenant-administrator";
    const policy = { actorId, scopes: ["scim.users.read"], expiresAt: new Date(Date.now() + 3600000) };
    const create = { ...policy, creationRequestId: "unique-catalog-request-" + i, provisioningDomainId: domain };
    const initial = await issuer("create", create);
    const owner = { connectionId: initial.connection.connectionId, provisioningDomainId: domain };
    assert.match(initial.token, /^ba_scim_credential_[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{48}$/);
    for (const runtime of runtimes) await request(runtime, initial.token, 200);

    const state = await peer("get", owner);
    assert.equal(state.credentials[0].credentialId, initial.credential.credentialId);
    assert.ok(state.credentials[0].lastUsedAt);
    const duplicate = goAdmin("create", create);
    assert.equal(duplicate.status, 409);
    assert.equal(duplicate.token, undefined);

    const rotated = await peer("rotate", { ...owner, ...policy });
    assert.notEqual(initial.token, rotated.token);
    for (const runtime of runtimes) {
      await request(runtime, rotated.token, 200);
      await request(runtime, initial.token, 200);
    }

    const revoke = { ...owner, credentialId: rotated.credential.credentialId, actorId };
    await issuer("revoke", revoke);
    await peer("revoke", revoke);
    for (const runtime of runtimes) {
      await request(runtime, rotated.token, 401);
      await request(runtime, initial.token, 200);
    }
    const history = await peer("events", { ...owner, limit: 2, offset: 0 });
    assert.deepEqual(history.events.map(e => [e.sequence, e.type]), [[3, "credential.rotated"], [4, "credential.revoked"]]);
    assert.equal(history.total, 4);
    const list = await peer("list", { provisioningDomainId: domain });
    assert.deepEqual(list.connections.map(c => c.connectionId), [owner.connectionId]);
    assert.equal(goAdmin("get", { ...owner, provisioningDomainId: "foreign" }).status, 404);

    const row = db.prepare("SELECT tokenDigest FROM scimManagedCredential WHERE credentialId=?").get(initial.credential.credentialId);
    assert.equal(row.tokenDigest.length, 43);
    assert.ok(!JSON.stringify(state).includes(row.tokenDigest));

    if (retirement) {
      const email = "retire-" + i + "@example.test";
      const createResponse = await runtimes[i].send(new Request(runtimes[i].base + "/api/auth/scim/v2/Users", {
        method: "POST",
        headers: { "content-type": "application/scim+json", authorization: "Bearer " + initial.token },
        body: JSON.stringify({ userName: email, schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"] }),
      }));
      assert.equal(createResponse.status, 403);
      const write = await issuer("rotate", { ...owner, ...policy, scopes: ["scim.users.write"] });
      const provisioned = await runtimes[i].send(new Request(runtimes[i].base + "/api/auth/scim/v2/Users", {
        method: "POST",
        headers: { "content-type": "application/scim+json", authorization: "Bearer " + write.token },
        body: JSON.stringify({ userName: email, schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"] }),
      }));
      assert.equal(provisioned.status, 201);
      const { id } = await provisioned.json();
      const subject = db.prepare("SELECT userId FROM scimUser WHERE id=?").get(id);
      const now = Date.now();
      const session = "retire-session-" + i;
      db.prepare('INSERT INTO session (id, token, userId, createdAt, updatedAt, expiresAt) VALUES(?,?,?,?,?,?)')
        .run(session, session, subject.userId, ...[now, now, now + 3600000].map(ms => new Date(ms).toISOString()));

      const result = await peer("retire", { ...owner, actorId });
      assert.equal(result.connection.status, "decommissioned");
      assert.equal(result.decommission.status, "complete");
      assert.equal(result.decommission.reconciledUsers, 1);
      assert.equal(result.decommission.batches, 1);
      assert.equal(result.credentials.find(k => k.credentialId === write.credential.credentialId).status, "decommissioned");
      for (const runtime of runtimes) await request(runtime, initial.token, 401);
      assert.equal(db.prepare("SELECT count(*) AS n FROM session WHERE id=?").get(session).n, 0);
      assert.equal(db.prepare("SELECT profileSourceId FROM scimSubject WHERE userId=?").get(subject.userId).profileSourceId, null);
      const repeat = await issuer("retire", { ...owner, actorId: "another-admin" });
      assert.equal(repeat.connection.decommissionedBy, actorId);
      assert.equal(repeat.decommission.status, "complete");
      const { events } = await issuer("events", owner);
      assert.deepEqual(events.slice(-2).map(e => e.type), ["connection.decommissioning", "connection.decommissioned"]);

      const beforeUse = { connectionId: "unused-directory-" + i, provisioningDomainId: domain };
      const terminal = await peer("retireDirectory", beforeUse);
      const observed = await issuer("retireDirectory", beforeUse);
      assert.equal(terminal.status, "complete");
      assert.equal(observed.status, "complete");
      assert.equal(observed.batches, 0);
      assert.equal(observed.reconciledUsers, 0);
      assert.equal(new Date(observed.completedAt).getTime(), new Date(terminal.completedAt).getTime());
    }
  }
}
