import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function chromePopup(t, goFixture) {
  const binary = [
    process.env.CHROME_BIN,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome"
  ].find((p) => p && existsSync(p));
  if (!binary) {
    t.skip("requires a local Chrome or Chromium");
    return;
  }
  const script = await readFile(new URL("../plugins/oauthpopup/browser.mjs", import.meta.url));
  let authURL, app, report;
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, "http://localhost");
    if (path.pathname === "/popup.mjs") {
      res.writeHead(200, { "Content-Type": "text/javascript" });
      res.end(script);
      return;
    }
    if (path.pathname === "/report") {
      let raw = "";
      for await (const part of req) raw += part;
      report(JSON.parse(raw));
      res.end();
      return;
    }
    if (path.pathname === "/authorize") {
      const redirect = new URL(path.searchParams.get("redirect_uri"));
      if (
        redirect.origin !== authURL ||
        redirect.pathname !== "/api/auth/callback/work" ||
        path.searchParams.get("code_challenge_method") !== "S256"
      ) {
        res.writeHead(400);
        res.end();
        return;
      }
      redirect.searchParams.set("state", path.searchParams.get("state"));
      redirect.searchParams.set("code", "fixture");
      res.writeHead(302, { location: redirect.href });
      res.end();
      return;
    }
    res.setHeader("Content-Type", "text/html");
    if (path.pathname === "/frame") {
      res.end('<iframe src="' + app + '/app"></iframe>');
      return;
    }
    if (path.pathname !== "/app") {
      res.end();
      return;
    }
    res.end(`<!doctype html><script type="module">
      import {createPopupClient} from "/popup.mjs";

      const audit = {calls: [], notifications: 0, hostListener: 0};
      window.addEventListener("message", event => {
        if (event.data?.type === "stonewrit:oauth-popup") audit.hostListener++;
      });
      const client = createPopupClient({
        baseURL: ${JSON.stringify(authURL)},
        onSession(session) {
          audit.notifications++;
          audit.email = session.user.email;
        },
        fetch(url, options) {
          audit.calls.push({
            path: new URL(url).pathname,
            bearer: options.headers.has("authorization"),
            credentials: options.credentials,
          });
          return fetch(url, options);
        },
      });
      try {
        audit.result = await client.signIn.popup({
          provider: "work",
          requestSignUp: true,
          additionalData: {campaign: "local"},
          timeoutMs: 12000,
        });
        audit.stored = Boolean(client.getStoredPopupToken());
        const logout = await client.fetch("/sign-out", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: "{}",
        });
        audit.logout = logout.status;
        audit.cleared = client.getStoredPopupToken() === null;
        const after = await client.fetch("/get-session");
        audit.after = await after.json();
      } catch (error) {
        audit.failure = String(error);
      }
      await fetch("/report", {method: "POST", body: JSON.stringify(audit)});
    </script>`);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(
    () =>
      new Promise((done) => {
        server.close(done);
        server.closeAllConnections();
      })
  );
  app = "http://127.0.0.1:" + server.address().port;
  authURL = (await goFixture(t, [], { CONFORMANCE_POPUP_ORIGIN: app })).baseURL;
  for (const embedded of [false, true]) {
    const site = embedded ? "http://localhost:" + server.address().port + "/frame" : app + "/app";
    const profile = await mkdtemp(join(tmpdir(), "stonewrit-popup-"));
    const result = new Promise((resolve) => (report = resolve));
    const chrome = spawn(
      binary,
      [
        "--headless=new",
        "--disable-popup-blocking",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-component-update",
        "--host-resolver-rules=MAP localhost 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "--user-data-dir=" + profile,
        site
      ],
      { stdio: "ignore" }
    );
    const closed = once(chrome, "exit");
    let timeout;
    try {
      const audit = await Promise.race([
        result,
        new Promise(
          (_, reject) =>
            (timeout = setTimeout(
              () => reject(new Error("Timed out waiting for Chrome popup")),
              22000
            ))
        ),
        closed.then(() => {
          throw Error("Chrome exited before completing the popup");
        })
      ]);
      assert.deepEqual(
        audit.result,
        { data: { success: true }, error: null },
        JSON.stringify(audit)
      );
      assert.equal(audit.email, "popup@example.org");
      assert.equal(audit.notifications, 1);
      assert.equal(audit.hostListener, 1);
      assert.equal(audit.stored, embedded);
      assert.deepEqual(
        audit.calls.slice(0, 2).map((x) => [x.bearer, x.credentials]),
        [
          [embedded, embedded ? "omit" : "include"],
          [embedded, embedded ? "omit" : "include"]
        ]
      );
      assert.equal(audit.logout, 200);
      assert.equal(audit.cleared, true);
      assert.equal(audit.after, null);
    } finally {
      clearTimeout(timeout);
      if (chrome.exitCode === null && !chrome.signalCode) chrome.kill();
      await closed;
      await rm(profile, { recursive: true, force: true, maxRetries: 3 });
    }
  }
}
