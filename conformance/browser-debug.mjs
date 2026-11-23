import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

export function chromeBinary() {
  return [process.env.CHROME_BIN, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome", "/usr/bin/chromium"].find(path => path && existsSync(path));
}

// Chrome creates DevToolsActivePort before writing its port and WebSocket path.
// The first newline distinguishes a complete port from an in-progress write.
export function chromeDebugPort(contents) {
  const newline = contents.indexOf("\n");
  if (newline === -1) return null;
  const port = contents.slice(0, newline).replace(/\r$/, "");
  if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
    throw Error("Invalid local browser port");
  }
  return Number(port);
}

// Start a disposable browser and expose its page-scoped DevTools connection.
export async function openChromePage(t, url, binary) {
  const dir = await mkdtemp(join(tmpdir(), "plainauth-chrome-"));
  const browser = spawn(binary, [
    "--headless=new", "--disable-background-networking", "--disable-default-apps",
    "--disable-sync", "--no-first-run", "--no-default-browser-check",
    "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
    "--user-data-dir=" + dir, url,
  ], {stdio: "ignore"});
  const exited = once(browser, "exit");
  let socket;
  t.after(async () => {
    socket?.close();
    if (browser.exitCode === null && browser.signalCode === null) browser.kill();
    await exited;
    await rm(dir, {recursive: true, force: true, maxRetries: 3});
  });

  let target;
  for (let attempt = 0; attempt < 150 && !target; attempt++) {
    if (browser.exitCode !== null || browser.signalCode) throw Error("Local browser exited during startup");
    try {
      const port = chromeDebugPort(await readFile(join(dir, "DevToolsActivePort"), "utf8"));
      if (port !== null) {
        const pages = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
        target = pages.find(page => page.type === "page" && page.url === url);
      }
    } catch (err) {
      if (err.code !== "ENOENT" && !(err instanceof TypeError)) throw err;
    }
    if (!target) await sleep(70);
  }
  assert.ok(target, "Chrome did not open the local fixture");
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });

  let sequence = 0;
  const pending = new Map();
  socket.onmessage = ({data}) => {
    const response = JSON.parse(data);
    const command = pending.get(response.id);
    if (!command) return;
    pending.delete(response.id);
    if (response.error) command.reject(Error(response.error.message));
    else command.resolve(response.result);
  };
  socket.onclose = () => {
    for (const command of pending.values()) command.reject(Error("Local browser disconnected"));
    pending.clear();
  };

  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, {resolve, reject});
    socket.send(JSON.stringify({id, method, params}));
  });
  await waitForDocument(call, url);
  return call;
}

// The target URL is visible before Chrome has committed the new document.
export async function waitForDocument(call, url) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const {result} = await call("Runtime.evaluate", {
        expression: 'document.readyState === "complete" && document.URL === ' + JSON.stringify(url),
        returnByValue: true,
      });
      if (result.value === true) return;
    } catch (err) {
      if (!/context was destroyed|Cannot find context/i.test(err.message)) throw err;
    }
    await sleep(40);
  }
  assert.fail("Chrome did not load the fixture document at " + url);
}
