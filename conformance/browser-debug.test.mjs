import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { chromeBinary, chromeDebugPort, openChromePage } from "./browser-debug.mjs";

test("browser startup waits for the complete port line", () => {
  const port = "51307";
  for (let len = 0; len <= port.length; len++) {
    assert.equal(chromeDebugPort(port.slice(0, len)), null);
  }
  assert.equal(chromeDebugPort(port + "\n"), 51307);
  assert.equal(chromeDebugPort(port + "\r\n/devtools/browser/test"), 51307);
  for (const value of ["", "0", "65536", "2x"]) {
    assert.throws(() => chromeDebugPort(value + "\n"), /Invalid local browser port/);
  }
});

test("the first browser command runs in the loaded fixture document", async t => {
  const binary = chromeBinary();
  if (!binary) return t.skip("requires a local Chrome or Chromium");
  const server = createServer(async (request, response) => {
    if (request.url === "/slow.js") {
      await sleep(1000);
      response.writeHead(200, {"Content-Type": "text/javascript"});
      response.end("window.fixtureReady = true;");
      return;
    }
    response.writeHead(200, {"Content-Type": "text/html"});
    response.end('<!doctype html><script defer src="/slow.js"></script>');
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });

  const url = "http://127.0.0.1:" + server.address().port + "/fixture";
  const call = await openChromePage(t, url, binary);
  const {result} = await call("Runtime.evaluate", {
    expression: "[document.URL, document.readyState, window.fixtureReady, typeof PublicKeyCredential]",
    returnByValue: true,
  });
  assert.deepEqual(result.value, [url, "complete", true, "function"]);
});
