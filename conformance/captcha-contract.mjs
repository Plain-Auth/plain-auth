// Capture provider requests and public errors with the pinned runtime's real
// middleware and an in-process HTTP transport. Fixture credentials are public.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { captcha } from "better-auth/plugins/captcha";

const secretKey = "fixture-secret";
const valid = { success: true, action: "login", hostname: "app.example.org" };
const providers = ["google-recaptcha", "cloudflare-turnstile", "hcaptcha", "captchafox"];
const cases = providers.flatMap(provider => [
  { name: provider + "-pass", provider, reply: valid },
  { name: provider + "-reject", provider, reply: { success: false } },
  { name: provider + "-outage", provider, status: 502, reply: {} },
]);
cases.push(
  { name: "missing-header", provider: "hcaptcha", missing: true },
  { name: "missing-secret", provider: "hcaptcha", noSecret: true },
  { name: "google-v3-low-score", provider: "google-recaptcha", reply: { ...valid, score: 0.49 } },
  { name: "google-v3-threshold", provider: "google-recaptcha", reply: { ...valid, score: 0.5 } },
  { name: "google-v3-custom-score", provider: "google-recaptcha", minScore: 0.9, reply: { ...valid, score: 0.8 } },
  { name: "google-action", provider: "google-recaptcha", reply: { ...valid, action: "other" } },
  { name: "google-host", provider: "google-recaptcha", reply: { ...valid, hostname: "other.example.org" } },
  { name: "turnstile-host", provider: "cloudflare-turnstile", reply: { success: true, action: "login" } },
  { name: "turnstile-action", provider: "cloudflare-turnstile", reply: { success: true, hostname: "app.example.org" } },
  { name: "override-url", provider: "captchafox", override: "https://custom.example.org/verify", reply: valid },
  { name: "google-override-url", provider: "google-recaptcha", override: "https://custom.example.org/google/verify", reply: valid },
  { name: "turnstile-override-url", provider: "cloudflare-turnstile", override: "https://custom.example.org/turnstile/verify", reply: valid },
  { name: "hcaptcha-override-url", provider: "hcaptcha", override: "https://custom.example.org/hcaptcha/verify", reply: valid },
);
const originalFetch = globalThis.fetch;
const results = [];
try {
  for (const c of cases) {
    let sent;
    globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      const type = request.headers.get("content-type");
      sent = { url: request.url, method: request.method, type,
        fields: type === "application/json" ? await request.json() : Object.fromEntries(new URLSearchParams(await request.text())) };
      return Response.json(c.reply, { status: c.status ?? 200 });
    };
    const options = { provider: c.provider, secretKey: c.noSecret ? "" : secretKey,
      endpoints: ["/ok"], siteKey: "site-key", siteVerifyURLOverride: c.override,
      minScore: c.minScore, expectedAction: "login", allowedHostnames: ["app.example.org"] };
    const request = new Request("http://app.example.org/mount/ok", {
      headers: { "x-forwarded-for": "203.0.113.4", ...(c.missing ? {} : { "x-captcha-response": "fixture-token" }) } });
    const result = await captcha(options).onRequest(request, {
      options: {basePath: "/mount"}, logger: { error() {}, warn() {} },
    });
    const expected = result ? { status: result.response.status, ...await result.response.json() } : { status: 200 };
    results.push({ ...c, sent, expected });
  }
} finally { globalThis.fetch = originalFetch; }

const path = new URL("../plugins/captcha/testdata/reference.json", import.meta.url);
const text = JSON.stringify(results, null, 2) + "\n";
if (process.argv.includes("--write")) await writeFile(path, text);
else assert.equal(await readFile(path, "utf8"), text);
