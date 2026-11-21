// Create a reader for the preference cookie issued by the Go login plugin.
export function loginPreference({ cookieName, domain } = {}) {
  const name = cookieName ?? ((globalThis.location?.protocol === "https:" ? "__Secure-" : "") + "authn.last_used_login_method");
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) throw new TypeError("Invalid cookie name");
  if (domain !== undefined && !/^\.?[a-z0-9-]+(?:\.[a-z0-9-]+)*$/i.test(domain)) throw new TypeError("Invalid cookie domain");

  function read() {
    const prefix = name + "=";
    for (const cookie of (globalThis.document?.cookie ?? "").split(";")) {
      const pair = cookie.trim();
      if (pair.startsWith(prefix)) {
        const value = pair.slice(prefix.length);
        try { return decodeURIComponent(value); } catch { return value; }
      }
    }
    return null;
  }

  return {
    read,
    is(method) { return read() === method; },
    clear() {
      if (!globalThis.document) return;
      const secure = globalThis.location?.protocol === "https:" || /^__(?:host|secure)-/i.test(name) ? "; Secure" : "";
      const expired = name + "=; Path=/; Max-Age=0";
      document.cookie = expired + secure;
      if (domain && !name.toLowerCase().startsWith("__host-")) {
        document.cookie = expired + "; Domain=" + domain + secure;
      }
    },
  };
}
