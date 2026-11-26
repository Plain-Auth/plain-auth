import assert from "node:assert/strict";

// One value per line; each line is the evidence for its option.
const colors = {
  background: "rgb(1 0 1)",
  foreground: "rgb(1 0 2)",
  primary: "rgb(1 0 3)",
  primaryForeground: "rgb(1 0 4)",
  mutedForeground: "rgb(1 0 5)",
  border: "rgb(1 0 6)",
  destructive: "rgb(1 0 7)",
  titleBorder: "rgb(1 0 8)",
  titleColor: "rgb(1 0 9)",
  gridColor: "rgb(1 0 10)",
  cardBackground: "rgb(1 0 11)",
  cornerBorder: "rgb(1 0 12)",
};
const size = {
  radiusSm: "0.11rem",
  radiusMd: "0.12rem",
  radiusLg: "0.13rem",
  textSm: "0.14rem",
  text2xl: "0.15rem",
  text4xl: "0.16rem",
  text6xl: "0.17rem",
};
const font = {
  defaultFamily: "'Fixture Sans', serif",
  monoFamily: '"Fixture Mono", monospace',
};
const switches = {
  disableTitleBorder: true,
  disableCornerDecorations: true,
  disableBackgroundGrid: true,
};
const query = "?error=login_failed&error_description=" + encodeURIComponent("Alice & Bob's <b>");

// goTheme maps a reference customization to the Go fixture's ErrorPage. The
// two radii the reference never reads have no Go field.
function goTheme({ colors = {}, size = {}, font = {}, ...rest }) {
  const { radiusMd, radiusLg, ...sizes } = size;
  return { ...colors, ...sizes, ...(font.defaultFamily && { fontFamily: font.defaultFamily }), ...(font.monoFamily && { monoFontFamily: font.monoFamily }), ...rest };
}

const tidy = page => page.replace(/[ \t]+$/gm, "").trimEnd();

// The reference page also links to the upstream site and keeps one HTML
// comment; both are removed before the pages are compared.
function referencePage(body, described) {
  const askAI = /\n {10}<a\n {12}href="https:\/\/[^"]*\?askai=[\s\S]*?<\/a>/;
  assert.match(body, askAI);
  body = body.replace(askAI, "");
  if (!described) {
    const more = / If you're a developer, you can find <a href='https:\/\/[^>]*>more information about the error<\/a>\./;
    assert.match(body, more);
    body = body.replace(more, "");
  }
  return tidy(body.replace(/\n *<!-- Corner decorations -->/, ""));
}

async function page(runtime, path) {
  const response = await runtime.send(new Request(runtime.baseURL + "/api/auth/error" + path));
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /^text\/html/);
  return response.text();
}

export async function compareErrorPage(t, { reference, goFixture }) {
  let themed;
  for (const theme of [
    {}, // the defaults
    { colors, size, font },
    { colors, ...switches },
  ]) {
    const ref = await reference(t, [], { onAPIError: { customizeDefaultErrorPage: theme } });
    const go = await goFixture(t, [], { CONFORMANCE_ERROR_PAGE: JSON.stringify(goTheme(theme)) });
    const goPage = await page(go, query);
    assert.equal(tidy(goPage), referencePage(await page(ref, query), true), JSON.stringify(theme));
    if (!theme.colors) {
      // A code alone gets the default sentence, and its quote is escaped.
      assert.equal(tidy(await page(go, "?error=it's")), referencePage(await page(ref, "?error=it's"), false));
    } else if (theme.size) {
      themed = goPage;
    } else {
      assert.ok(!goPage.includes(colors.titleBorder) && !goPage.includes(colors.gridColor) && !goPage.includes("4px solid var(--corner-border)"));
      assert.ok(goPage.includes("border: 2px solid transparent;"));
    }
  }
  const { radiusMd, radiusLg, ...used } = size;
  for (const value of [...Object.values(colors), ...Object.values(used), ...Object.values(font)]) assert.ok(themed.includes(value), value);
  assert.ok(!themed.includes(radiusMd) && !themed.includes(radiusLg));
}
