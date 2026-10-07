// Every page of the controller under its Content-Security-Policy (internal/websec): it loads
// with no violation and its scripts run, and the builder's flasher (the vendored
// esp-web-tools) loads, opens its dialog on a stubbed Web Serial port and imports every chunk
// it ships, with no hardware.
const fs = require("node:fs");
const path = require("node:path");
const { test, expect } = require("@playwright/test");

const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
// The builder page's (websec.BuilderCSP): style attributes with exactly the two values of
// esp-web-tools' "no port picked" dialog, by hash; nothing else.
const BUILDER_CSP = CSP + "; style-src-attr 'unsafe-hashes' " +
  "'sha256-w68cv7ZL7DW/1c2v0g4i6aPlMi0iRw663JuMxEmNmU4=' 'sha256-2PZQPqAcY6IE7H879XiZ2Hm3cBUNVB41T1m3kjNvN6E='";
const web = path.join(__dirname, "..", "..", "web");
const pages = fs.readdirSync(web).filter(f => f.endsWith(".html")).sort();

// Records every CSP violation, as the page reports it (the event) and as Chromium logs it.
async function watch(page) {
  const seen = [];
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener("securitypolicyviolation",
      e => window.__csp.push(`${e.violatedDirective} blocked ${e.blockedURI || "inline"} (${e.sourceFile}:${e.lineNumber})`));
  });
  page.on("console", m => { if (/Content.Security.Policy/i.test(m.text())) seen.push(m.text()); });
  page.on("pageerror", e => seen.push(`uncaught: ${e.message}`));
  return async () => [...seen, ...await page.evaluate(() => window.__csp)];
}

const { login, apiGet } = require("./session");

// serve.sh's controller lists no node and browses no mDNS (-browse-mdns=false): one found
// here means it went on the network, to the nodes on this LAN.
test("no node is known", async ({ page }) => {
  await login(page);
  await page.waitForTimeout(3000); // a browse answers within a second or two
  const r = await apiGet(page, "api/nodes");
  expect(r.status).toBe(200);
  expect(r.json).toEqual([]);
});

test("the pages are found", () => {
  expect(pages).toContain("index.html");
  expect(pages).toContain("builder.html");
  expect(pages.length).toBeGreaterThan(8);
});

for (const name of pages.filter(p => p !== "login.html")) {
  test(`${name}: no CSP violation, its scripts run`, async ({ page }) => {
    const violations = await watch(page);
    await login(page);
    const r = await page.goto(name);
    expect(r.status()).toBe(200);
    expect(r.headers()["content-security-policy"]).toBe(name === "builder.html" ? BUILDER_CSP : CSP);
    expect(r.headers()["x-frame-options"]).toBe("DENY");
    // common.js's header() draws the top bar: the page's module ran.
    await expect(page.locator('nav[aria-label="Main"]')).toBeVisible();
    await page.waitForLoadState("networkidle");
    expect(await violations()).toEqual([]);
  });
}

test("login.html logged out: no CSP violation, the form shown", async ({ page }) => {
  const violations = await watch(page);
  const r = await page.goto("login.html");
  expect(r.headers()["content-security-policy"]).toBe(CSP);
  await expect(page.locator("#form")).toBeVisible();
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

test("a page logged out: redirected to the login, with the headers", async ({ page }) => {
  const violations = await watch(page);
  const seen = [];
  page.on("response", r => seen.push(r));
  await page.goto("index.html");
  await expect(page).toHaveURL(/login\.html/);
  const redirect = seen.find(r => r.status() === 303);
  expect(redirect, "the 303").toBeTruthy();
  expect(redirect.headers()["content-security-policy"]).toBe(CSP);
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

// A Web Serial port that opens and never answers: enough for esp-web-tools to open its
// dialog and try to reach the chip.
function stubSerial() {
  const port = {
    readable: new ReadableStream({ pull() { return new Promise(() => {}); } }),
    writable: new WritableStream({ write() {} }),
    async open() {}, async close() {}, async setSignals() {}, async forget() {},
    getInfo() { return { usbVendorId: 0x303a, usbProductId: 0x1001 }; },
    addEventListener() {}, removeEventListener() {},
  };
  const serial = {
    async requestPort() { return port; }, async getPorts() { return [port]; },
    addEventListener() {}, removeEventListener() {},
  };
  Object.defineProperty(Navigator.prototype, "serial", { configurable: true, get: () => serial });
}

test("builder.html: the flasher loads, opens on a stubbed port, every chunk imports", async ({ page }) => {
  const violations = await watch(page);
  await page.addInitScript(stubSerial);
  await login(page);
  await page.goto("builder.html");
  await page.waitForFunction(() => customElements.get("esp-web-install-button") !== undefined);

  // The button as builder.js makes it for a prepared image; its activate slot opens the dialog.
  await page.evaluate(() => {
    const b = document.createElement("esp-web-install-button");
    b.id = "e2e-install";
    b.setAttribute("manifest", "build/e2e/manifest.json");
    const act = document.createElement("button");
    act.slot = "activate";
    act.textContent = "Install over USB";
    b.append(act);
    document.querySelector("main").append(b);
  });
  await page.getByRole("button", { name: "Install over USB" }).click();
  await page.waitForFunction(() => customElements.get("ewt-install-dialog") !== undefined &&
    document.querySelector("ewt-install-dialog") !== null);

  // Every chunk the vendored copy ships (its SHA256SUMS), imported under the CSP.
  const sums = await (await page.request.get("vendor/esp-web-tools/SHA256SUMS")).text();
  const chunks = sums.trim().split("\n").map(l => l.split(/\s+/)[1]).filter(f => f.endsWith(".js"));
  expect(chunks.length).toBeGreaterThan(20);
  const failed = await page.evaluate(async chunks => {
    const out = [];
    for (const c of chunks) {
      try { await import(`./vendor/esp-web-tools/${c}`); } catch (e) { out.push(`${c}: ${e.message}`); }
    }
    return out;
  }, chunks);
  expect(failed).toEqual([]);
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

// The port picker cancelled (requestPort rejects with NotFoundError, as Chromium does): the
// install button opens esp-web-tools' "no port picked" dialog, whose icon has the two style
// attributes BUILDER_CSP allows by hash.
test("builder.html: the port picker cancelled, the no-port dialog shows, no CSP violation", async ({ page }) => {
  const violations = await watch(page);
  await page.addInitScript(() => {
    const serial = {
      async requestPort() { throw new DOMException("No port selected by the user.", "NotFoundError"); },
      async getPorts() { return []; },
      addEventListener() {}, removeEventListener() {},
    };
    Object.defineProperty(Navigator.prototype, "serial", { configurable: true, get: () => serial });
  });
  await login(page);
  const r = await page.goto("builder.html");
  expect(r.headers()["content-security-policy"]).toBe(BUILDER_CSP);
  await page.waitForFunction(() => customElements.get("esp-web-install-button") !== undefined);
  await page.evaluate(() => {
    const b = document.createElement("esp-web-install-button");
    b.setAttribute("manifest", "build/e2e/manifest.json");
    const act = document.createElement("button");
    act.slot = "activate";
    act.textContent = "Install over USB";
    b.append(act);
    document.querySelector("main").append(b);
  });
  await page.getByRole("button", { name: "Install over USB" }).click();
  const dialog = page.locator("ewt-no-port-picked-dialog");
  await expect(dialog.getByText("Try Again")).toBeVisible();
  // Its icon, with the two style attributes, was drawn.
  expect(await page.evaluate(() =>
    document.querySelector("ewt-no-port-picked-dialog").shadowRoot.querySelectorAll("svg[style]").length)).toBeGreaterThan(0);
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

test("a page can't be framed", async ({ page }) => {
  const violations = await watch(page);
  await login(page);
  // A frame of the dashboard in a page of its own origin: frame-ancestors 'none' refuses even that.
  await page.goto("jobs.html");
  const loaded = await page.evaluate(() => new Promise(resolve => {
    const f = document.createElement("iframe");
    f.src = "index.html";
    f.addEventListener("load", () => {
      try { resolve(f.contentDocument !== null && f.contentDocument.querySelector("main") !== null); }
      catch { resolve(false); }
    });
    document.body.append(f);
  }));
  expect(loaded).toBe(false);
  expect((await violations()).some(v => /frame-ancestors/.test(v))).toBeTruthy();
});
