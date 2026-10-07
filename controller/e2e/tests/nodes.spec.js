// The Nodes page (index.html, home.js, addnode.js) and the shell it shares (shell.js),
// against a fake controller: serve.sh's controller logs in and serves the pages, and the
// APIs the page reads are answered here (page.route), with documentation addresses
// (RFC 5737), so nothing goes on the network. E2E_SHOTS=<dir> also takes the page and the
// + Add node panel at 375 and 1366 px, light and dark, into that directory.
const path = require("node:path");
const { test, expect } = require("@playwright/test");
const { login } = require("./session");

// Records every CSP violation and uncaught error, as csp.spec.js does.
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

const DNS2 = "192.0.2.53", DNS3 = "192.0.2.54", FOUND = "198.51.100.37", TYPED = "192.0.2.77", NOBODY = "192.0.2.99";
// The interfaces' MACs (/api/nodes "mac", /api/nodes/found "mac"): dns3 runs on DHCP.
const MAC2 = "aa:bb:cc:00:00:05", MAC3 = "aa:bb:cc:00:00:06", MACFOUND = "aa:bb:cc:00:00:3a", MACTYPED = "aa:bb:cc:00:00:7a";

function node(addr, id, name, board, health, extra = {}) {
  return {
    id, addr, hostname: `espdns-${id.slice(-5).replace(":", "")}.local`, source: "settings", online: true,
    last_seen: new Date().toISOString(), polled: new Date().toISOString(), qps: 0.4,
    status: { board, version: "0.0.1", uptime_s: 9660, net: { kind: "ethernet", hostname: `${name}.local` }, health, config: { name, source: "node" } },
    ...extra,
  };
}

// dhcp is n on an address from DHCP (its /status config.address).
function dhcp(n) { n.status.config.address = "dhcp"; return n; }

const series = vs => Array(60 - vs.length).fill(null).concat(vs); // the newest minutes

// fake answers the page's APIs; state.changes is what /api/changes lists, state.posts what
// was sent.
async function fake(page) {
  const state = {
    changes: [{ id: "c1", kind: "lists", summary: "Always allow example.com", effect: "Blocking: compiled again, then sent to the nodes, live (no restart)" }],
    posts: [],
  };
  const json = (route, body, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
  await page.route(/\/api\/nodes$/, r => json(r, [
    node(DNS2, "aa:bb:cc:00:00:02", "dns2", "p4-ip101", { state: "healthy", answering: true, reasons: [] }, { mac: MAC2 }),
    dhcp(node(DNS3, "aa:bb:cc:00:00:03", "dns3", "ws-s3-eth", { state: "degraded", answering: true, reasons: ["zone refresh failing"] }, { qps: 0, mac: MAC3 })),
  ]));
  const found = { host: FOUND, id: "aa:bb:cc:00:00:37", hostname: "espdns-000037.local", source: "mdns", online: true, read: true,
    board: "xiao-s3-sense", version: "0.0.4", net: "wifi", mac: MACFOUND, adopted: false, listed: false, configs: true, config: "dns4.json", next: "adopt" };
  await page.route(/\/api\/nodes\/found$/, r => json(r, { nodes: [found] }));
  await page.route(/\/api\/nodes\/lookup$/, r => {
    const b = r.request().postDataJSON();
    state.posts.push(["lookup", b]);
    if (b.address === TYPED) return json(r, { address: TYPED, found: true, node: { ...found, host: TYPED, id: "aa:bb:cc:00:00:77", source: "lookup", net: "ethernet", mac: MACTYPED, board: "ws-s3-eth" } });
    return json(r, { address: b.address, found: false, answered: false, error: `${b.address}: no answer` });
  });
  await page.route(/\/api\/adopt$/, r => json(r, { nodes: [], configs: [{ name: "dns4.json", config_name: "dns4", address: "198.51.100.40/24", gateway: "198.51.100.1" }],
    primary: {}, key: true, no_dhcp: [], dry_run_valid_s: 900 }));
  await page.route(/\/api\/updates$/, r => json(r, { scheme: "semver", builds: [], available: [DNS2], nodes: [
    { host: DNS2, listed: true, online: true, runs: { version: "0.0.1", build: "a1" }, newest: { version: "0.0.4", build: "b4", source: "builds/p4-ip101" }, state: "available", why: "" },
    { host: DNS3, listed: true, online: true, runs: { version: "0.0.4", build: "b4" }, newest: { version: "0.0.4", build: "b4", source: "builds/ws-s3-eth" }, state: "current", why: "" },
  ] }));
  await page.route(/\/api\/dashboard$/, r => json(r, { window_s: 3600, bin_s: 60, bins: 60, nodes: [], fleet: {
    now: { qps: 0.4 }, hour: { qps: 0.4, servfail: 0, dropped: 0, blocked_share: 0.009, p50_ms: 7 },
    qps: series([0.2, 0.3, 0.2, 0.4, 0.3, 0.5, 0.4, 0.6, 0.5, 0.4]), p95_ms: series([7, 8, 7, 9, 22, 8, 7, 8, 7, 7]),
    blocked_qps: series([0.01, 0, 0.01, 0.01, 0.02, 0.01, 0, 0.01, 0.01, 0.01]) } }));
  await page.route(/\/api\/changes$/, r => json(r, { changes: state.changes, restarts: [], apply: null }));
  await page.route(/\/api\/jobs$/, r => {
    const b = r.request().postDataJSON();
    state.posts.push(["job", b]);
    return json(r, { id: "j1", kind: b.kind, who: "admin", state: "running", created: new Date().toISOString() }, 201);
  });
  await page.route(/\/api\/jobs\/j1\/events/, r => {
    state.changes = [];
    const progress = { changes: ["c1"], steps: [{ name: "check", state: "done" }, { name: "write", state: "done" }, { name: "compile", state: "done" },
      { name: "dry run", state: "done" }, { name: "push", state: "done" }],
    rollouts: [{ kind: "blocklist", what: "Blocklist", order: [DNS3, DNS2], state: "done", nodes: { [DNS3]: { state: "done" }, [DNS2]: { state: "done" } } }] };
    const end = { id: "j1", kind: "apply", who: "admin", state: "done", progress };
    return r.fulfill({ status: 200, contentType: "text/event-stream",
      body: `id: 1\nevent: progress\ndata: ${JSON.stringify(progress)}\n\nid: 2\nevent: end\ndata: ${JSON.stringify(end)}\n\n` });
  });
  return state;
}

test("Nodes: the list renders from the controller's nodes", async ({ page }) => {
  const violations = await watch(page);
  await login(page);
  await fake(page);
  await page.goto("./");
  await expect(page.locator("#sentence")).toHaveText("DNS is answering · dns3 needs attention");
  await expect(page.locator("#sentence-sub")).toContainText("Zone refresh failing");
  const nav = page.locator('nav[aria-label="Main"] a');
  await expect(nav).toHaveText(["Nodes", "Zones", "Blocking", "Query log"]);
  await expect(nav.first()).toHaveAttribute("aria-current", "page");

  const rows = page.locator("#nodes .r:not(.headr)");
  await expect(rows).toHaveCount(3);
  const dns2 = rows.nth(0), dns3 = rows.nth(1), found = rows.nth(2);
  await expect(dns2.locator(".name")).toHaveText("dns2");
  await expect(dns2.locator(".ip")).toHaveText(DNS2);
  await expect(dns2.locator(".led")).toHaveClass(/\bhealthy\b/);
  await expect(dns2).toContainText("Update available: 0.0.1 → 0.0.4");
  await expect(dns2).not.toHaveClass(/r-warn|r-bad/);
  await expect(dns3.locator(".led")).toHaveClass(/\bdegraded\b/);
  await expect(dns3).toHaveClass(/\br-warn\b/);
  await expect(dns3.locator(".led")).toHaveAttribute("title", /two amber blinks/);
  await expect(found).toHaveClass(/\br-new\b/);
  await expect(found).toContainText("New device found");
  await expect(found.locator(".ipc:not(.mac) .ip")).toHaveText(FOUND);
  await expect(dns2.locator(".name")).toHaveAttribute("href", `nodes.html#${encodeURIComponent("aa:bb:cc:00:00:02")}`);

  await expect(page.locator("#facts")).toContainText("2 of 2 nodes answering");
  await expect(page.locator("#update")).toContainText("Firmware 0.0.4 for dns2");
  await expect(page.locator("#minis .spark")).toHaveCount(3);
  await expect(page.locator("#copy-dns")).toHaveAttribute("title", `${DNS2}, ${DNS3}`);
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

test("+ Add node: the found nodes, then an address looked up", async ({ page }) => {
  const violations = await watch(page);
  await login(page);
  const state = await fake(page);
  await page.goto("./");
  await page.getByRole("button", { name: "+ Add node" }).click();
  const box = page.locator("#nq"), list = page.locator("#nqres");
  await expect(box).toBeFocused();
  await expect(list).toContainText("Found on your network");
  await expect(list).toContainText(FOUND);
  await expect(list).toContainText("A new board over USB");

  // Nothing at this address.
  await box.fill(NOBODY);
  await box.press("Enter");
  await expect(list).toContainText("No espDNS node answers there");
  // A node at this one: chosen, with its name and address to give it.
  await box.fill(TYPED);
  await box.press("Enter");
  await expect(list.locator("#nnname")).toHaveValue("dns4.json");
  await expect(list.locator("#nnname option:checked")).toHaveText("dns4"); // the config's name, not its file
  await expect(list.locator("#nnip")).toHaveValue("198.51.100.40/24");
  await expect(list).toContainText(`Found at ${TYPED} over Wired`);
  await expect(list.getByRole("button", { name: "Add node" })).toBeEnabled();
  expect(state.posts.filter(p => p[0] === "lookup").map(p => p[1].address)).toEqual(expect.arrayContaining([NOBODY, TYPED]));

  // A listed node's address is one of the nodes already: not looked up.
  await list.getByRole("button", { name: "Back" }).click();
  const before = state.posts.length;
  await box.fill(DNS2);
  await expect(list).toContainText("Already one of your nodes");
  expect(state.posts.length).toBe(before);

  // Esc closes it.
  await box.fill("");
  await box.press("Escape");
  await expect(page.getByRole("button", { name: "+ Add node" })).toBeVisible();
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

test("+ Add node: a lookup answered after the address was typed over is dropped", async ({ page }) => {
  await login(page);
  await fake(page);
  // The lookup answers late: by then the box holds other text.
  await page.route(/\/api\/nodes\/lookup$/, async r => { await new Promise(res => setTimeout(res, 800)); await r.fallback(); });
  await page.goto("./");
  await page.getByRole("button", { name: "+ Add node" }).click();
  const box = page.locator("#nq"), list = page.locator("#nqres");
  await box.fill(TYPED);
  await box.press("Enter");
  await expect(list).toContainText(`Looking for a node at ${TYPED}`);
  await box.fill("dns");
  await page.waitForTimeout(1500);
  await expect(list.locator("#nnname")).toHaveCount(0);
  await expect(list).toContainText("Type the node's whole address");
});

test("an apply the controller no longer has doesn't stay Applying", async ({ page }) => {
  await login(page);
  await fake(page);
  await page.route(/\/api\/jobs\/j1\/events/, r => r.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: "no such job" }) }));
  await page.goto("./");
  const chip = page.locator(".changes .chip-btn");
  await chip.click();
  await page.getByRole("dialog", { name: "Changes to apply" }).getByRole("button", { name: "Apply 1 change" }).click();
  const d = page.getByRole("dialog");
  await expect(d).toContainText("Apply failed");
  await expect(d).toContainText("no longer has this apply");
  await expect(d.getByRole("button", { name: "Stop after this node" })).toHaveCount(0);
  await d.getByRole("button", { name: "Done" }).click();
  await expect(chip).toHaveText("1 change to apply");
});

test("the pending changes show in the header, and Apply runs them", async ({ page }) => {
  const violations = await watch(page);
  await login(page);
  const state = await fake(page);
  await page.goto("./");
  const chip = page.locator(".changes .chip-btn");
  await expect(chip).toHaveText("1 change to apply");
  await chip.click();
  const drawer = page.getByRole("dialog", { name: "Changes to apply" });
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("Always allow example.com");
  await expect(drawer).toContainText("No restart needed");
  await drawer.getByRole("button", { name: "Apply 1 change" }).click();
  await expect(page.getByRole("dialog")).toContainText("Changes applied");
  await expect(page.getByRole("dialog")).toContainText("dns3");
  const job = state.posts.find(p => p[0] === "job");
  expect(job[1].kind).toBe("apply");
  expect(job[1].params.soak_s).toBe(60);
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(chip).toHaveCount(0);
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

test("a panel closes with its x, Esc and a click outside", async ({ page }) => {
  await login(page);
  await fake(page);
  await page.goto("./");
  const chip = page.locator(".changes .chip-btn");
  for (const how of ["x", "Escape", "outside"]) {
    await chip.click();
    const d = page.getByRole("dialog", { name: "Changes to apply" });
    await expect(d).toBeVisible();
    if (how === "x") await d.getByRole("button", { name: "Close" }).click();
    else if (how === "Escape") await page.keyboard.press("Escape");
    else await page.mouse.click(10, 300);
    await expect(d).toHaveCount(0);
  }
});

// A node's MAC, to copy for a DHCP reservation or a static address: on a found node's row,
// on a listed node's only while it is on DHCP, and in + Add node's view of the node chosen
// or looked up; each copy button puts it on the clipboard.
test("the MAC to copy: found nodes, nodes on DHCP, and + Add node", async ({ page, context }) => {
  const violations = await watch(page);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await login(page);
  await fake(page);
  await page.goto("./");
  const rows = page.locator("#nodes .r:not(.headr)");
  await expect(rows).toHaveCount(3);
  const dns2 = rows.nth(0), dns3 = rows.nth(1), found = rows.nth(2);
  await expect(dns2.locator(".mac")).toHaveCount(0); // a static address: no MAC in its row
  await expect(dns3.locator(".mac .ip")).toHaveText(MAC3);
  await expect(found.locator(".mac .ip")).toHaveText(MACFOUND);
  await expect(found.locator(".mac")).toHaveAttribute("title", /DHCP reservation.*static address/);
  const clip = () => page.evaluate(() => navigator.clipboard.readText());

  // The copy button copies the MAC, and doesn't open the row (no navigation at all).
  const navs = [];
  page.on("framenavigated", f => { if (f === page.mainFrame()) navs.push(f.url()); });
  await found.getByRole("button", { name: `Copy MAC ${MACFOUND}` }).click();
  await expect(page.locator("#toast")).toContainText(`Copied MAC ${MACFOUND}`);
  expect(await clip()).toBe(MACFOUND);
  await dns3.getByRole("button", { name: `Copy MAC ${MAC3}` }).click();
  await expect(page.locator("#toast")).toContainText(`Copied MAC ${MAC3}`);
  expect(await clip()).toBe(MAC3);
  await page.waitForLoadState("networkidle");
  expect(navs).toEqual([]);
  await expect(page).toHaveURL(/\/$|index\.html$/);
  // The address's copy button still copies the address.
  await found.getByRole("button", { name: `Copy ${FOUND}` }).click();
  expect(await clip()).toBe(FOUND);

  // + Add node: the found node chosen, its MAC with the hint.
  await page.getByRole("button", { name: "+ Add node" }).click();
  const list = page.locator("#nqres");
  await list.getByRole("button", { name: "Add" }).click();
  await expect(list.locator("#nnname")).toHaveValue("dns4.json");
  await expect(list.locator(".macl")).toContainText("For a DHCP reservation in your router, or to set a static address.");
  await list.getByRole("button", { name: `Copy MAC ${MACFOUND}` }).click();
  expect(await clip()).toBe(MACFOUND);
  // and one looked up at its address.
  await list.getByRole("button", { name: "Back" }).click();
  await page.locator("#nq").fill(TYPED);
  await page.locator("#nq").press("Enter");
  await expect(list.locator(".macl .mac .ip")).toHaveText(MACTYPED);
  await list.getByRole("button", { name: `Copy MAC ${MACTYPED}` }).click();
  expect(await clip()).toBe(MACTYPED);
  await page.waitForLoadState("networkidle");
  expect(await violations()).toEqual([]);
});

// The screenshots for review (E2E_SHOTS=<dir>): not a check.
const shots = process.env.E2E_SHOTS;
for (const scheme of ["light", "dark"]) {
  for (const width of [375, 1366]) {
    test(`screenshots: ${width} px, ${scheme}`, async ({ page }) => {
      test.skip(!shots, "E2E_SHOTS not set");
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await page.setViewportSize({ width, height: width < 600 ? 812 : 900 });
      await login(page);
      await fake(page);
      await page.goto("./");
      await expect(page.locator("#minis .spark")).toHaveCount(3);
      await page.screenshot({ path: path.join(shots, `nodes-${width}-${scheme}.png`), fullPage: true });
      await page.getByRole("button", { name: "+ Add node" }).click();
      await expect(page.locator("#nqres")).toContainText(FOUND);
      await page.screenshot({ path: path.join(shots, `add-node-${width}-${scheme}.png`), fullPage: true });
      await page.locator("#nqres").getByRole("button", { name: "Add" }).click();
      await expect(page.locator("#nnname")).toHaveValue("dns4.json");
      await page.screenshot({ path: path.join(shots, `add-node-form-${width}-${scheme}.png`), fullPage: true });
      await page.locator("#nq").press("Escape");
      await page.locator(".changes .chip-btn").click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await page.screenshot({ path: path.join(shots, `changes-${width}-${scheme}.png`) });
    });
  }
}
