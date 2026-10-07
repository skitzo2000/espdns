// The session's two halves (internal/auth, #67), the password asked again (#68) for a
// backup and for a config's Wi-Fi password, and the login's backoff per client, in the
// browser: the pages keep the session's token in localStorage and send it with every API
// request (common.js api), a job's events come through with it (common.js events), and the
// Backup and Configs pages ask for the password in a dialog (common.js askPassword).
const { test, expect } = require("@playwright/test");
const { login, apiGet } = require("./session");

const port = process.env.E2E_PORT;
const cookieName = `espdns_session_${port}`;

test("the cookie is named for the port; alone it opens no API", async ({ page, context }) => {
  await login(page);
  const cookies = await context.cookies();
  expect(cookies.map(c => c.name)).toContain(cookieName);
  const c = cookies.find(x => x.name === cookieName);
  expect(c.httpOnly).toBe(true);
  expect(c.sameSite).toBe("Strict");
  // What another port of this host gets: the cookie, not the page's localStorage.
  for (const url of ["api/nodes", "api/configs", "api/backup", "api/key"]) {
    const r = await page.request.get(url);
    expect(r.status(), url).toBe(401);
  }
  const s = await (await page.request.get("api/session")).json();
  expect(s.logged_in).toBe(false);
  expect(s.token).toBeUndefined();
  const r = await page.request.post("api/jobs", { data: { kind: "check" } });
  expect(r.status()).toBe(401);
  // The page, with its token.
  expect((await apiGet(page, "api/nodes")).status).toBe(200);
  expect((await apiGet(page, "api/session")).json.logged_in).toBe(true);
});

test("a cookie planted by another port doesn't hide the session", async ({ page, context }) => {
  await login(page);
  // A narrower Path is sent first: the controller tries every cookie of its name.
  await context.addCookies([{ name: cookieName, value: "planted", domain: "127.0.0.1", path: "/api", httpOnly: false, sameSite: "Strict" }]);
  await page.goto("jobs.html");
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
  expect((await apiGet(page, "api/nodes")).status).toBe(200);
});

test("a job's events come through with the token", async ({ page }) => {
  await login(page);
  await page.goto("jobs.html");
  await page.locator("#check").click();
  await expect(page.locator("#job")).toBeVisible();
  await expect(page.locator("#job-state")).toHaveText(/^(done|failed)$/, { timeout: 30000 });
  await expect(page.locator("#log")).not.toBeEmpty();
});

async function startBackup(page) {
  await page.goto("backup.html");
  await page.locator("#pass").fill("an e2e backup passphrase");
  await page.locator("#pass2").fill("an e2e backup passphrase");
  await page.locator("#go").click();
  const d = page.locator("dialog.reauth");
  await expect(d).toBeVisible();
  return d;
}

test("a backup asks for the password again", async ({ page }) => {
  await login(page);
  // Cancelled: nothing downloaded.
  let d = await startBackup(page);
  await d.getByRole("button", { name: "Cancel" }).click();
  await expect(d).toHaveCount(0);
  await expect(page.locator("#status")).toHaveText(/Not downloaded/);
  // A wrong password, then the right one.
  d = await startBackup(page);
  await d.locator("input[type=password]").fill("not the password");
  await d.getByRole("button", { name: "Continue" }).click();
  await expect(d.locator("[role=status]")).toHaveText(/wrong password/);
  await d.locator("input[type=password]").fill(process.env.E2E_PASSWORD);
  const download = page.waitForEvent("download");
  await d.getByRole("button", { name: "Continue" }).click();
  expect((await download).suggestedFilename()).toMatch(/^espdns-backup-\d{8}-\d{6}\.age$/);
  await expect(page.locator("#status")).toHaveText(/^Saved espdns-backup-/);
  // The API without a grant: refused, asking for it.
  const r = await page.evaluate(async () => {
    const r = await fetch("api/backup", { method: "POST", body: JSON.stringify({ passphrase: "an e2e backup passphrase" }),
      headers: { "Content-Type": "application/json", "X-Session-Token": localStorage.getItem("espdns.session") } });
    return { status: r.status, json: await r.json() };
  });
  expect(r.status).toBe(403);
  expect(r.json.reauth).toBe(true);
});

test("a config's Wi-Fi password is shown only with the password again", async ({ page }) => {
  await login(page);
  const text = '{\n  "name": "e2e-wifi",\n  "wifi": { "ssid": "e2e", "password": "an e2e wifi secret" }\n}\n';
  const saved = await page.evaluate(async text => {
    const r = await fetch("api/configs/e2e-wifi.json", { method: "POST", body: JSON.stringify({ text, hash: "" }),
      headers: { "Content-Type": "application/json", "X-Session-Token": localStorage.getItem("espdns.session") } });
    return { status: r.status, body: await r.text() };
  }, text);
  expect(saved.status, saved.body).toBeLessThan(300);
  // The API without a grant: refused, the password not in the reply.
  const bare = await apiGet(page, "api/configs/e2e-wifi.json?reveal=1");
  expect(bare.status).toBe(403);
  expect(bare.json.reauth).toBe(true);
  expect(bare.text).not.toContain("an e2e wifi secret");
  // The page: Show asks for the password; cancelled, the text keeps its stand-in.
  await page.goto("configs.html#config=e2e-wifi.json");
  const show = page.getByRole("button", { name: "Show the Wi-Fi password" });
  await show.click();
  const d = page.locator("dialog.reauth");
  await expect(d).toBeVisible();
  await d.getByRole("button", { name: "Cancel" }).click();
  await expect(d).toHaveCount(0);
  await expect(page.locator("#text")).not.toHaveValue(/an e2e wifi secret/);
  // Given: the text has the password.
  await show.click();
  await d.locator("input[type=password]").fill(process.env.E2E_PASSWORD);
  await d.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator("#text")).toHaveValue(/an e2e wifi secret/);
});

test("three wrong passwords end the session", async ({ page }) => {
  await login(page);
  const d = await startBackup(page);
  for (let i = 0; i < 2; i++) {
    await d.locator("input[type=password]").fill(`wrong ${i}`);
    await d.getByRole("button", { name: "Continue" }).click();
    await expect(d.locator("[role=status]")).toHaveText(/wrong password/);
  }
  await d.locator("input[type=password]").fill("wrong 2");
  await d.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/login\.html/);
  expect((await apiGet(page, "api/session")).json.logged_in).toBe(false);
});

// Last: it backs off this address for a while (the end waits it out and logs in from the
// address, which starts its count over for whatever runs after).
test("failed logins elsewhere don't lock out a browser that logged in before", async ({ page, browser }) => {
  await login(page); // this browser's device token, kept in its localStorage
  await page.getByRole("button", { name: /^Account: / }).click(); // the home page's account panel
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/login\.html/);
  // Another client, with no device token: backed off.
  const other = await browser.newContext({ baseURL: `http://127.0.0.1:${port}/` });
  let last;
  for (let i = 0; i < 4; i++) {
    last = await other.request.post("api/login", { data: { user: process.env.E2E_USER, password: "not the password" } });
  }
  expect(last.status()).toBe(429);
  // This browser: still logs in.
  await login(page);
  // The other client waits, then its login starts its count over.
  await new Promise(r => setTimeout(r, 1000 * Number(last.headers()["retry-after"] || 1)));
  const ok = await other.request.post("api/login", { data: { user: process.env.E2E_USER, password: process.env.E2E_PASSWORD } });
  expect(ok.status()).toBe(200);
  await other.close();
});
