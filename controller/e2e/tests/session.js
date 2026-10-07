// The login as the pages have it (internal/auth): through the login page, which keeps the
// session's token in the origin's localStorage; the cookie alone opens no API.
const { expect } = require("@playwright/test");

// login logs in through the login page, and waits for the page it goes to.
async function login(page) {
  await page.goto("login.html");
  await page.locator("#user").fill(process.env.E2E_USER);
  await page.locator("#password").fill(process.env.E2E_PASSWORD);
  await page.locator("#submit").click();
  await expect(page).not.toHaveURL(/login\.html/); // to index.html, which the server answers at /
}

// apiGet reads an API from the page, as common.js's api does: with the session's token.
function apiGet(page, url) {
  return page.evaluate(async url => {
    const r = await fetch(url, { headers: { "X-Session-Token": localStorage.getItem("espdns.session") || "" } });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: r.status, json, text };
  }, url);
}

module.exports = { login, apiGet };
