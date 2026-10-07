// The login (login.html): the form, the countdown after too many failures, and where to go after.
import { session, loggedIn, deviceToken } from "./common.js";

// Where to go after: a page of this controller only. Resolved as the browser will (it
// drops tabs and newlines, so "/\t/elsewhere" is "//elsewhere"), then its origin checked.
const next = (() => {
  const n = new URLSearchParams(location.search).get("next") || "";
  try {
    const u = new URL(n, location.origin);
    if (n.startsWith("/") && u.origin === location.origin) return u.pathname + u.search + u.hash;
  } catch { /* not a URL */ }
  return "index.html";
})();
const $ = id => document.getElementById(id);

const s = await session;
if (s.logged_in) location.replace(next);
if (!s.password_set) $("nopass").hidden = false;
else {
  $("form").hidden = false;
  if (s.error) { $("broken").hidden = false; $("broken").textContent = `The login can't be used: ${s.error}`; }
  // The user name is never filled in by the page (it isn't said before a login); the
  // browser may fill it, and then the password is next.
  ($("user").value ? $("password") : $("user")).focus();
}

let wait = null;
function countdown(secs) {
  clearInterval(wait);
  const end = Date.now() + secs * 1000;
  const tick = () => {
    const left = Math.ceil((end - Date.now()) / 1000);
    if (left <= 0) {
      clearInterval(wait);
      $("submit").disabled = false;
      $("msg").textContent = "Try again.";
      return;
    }
    $("submit").disabled = true;
    $("msg").textContent = `Too many failed logins: try again in ${left} s.`;
  };
  tick();
  wait = setInterval(tick, 250);
}

$("form").addEventListener("submit", async e => {
  e.preventDefault();
  $("msg").className = "status";
  $("msg").textContent = "Checking…";
  $("submit").disabled = true;
  try {
    const headers = { "Content-Type": "application/json" };
    if (deviceToken()) headers["X-Login-Device"] = deviceToken();
    const r = await fetch("api/login", { method: "POST", headers,
      body: JSON.stringify({ user: $("user").value, password: $("password").value }) });
    const j = await r.json().catch(() => ({}));
    if (r.ok) { loggedIn(j); location.replace(next); return; }
    $("msg").className = "status bad";
    if (r.status === 429) { countdown(Number(r.headers.get("Retry-After")) || 1); return; }
    $("msg").textContent = j.error || r.statusText;
    $("password").select();
  } catch (err) {
    $("msg").className = "status bad";
    $("msg").textContent = `Can't reach the controller: ${err.message}`;
  }
  $("submit").disabled = false;
});
