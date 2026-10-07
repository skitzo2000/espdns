// System (system.html, ⚙ in the top bar): links to the tools that aren't top-level pages,
// the release key and the login, and the zone primary's lists (primary.js).
import { header, el, session, releaseKey } from "./common.js";
import { loadPrimary } from "./primary.js";

header("system.html");

const $ = id => document.getElementById(id);

function fact(t, k, v, cls) {
  const tr = el("tr");
  const td = el("td", cls || "");
  if (v instanceof Node) td.append(v); else td.textContent = v;
  tr.append(el("th", "", k), td);
  t.append(tr);
}

async function keys() {
  const [s, k] = await Promise.all([session, releaseKey()]);
  const t = $("keys");
  t.replaceChildren();
  if (k.present) fact(t, "Release key", `${k.fingerprint} (${k.source || "keys/release.pem"})`, "mono");
  else fact(t, "Release key", k.missing ? "none: the controller only reads nodes until one is imported (espdns key import: docs/getting-started.md, step 7)"
    : `can't be used: ${k.error}`, "warn");
  fact(t, "Login", s.logged_in ? `logged in as ${s.user}` : s.password_set ? "not logged in"
    : "no password set: read-only (espdns passwd: docs/getting-started.md, step 6)", s.password_set || s.logged_in ? "" : "warn");
}

const primary = () => loadPrimary($("primary"), $("primary-sub"));
$("primary-refresh").onclick = primary;

keys();
session.then(s => {
  if (!s.logged_in) {
    $("primary").replaceChildren(el("div", "sub", s.password_set ? "Log in to read the zone primary." : "The zone primary's lists need a login: set a password, then log in."));
    $("primary-refresh").hidden = true;
    return;
  }
  primary();
});
