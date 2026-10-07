// The Backup page: a backup of the data directory downloaded (POST /api/backup, the file
// streamed back), what it holds (GET /api/backup), and how to restore one (the CLI's). A
// download needs the login password again (askPassword: a grant for that one request): a
// backup holds the release key and the Wi-Fi passwords.
import { header, el, getJSON, api, askPassword } from "./common.js";

header("backup.html");

const $ = id => document.getElementById(id);
let minLen = 12;

function size(n) {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KiB`;
  return `${n} bytes`;
}

function banner(text, cls = "bad") {
  const b = $("banner");
  b.replaceChildren();
  if (text) b.append(el("div", `banner ${cls}`, text));
}

async function load() {
  let info;
  try {
    info = await getJSON("api/backup");
  } catch (e) {
    banner(e.message);
    $("go").disabled = true;
    return;
  }
  minLen = info.min_passphrase || minLen;
  $("minlen").textContent = `(at least ${minLen} characters)`;
  $("where").textContent = `${info.data_dir}; backup format ${info.format}.` + (info.lock ? ` The fleet lock is held by ${info.lock}.` : "");
  const tb = $("parts");
  tb.replaceChildren();
  for (const p of info.parts || []) {
    const tr = el("tr");
    const inc = el("td", p.included ? "ok" : "muted", p.included ? "yes" : "no");
    if (p.note) inc.append(el("div", "sub", p.note));
    tr.append(el("td", "mono", p.name), el("td", "", String(p.files)), el("td", "", size(p.bytes)), inc);
    tb.append(tr);
    if (p.name === "firmware") $("fwsize").textContent = `(${size(p.bytes)}: the boards' builds and chip images, made again by make)`;
  }
  if (!(info.parts || []).length) {
    const tr = el("tr"), td = el("td", "empty", "The data directory is empty.");
    td.colSpan = 4;
    tr.append(td);
    tb.append(tr);
  }
}

// The file name the controller gave, from Content-Disposition.
function fileName(r) {
  const m = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "");
  return m ? m[1] : "espdns-backup.age";
}

$("form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const pass = $("pass").value, pass2 = $("pass2").value, recipient = $("recipient").value.trim();
  const status = $("status");
  status.className = "sub";
  banner("");
  if (recipient && (pass || pass2)) { status.textContent = "A passphrase or an age key, not both."; status.className = "sub bad"; return; }
  if (!recipient) {
    if ([...pass].length < minLen) { status.textContent = `The passphrase: at least ${minLen} characters.`; status.className = "sub bad"; return; }
    if (pass !== pass2) { status.textContent = "The two passphrases differ."; status.className = "sub bad"; return; }
  }
  const body = recipient ? { recipient } : { passphrase: pass };
  body.firmware = $("firmware").checked;
  $("go").disabled = true;
  try {
    status.textContent = "Your login password, to download a backup…";
    const grant = await askPassword("A backup holds the release key and the Wi-Fi passwords: enter your login password to download one.");
    if (!grant) { status.textContent = "Not downloaded: the password wasn't given."; return; }
    status.textContent = "Writing the backup (the passphrase is stretched first: a second or two)…";
    const r = await api("api/backup", { method: "POST", headers: { "Content-Type": "application/json", "X-Reauth": grant },
      body: JSON.stringify(body) });
    if (r.status === 401) { location.href = "login.html?next=backup.html"; return; }
    if (!r.ok) {
      let msg = r.statusText;
      try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    const blob = await r.blob();
    const name = fileName(r);
    const a = el("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60_000);
    status.textContent = `Saved ${name}: ${size(blob.size)}, ${r.headers.get("X-Backup-Summary") || ""}. Check it with espdns restore -dry-run.`;
    status.className = "sub ok";
    $("pass").value = $("pass2").value = "";
  } catch (e) {
    status.textContent = e.message;
    status.className = "sub bad";
  } finally {
    $("go").disabled = false;
    load();
  }
});

load();
