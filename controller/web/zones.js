// The zone editor (zones.html): the hosted zones' master files in the data directory, each
// edited as text with its records beside it. Every check is the controller's (POST
// /api/zones/<name>/check: espdns zones -check, the same code, then the set each node would
// get, against its limit and its secondary and forward zones): nothing is checked here. A
// push is the Push page's: this page opens it with the zones chosen. A node's zones go back
// to the older bundle it keeps with the job "revert" (as espdns revert -kind zones). Zone
// text and what the nodes report are shown as text only.
import { header, el, post, getJSON, session, confirmDialog, nodeLabel, nodeText, events } from "./common.js";

header("zones.html");

const SERVES = {
  file: ["ok", "serves it"],
  other: ["warn", "another version"],
  unrecorded: ["warn", "not recorded here"],
};

let sess = {};
let list = { zones: [], nodes: [], deleted: [] };
let cur = null;     // {name, text, hash, modified, history, isNew}
let result = null;  // the last check
let checking = 0;   // the check in flight (only the newest is shown)
let pick = null;    // the zones chosen for the push: a Set of file names
let opening = 0;    // the zone being opened (only the newest is shown)
const acts = {};    // a node's last revert: host -> {text, cls}

const $ = id => document.getElementById(id);
const arr = v => Array.isArray(v) ? v : [];
const obj = v => v && typeof v === "object" && !Array.isArray(v) ? v : {};

function facts(rows) {
  const t = el("table", "facts");
  for (const [k, v, cls] of rows) {
    const tr = el("tr");
    tr.append(el("th", "", k));
    const td = el("td", cls || "");
    if (v instanceof Node) td.append(v); else td.textContent = v;
    tr.append(td);
    t.append(tr);
  }
  return t;
}

function section(title, ...children) {
  const s = el("div", "sect");
  s.append(el("h3", "", title), ...children.filter(Boolean));
  return s;
}

function chip(text, cls, title) {
  const c = el("span", `chip ${cls || ""}`, text);
  if (title) c.title = title;
  return c;
}

function kb(n) { return typeof n === "number" ? `${Math.ceil(n / 1024)} KB` : "–"; }

function bar(used, total, label) {
  const w = el("div", "barwrap");
  const b = el("div", "bar"), f = el("div", "fill");
  f.style.width = `${total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0}%`;
  if (used > total) f.classList.add("high");
  b.append(f);
  w.append(b, el("span", "sub", label));
  return w;
}

function rowOf(cells, tag = "td") {
  const tr = el("tr");
  for (const c of cells) {
    const td = el(tag);
    if (c instanceof Node) td.append(c); else td.textContent = c;
    tr.append(td);
  }
  return tr;
}
function scrollOf(t) { const d = el("div", "scroll"); d.append(t); return d; }

// ---- the list -------------------------------------------------------------------------

function renderList() {
  const box = $("list");
  if (!list.zones.length) {
    box.replaceChildren(el("div", "empty", "No zone files yet: create one below."));
  } else {
    box.replaceChildren(...list.zones.map(z => {
      const b = el("button", "boardrow" + (cur && cur.name === z.name ? " on" : ""));
      b.type = "button";
      const top = el("div", "top");
      top.append(el("strong", "", z.zone), z.error ? el("span", "pill bad", "invalid") : el("span", "sub", `serial ${z.serial}`));
      b.append(top);
      b.append(el("span", "sub", z.error ? z.name : `${z.records} records · ${kb(z.mem)} in memory · ${z.name}`));
      const chips = el("div", "chips");
      for (const n of arr(z.nodes)) {
        const [cls, text] = SERVES[n.state] || ["muted", "?"];
        chips.append(chip(`${nodeText(n.host)}: ${text}`, cls, n.text));
      }
      if (!arr(z.nodes).length) chips.append(chip("no node serves it", "info"));
      b.append(chips);
      b.onclick = () => open(z.name);
      return b;
    }));
  }
  renderNodes();
  renderDeleted();
}

// The nodes and their hosted zones, as /status says.
function renderNodes() {
  const box = $("nodesbox");
  const ns = list.nodes.filter(n => n.listed || n.hosted);
  box.hidden = !ns.length;
  if (!ns.length) return;
  const out = [el("strong", "", "Nodes")];
  for (const n of ns) {
    const d = el("div", "");
    const h = obj(n.hosted);
    const top = el("div", "zhead");
    top.append(nodeLabel(n.host), el("span", `pill ${!n.online ? "bad" : h.state === "on" ? "" : h.state === "off" || !n.hosted ? "muted" : "warn"}`,
      !n.online ? "offline" : !n.read ? "no /status yet" : !n.hosted ? "no hosted zones (old firmware)" : h.state === "on" && !arr(h.zones).length ? "hosted on, serving none" : `hosted ${h.state || "?"}`));
    d.append(top);
    if (n.hosted) {
      d.append(bar(h.bytes || 0, h.limit_bytes || 0, `${kb(h.bytes || 0)} of ${kb(h.limit_bytes || 0)} · ${arr(h.zones).length} zones · seq ${h.seq}${typeof h.slot === "number" && h.slot >= 0 ? ` · slot ${h.slot}` : ""}`));
      if (h.reverted_from > 0) d.append(el("div", "sub warn", `reverted from seq ${h.reverted_from}`));
      if (h.fallback) d.append(el("div", "sub warn", `older copy: ${h.fallback}`));
      if (h.error) d.append(el("div", "sub bad", h.error));
      if (arr(n.unfiled).length) d.append(el("div", "sub warn", `serves ${n.unfiled.join(", ")}, with no file here: a push from here drops it`));
      if (n.pushed) d.append(el("div", "sub", `the set pushed ${new Date(n.pushed.time).toLocaleString()} (by ${n.pushed.by})`));
    }
    if (arr(n.secondary).length) d.append(el("div", "sub", `secondary: ${n.secondary.join(", ")}`));
    if (!n.listed) d.append(el("div", "sub", "not in settings.json: not pushed to"));
    else if (n.hosted && n.online) {
      const r = el("button", "btn quiet small", "Revert zones…");
      r.type = "button";
      r.onclick = () => revert(n);
      if (h.state !== "on") { r.disabled = true; r.title = "no zones in use: nothing to revert from"; }
      d.append(r);
    }
    const a = acts[n.host];
    if (a) d.append(el("div", `act ${a.cls}`, a.text));
    out.push(d);
  }
  box.replaceChildren(...out);
}

// revert sends a node's hosted zones back to the older bundle it keeps (the job "revert"),
// followed here; the node refuses it when it keeps nothing older and says why.
async function revert(n) {
  const h = obj(n.hosted);
  const ok = await confirmDialog(`Revert the hosted zones on ${nodeText(n.host)}?`, [
    `It goes back to the older bundle it keeps in its other slot, live. It runs seq ${h.seq} now.`,
    "The node refuses it when it keeps nothing older (none pushed before, or the one it reverted from), and says why. It keeps to the older bundle until a newer one is pushed.",
  ], "Revert", "btn danger");
  if (!ok) return;
  const what = "revert the zones";
  const show = (text, cls) => { acts[n.host] = { text, cls }; renderNodes(); };
  show(`${what}: starting…`, "muted");
  try {
    const j = await post("api/jobs", { kind: "revert", params: { node: n.host, list: "zones" } });
    show(`${what}: ${j.state}…`, "muted");
    const es = events(`api/jobs/${encodeURIComponent(j.id)}/events`);
    es.addEventListener("end", e => {
      es.close();
      const end = JSON.parse(e.data);
      const reply = String(obj(end.result).reply || "").trim();
      if (end.state === "done") show(`${what}: done${reply ? ` (${reply})` : ""}. The node's row updates with its next /status.`, "");
      else show(`${what}: ${end.state}: ${end.error || ""}`, "bad");
      setTimeout(loadList, 1500);
      setTimeout(loadList, 11000);
    });
  } catch (e) {
    show(`${what}: not started: ${e.message}`, "bad");
  }
}

function renderDeleted() {
  const box = $("deleted");
  box.hidden = !arr(list.deleted).length;
  if (box.hidden) return;
  const out = [el("strong", "", "Deleted (kept in the history)")];
  for (const v of list.deleted) {
    const name = v.file.slice(0, v.file.lastIndexOf(".", v.file.lastIndexOf(".") - 1));
    const row = el("div", "row tight");
    const b = el("button", "btn quiet small", "Restore…");
    b.type = "button";
    b.onclick = () => restore(name, v.file);
    row.append(el("span", "mono", name), el("span", "sub", new Date(v.time).toLocaleString()), b);
    out.push(row);
  }
  box.replaceChildren(...out);
}

async function loadList() {
  try {
    list = await getJSON("api/zones");
  } catch (e) {
    $("list").replaceChildren(el("div", "empty bad", e.message));
    return;
  }
  renderList();
  renderPush();
}

// ---- one zone -------------------------------------------------------------------------

const dirty = () => cur && $("text") && $("text").value !== cur.text;

async function leave() {
  return !(cur && dirty()) || confirmDialog(`Leave ${cur.name}?`, ["Its edits aren't saved: they are dropped."], "Drop the edits");
}

async function open(name, opts = {}) {
  if (!opts.force && !await leave()) return;
  const n = ++opening;
  try {
    const z = await getJSON(`api/zones/${encodeURIComponent(name)}`);
    if (n !== opening) return; // another zone opened (or a new one started) meanwhile
    cur = { ...z, isNew: false };
  } catch (e) {
    $("main").replaceChildren(el("div", "banner bad", e.message));
    return;
  }
  history.replaceState(null, "", `#zone=${encodeURIComponent(name)}`);
  result = null;
  pick = null;
  renderMain();
  renderList();
  check();
}

function edit(name, text, note) {
  opening++;
  cur ={ name, text, hash: "", history: [], isNew: true, note };
  history.replaceState(null, "", `#zone=${encodeURIComponent(name)}`);
  result = null;
  pick = null;
  renderMain();
  renderList();
  check();
}

async function restore(name, file) {
  if (!await leave()) return;
  if (list.zones.some(z => z.name === name)) { open(name, { force: true }); return; }
  try {
    const v = await getJSON(`api/zones/${encodeURIComponent(name)}?version=${encodeURIComponent(file)}`);
    edit(name, v.text, `Restored from the history (${file}): save it to have it back.`);
  } catch (e) { await confirmDialog("Not restored", [e.message], "OK", "btn"); }
}

function renderMain() {
  const m = $("main");
  if (!cur) { m.replaceChildren(el("div", "empty", "Choose a zone.")); return; }
  const head = el("div", "row");
  head.append(el("h2", "", cur.name));
  if (cur.isNew) head.append(el("span", "pill warn", "new, not saved"));
  else head.append(el("span", "sub", `saved ${new Date(cur.modified).toLocaleString()}`));
  const unsaved = el("span", "pill warn", "unsaved edits");
  unsaved.id = "unsaved";
  unsaved.hidden = true;
  head.append(unsaved);

  const ta = el("textarea", "cfgtext");
  ta.id = "text";
  ta.spellcheck = false;
  ta.value = cur.text;
  ta.setAttribute("aria-label", `${cur.name}, master file`);
  ta.rows = Math.min(40, Math.max(16, cur.text.split("\n").length + 2));
  let timer = 0;
  ta.addEventListener("input", () => {
    $("unsaved").hidden = !dirty();
    renderPush();
    clearTimeout(timer);
    timer = setTimeout(check, 600);
  });

  const btn = (text, cls, f, id) => { const b = el("button", cls, text); b.type = "button"; b.onclick = f; if (id) b.id = id; return b; };
  const bar_ = el("div", "acts");
  bar_.append(btn("Check", "btn", check), btn("Bump serial", "btn quiet", bump, "bump"), btn(cur.isNew ? "Create…" : "Save…", "btn primary", saveDialog, "save"));
  if (!cur.isNew) bar_.append(btn("Revert", "btn quiet", () => open(cur.name, { force: true })), btn("Delete…", "btn quiet", deleteDialog));

  const notes = el("div", "sub");
  if (cur.note) notes.append(cur.note, " ");
  if (arr(cur.history).length) notes.append(`${cur.history.length} earlier version(s) kept in zones/.history/ (the newest ${new Date(cur.history[0].time).toLocaleString()}).`);

  const out = el("div", "cfgresult");
  out.id = "result";
  const pushBox = el("div");
  pushBox.id = "push";
  m.replaceChildren(head, bar_, notes, el("div", "cfgedit"), pushBox);
  m.querySelector(".cfgedit").append(ta, out);
  renderResult();
  renderPush();
}

// ---- the check ------------------------------------------------------------------------

async function check() {
  if (!cur) return;
  const n = ++checking;
  try {
    const r = await post(`api/zones/${encodeURIComponent(cur.name)}/check`, { text: $("text").value });
    if (n !== checking) return;
    result = r;
  } catch (e) {
    if (n !== checking) return;
    result = { ok: false, error: e.message, request: true };
  }
  renderResult();
  renderPush();
}

function renderResult() {
  const box = $("result");
  if (!box) return;
  const r = result;
  if (!r) { box.replaceChildren(el("div", "empty", "Checking…")); return; }
  const out = [];
  const refused = arr(r.nodes).filter(n => n.refused && n.listed);
  if (r.error) out.push(el("div", "banner bad", r.request ? r.error : `Refused: ${r.error}`));
  else if (r.ok) out.push(el("div", "banner ok", `Passes: ${r.records} records, serial ${r.serial}${arr(r.nodes).length ? ", and every node in settings.json takes it" : ""}.`));
  else out.push(el("div", "banner bad", `Passes alone, but ${refused.map(n => nodeText(n.host)).join(", ")} would refuse it: see below.`));
  if (r.serial_warn) {
    const w = el("div", "banner warn");
    w.append(r.serial_warn + ". ");
    const b = el("button", "btn small", `Bump to ${r.next_serial}`);
    b.type = "button";
    b.onclick = bump;
    w.append(b);
    out.push(w);
  }
  // espdns zones -check, as the CLI says it.
  if (!r.request) {
    const cli = el("pre", "raw");
    cli.textContent = `$ ${r.command}\n${arr(r.lines).join("\n")}${r.error ? (arr(r.lines).length ? "\n" : "") + "espdns: " + r.error : ""}`;
    out.push(section("espdns zones -check", cli));
  }
  const sects = el("div", "sects one");
  if (arr(r.nodes).length) sects.append(section("Against each node", nodeTable(r)));
  if (arr(r.list).length) {
    const t = el("table", "mini zrec");
    t.append(rowOf(["Name", "Type", "TTL", "Data"], "th"));
    for (const rec of r.list) t.append(rowOf([rec.owner, rec.type, String(rec.ttl), rec.data]));
    const d = el("details");
    d.open = r.records <= 40;
    d.append(el("summary", "", `Records (${r.records}, as the node gets them: names lowercased, duplicates dropped)`), scrollOf(t));
    if (r.more) d.append(el("p", "sub", `… and ${r.more} more.`));
    sects.append(d);
  }
  out.push(sects);
  if (arr(r.diff).length) out.push(diffView(r.diff, "Changes against the saved file"));
  else if (cur && !cur.isNew && !r.request) out.push(el("p", "sub", "Same as the saved file."));
  box.replaceChildren(...out);
}

function nodeTable(r) {
  const t = el("table", "mini ztab");
  t.append(rowOf(["Node", "Serves", "The set from here", "Memory", ""], "th"));
  for (const n of arr(r.nodes)) {
    const who = nodeLabel(n.host);
    if (!n.listed) who.append(el("div", "sub", "not in settings.json"));
    const set = el("div");
    set.append(el("div", "", `${arr(n.set).length} zone(s)`));
    set.title = arr(n.set).join(", ");
    if (arr(n.missing).length) set.append(el("div", "sub warn", `left out (no file here): ${n.missing.join(", ")}`));
    if (arr(n.secondary).length) set.append(el("div", "sub", `its secondary zones: ${n.secondary.join(", ")}`));
    const mem = n.limit_kb ? bar(n.mem, n.limit_kb * 1024, `${kb(n.mem)} of ${n.limit_kb} KB`) : el("span", "sub", "–");
    const verdict = n.refused ? el("div", "bad", n.refused) : el("div", "ok", `takes it: ${n.bytes} bytes`);
    if (n.config) verdict.title = `its config: ${n.config}`;
    t.append(rowOf([who, n.serves ? `serial ${n.serial}` : "no", set, mem, verdict]));
  }
  return scrollOf(t);
}

function diffView(lines, title) {
  const wrap = el("div", "diffwrap");
  wrap.append(el("h3", "", title));
  const pre = el("pre", "diff");
  for (const l of arr(lines)) pre.append(el("div", l.op === "+" ? "add" : l.op === "-" ? "del" : "same", `${l.op} ${l.text}`));
  wrap.append(pre);
  return wrap;
}

// ---- the serial, save, delete -----------------------------------------------------------

async function bump() {
  if (!cur) return;
  try {
    const r = await post(`api/zones/${encodeURIComponent(cur.name)}/serial`, { text: $("text").value });
    $("text").value = r.text;
    $("unsaved").hidden = !dirty();
    check();
  } catch (e) { await confirmDialog("Serial not changed", [e.message], "OK", "btn"); }
}

async function saveDialog() {
  await check();
  const r = result || {};
  if (r.error) { await confirmDialog("Not saved", [`The zone doesn't pass espdns zones -check: ${r.error}`], "OK", "btn"); return; }
  if (!cur.isNew && !arr(r.diff).length) { await confirmDialog("Nothing to save", ["The text is the same as the saved file."], "OK", "btn"); return; }
  const lines = [];
  if (!r.ok) lines.push(el("p", "bad", "It passes alone, but not for every node: it can be saved; a push to those nodes is refused until it does."));
  if (r.serial_warn) lines.push(el("p", "warn", `${r.serial_warn}.`));
  if (arr(r.diff).length) lines.push(diffView(r.diff, "What changes in the file"));
  else lines.push(`A new file, ${cur.name}.`);
  lines.push("The version before is kept in zones/.history/. Saving doesn't push it.");
  if (!await confirmDialog(`Save ${cur.name}?`, lines, "Save", "btn primary")) return;
  try {
    await post(`api/zones/${encodeURIComponent(cur.name)}`, { text: $("text").value, hash: cur.isNew ? "" : cur.hash });
    await loadList();
    await open(cur.name, { force: true });
  } catch (e) { await confirmDialog("Not saved", [e.message], "OK", "btn"); }
}

async function deleteDialog() {
  const z = list.zones.find(x => x.name === cur.name);
  const serving = arr(z && z.nodes).map(n => n.host);
  const lines = [`${cur.name} is removed from ${list.dir}; it is kept in zones/.history/, where Restore has it back.`];
  if (serving.length) lines.push(el("p", "warn", `${serving.join(", ")} still serve ${z.zone} until a push of the zones without it (the Push page, kind zones).`));
  if (dirty()) lines.push("The edits not saved are dropped.");
  if (!await confirmDialog(`Delete ${cur.name}?`, lines, "Delete")) return;
  try {
    await post(`api/zones/${encodeURIComponent(cur.name)}/delete`, { hash: cur.hash });
    cur = null;
    history.replaceState(null, "", "#");
    await loadList();
    renderMain();
  } catch (e) { await confirmDialog("Not deleted", [e.message], "OK", "btn"); }
}

// ---- the push: the Push page, with the zones chosen ----------------------------------------

// The zones the listed nodes serve that have files here: a push replaces each node's set, so
// they are chosen too unless left out.
function served() {
  const out = new Set();
  for (const z of list.zones) if (arr(z.nodes).some(n => list.nodes.some(x => x.host === n.host && x.listed))) out.add(z.name);
  return out;
}

function renderPush() {
  const box = $("push");
  if (!box || !cur) return;
  const s = el("div", "sect pushsect");
  s.append(el("h3", "", "Push the zones"));
  let why = "";
  if (cur.isNew) why = "Save it first: a push sends the saved files.";
  else if (dirty()) why = "Save the edits first: a push sends the saved files.";
  if (!pick) pick = new Set([...served(), cur.isNew ? null : cur.name].filter(Boolean));
  s.append(el("p", "sub", "A push replaces each node's hosted zones with the set chosen: every zone it should serve. The Push page opens with these chosen, for a dry run first, then the rollout, one node at a time."));
  const t = el("table", "mini pickt");
  t.append(rowOf(["", "Zone", "Serial", "Served by"], "th"));
  for (const z of list.zones) {
    const cb = el("input");
    cb.type = "checkbox";
    cb.checked = pick.has(z.name);
    cb.disabled = !!z.error;
    cb.setAttribute("aria-label", `push ${z.name}`);
    cb.onchange = () => { cb.checked ? pick.add(z.name) : pick.delete(z.name); renderPush(); };
    t.append(rowOf([cb, z.name, z.error ? "invalid" : String(z.serial), arr(z.nodes).map(n => nodeText(n.host)).join(", ") || "–"]));
  }
  s.append(scrollOf(t));
  // The set sent: the chosen files that pass their checks (one that doesn't stays ticked
  // but isn't sent). What it leaves out on the nodes in settings.json.
  const names = [...pick].filter(n => list.zones.some(z => z.name === n && !z.error)).sort();
  const drops = [];
  for (const n of list.nodes.filter(n => n.listed && n.hosted)) {
    const gone = arr(n.hosted.zones).map(z => z.name).filter(name => !names.includes(`${name.toLowerCase().replace(/\.$/, "")}.zone`));
    if (gone.length) drops.push(`${nodeText(n.host)} stops serving ${gone.join(", ")}`);
  }
  if (drops.length) s.append(el("p", "sub warn", `With this set: ${drops.join("; ")}.`));
  const go = el("a", "btn", "Open in Push");
  if (why || !names.length) { go.setAttribute("aria-disabled", "true"); go.classList.add("disabled"); go.removeAttribute("href"); }
  else go.href = `push.html#kind=zones&zones=${encodeURIComponent(names.join(","))}`;
  const row = el("div", "acts");
  row.append(go, el("span", "sub", why || (names.length ? `${names.length} zone(s): ${names.join(", ")}` : "Choose the zones.")));
  s.append(row);
  box.replaceChildren(s);
}

// ---- a new zone ---------------------------------------------------------------------------

$("newname").addEventListener("input", () => $("newname").setCustomValidity(""));
$("new").addEventListener("submit", async e => {
  e.preventDefault();
  const input = $("newname");
  const zone = input.value.trim().toLowerCase().replace(/\.$/, "").replace(/\.zone$/, "");
  const name = `${zone}.zone`;
  const ok = /^[a-z0-9][a-z0-9._-]*$/.test(zone) && zone.split(".").every(l => /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l)) && name.length <= 64;
  if (!ok) { input.setCustomValidity("a zone name: labels of letters, digits, '_' and '-', separated by '.'"); input.reportValidity(); return; }
  input.setCustomValidity("");
  if (list.zones.some(z => z.name === name)) { open(name); return; }
  if (!await leave()) return;
  try {
    const t = await getJSON(`api/zones/${encodeURIComponent(name)}/new`);
    edit(name, t.text, "A new zone from the template: fill in its records.");
  } catch (err) { await confirmDialog("Not created", [err.message], "OK", "btn"); }
});

window.addEventListener("beforeunload", e => { if (dirty()) e.preventDefault(); });

// ---- start ----------------------------------------------------------------------------------

async function start() {
  sess = await session;
  if (!sess.logged_in) {
    $("list").replaceChildren(el("div", "empty", sess.password_set ? "Log in to see the zones." : "The hosted zones need a login, and no password is set: espdns passwd: docs/getting-started.md, step 6."));
    $("main").replaceChildren();
    $("new").hidden = true;
    return;
  }
  await loadList();
  const name = new URLSearchParams(location.hash.slice(1)).get("zone");
  if (name && list.zones.some(z => z.name === name)) return open(name);
  if (list.zones.length) open(list.zones[0].name);
}

start();
setInterval(() => { if (!dirty()) loadList(); }, 15000);
