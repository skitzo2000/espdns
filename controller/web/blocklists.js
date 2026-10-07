// Blocklists (blocklists.html): the deployment's lists, each compiled from its sources
// into lists/<name>.bin by the job "blocklist" (blocklist.Run on the request the list's
// definition makes, the same as espdns blocklist's flags for it); the source files, allow
// lists and the overrides, edited as text; each node's blocking from its /status, with
// pause, resume and revert, each a job. Nothing is pushed from here: Open in Push opens the
// Push page with the compiled file chosen. Everything from files or nodes is shown as text.
import { header, el, post, getJSON, session, confirmDialog, ago, uptime, nodeLabel, nodeText, statePill, stateClass, events } from "./common.js";

header("blocklists.html");

const KINDS = ["hosts", "domains", "wildcard", "adblock", "rpz"];
const PAUSES = [[300, "5 min"], [900, "15 min"], [1800, "30 min"], [3600, "1 hour"], [4 * 3600, "4 hours"], [86400, "1 day"]];
const OVR = "overrides", OVR_BLOCK = "overrides.txt", OVR_ALLOW = "overrides-allow.txt";

let sess = {};
let ov = null;          // GET /api/blocking
let sel = null;         // {type: "list"|"source", name}
let draft = null;       // the list being edited: {def, orig (JSON), isNew}
let cur = null;         // the source being edited: {name, text, hash, size, partial, history, isNew, note, upload}
let ovr = {};           // the overrides' two files: name -> {text, hash, exists}
const comp = {};        // a list's compile: name -> {job, log: [], es}
const acts = {};        // a node's last action: host -> {text, cls}
const pauseFor = {};    // the pause chosen in a node's row: host -> seconds
let opening = 0;

const $ = id => document.getElementById(id);
const arr = v => Array.isArray(v) ? v : [];
const obj = v => v && typeof v === "object" && !Array.isArray(v) ? v : {};
const str = v => typeof v === "string" ? v : v === undefined || v === null ? "" : String(v);
const num = v => typeof v === "number" ? v.toLocaleString() : "–";
const can = () => !!sess.logged_in;

function bytes(n) {
  if (typeof n !== "number") return "–";
  return n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${Math.ceil(n / 1024)} KB` : `${n} B`;
}
function btn(text, cls, f, title) {
  const b = el("button", cls, text);
  b.type = "button";
  b.onclick = f;
  if (title) b.title = title;
  return b;
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
function section(title, ...children) {
  const s = el("div", "sect");
  s.append(el("h3", "", title), ...children.filter(Boolean));
  return s;
}
function lines(text) { return str(text).split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#")); }
async function oops(title, e) { await confirmDialog(title, [e.message || String(e)], "OK", "btn"); }

// ---- the nodes ----------------------------------------------------------------------------

function listCell(l, runs) {
  const d = el("div");
  if (!l || typeof l !== "object") { d.append(el("span", "sub", "–")); return d; }
  const state = str(l.state) || "?";
  d.append(el("span", `pill ${state === "on" ? "" : state === "failed" ? "bad" : state === "off" ? "muted" : "warn"}`, state));
  if (state === "on" || l.seq) {
    const bits = [`seq ${num(l.seq)}`];
    if (typeof l.slot === "number") bits.push(l.slot >= 0 ? `slot ${l.slot}` : "no slot");
    if (l.tier) bits.push(str(l.tier));
    if (typeof l.entries === "number") bits.push(`${num(l.entries)} entries`);
    d.append(el("div", "sub", bits.join(" · ")));
  }
  if (runs) d.append(el("div", "sub", `runs ${runs} as compiled here`));
  if (l.reverted_from > 0) d.append(el("div", "sub warn", `reverted from seq ${num(l.reverted_from)}`));
  if (l.fallback) d.append(el("div", "sub warn", `older copy: ${str(l.fallback)}`));
  if (l.error) d.append(el("div", "sub bad", str(l.error)));
  return d;
}

function renderNodes() {
  const box = $("nodes");
  const ns = arr(ov && ov.nodes);
  if (!ns.length) { box.replaceChildren(el("div", "empty", "No nodes known yet (settings.json, or found over mDNS).")); return; }
  const t = el("table", "mini blkt");
  t.append(rowOf(["Node", "Blocklist", "Overrides", "Paused", ""], "th"));
  for (const n of ns) {
    const who = nodeLabel(str(n.host));
    // Only an abnormal state shows, in the words the Nodes page uses.
    if (!n.online || (n.read && stateClass(true, n.state))) who.append(statePill(n.online, n.state));
    else if (!n.read) who.append(el("span", "sub", " no /status yet"));
    if (!n.listed) who.append(el("div", "sub", "not in settings.json"));
    const b = n.blocking && typeof n.blocking === "object" ? n.blocking : null;
    const runs = obj(n.runs);
    const paused = el("div");
    if (!b) paused.append(el("span", "sub", n.read ? "not reported (firmware from before blocking)" : "–"));
    else if (b.paused_s > 0) paused.append(el("span", "pill", `paused, ${uptime(b.paused_s)} left`));
    else paused.append(el("span", "sub", n.off ? "blocking off in its config" : "no"));
    const tr = rowOf([who, b ? listCell(b.list, str(runs.blocklist)) : "–", b ? listCell(b.overrides, str(runs.overrides)) : "–", paused, nodeActions(n, b)]);
    // On a phone the header row is hidden: each value carries its column's name.
    ["", "Blocklist", "Overrides", "Paused"].forEach((l, i) => { if (l) tr.children[i].dataset.label = l; });
    t.append(tr);
  }
  const head = el("div", "row blkhead");
  head.append(el("h2", "", "Nodes"), el("span", "sub", "A pause and a revert apply live; a pause ends at a reboot."));
  box.replaceChildren(head, scrollOf(t));
}

function nodeActions(n, b) {
  const d = el("div", "blkacts");
  const a = acts[n.host];
  if (!can()) d.append(el("span", "sub", "read-only"));
  else if (!n.listed) d.append(el("span", "sub", "only the nodes in settings.json"));
  else if (!b) d.append(el("span", "sub", "–"));
  else {
    const row = el("div", "acts");
    const sel_ = el("select");
    sel_.setAttribute("aria-label", `pause ${nodeText(n.host)} for`);
    for (const [s, label] of PAUSES) sel_.append(new Option(label, String(s)));
    sel_.value = String(pauseFor[n.host] || ov.pause_default_s || 300);
    sel_.onchange = () => { pauseFor[n.host] = Number(sel_.value); };
    row.append(sel_, btn("Pause", "btn small", () => pause(n, Number(sel_.value))));
    if (b.paused_s > 0) row.append(btn("Resume", "btn small", () => pause(n, 0)));
    d.append(row);
    const row2 = el("div", "acts");
    for (const [k, label, l] of [["blocklist", "Revert list…", b.list], ["overrides", "Revert overrides…", b.overrides]]) {
      const r = btn(label, "btn small", () => revert(n, k));
      if (!l || l.state !== "on") { r.disabled = true; r.title = `no ${k} in use: nothing to revert from`; }
      row2.append(r);
    }
    d.append(row2);
  }
  if (a) d.append(el("div", `act ${a.cls}`, a.text));
  return d;
}

// action starts a node job and follows it in the node's row.
async function action(n, kind, params, what) {
  acts[n.host] = { text: `${what}: starting…`, cls: "muted" };
  renderNodes();
  try {
    const j = await post("api/jobs", { kind, params });
    acts[n.host] = { text: `${what}: ${j.state}…`, cls: "muted" };
    renderNodes();
    follow(j, null, end => {
      const reply = str(obj(end.result).reply).trim();
      acts[n.host] = end.state === "done"
        ? { text: `${what}: done${reply ? ` (${reply})` : ""}. The row updates with the node's next /status.`, cls: "" }
        : { text: `${what}: ${end.state}: ${str(end.error)}`, cls: "bad" };
      renderNodes();
      setTimeout(load, 1500);
      setTimeout(load, 11000);
    });
  } catch (e) {
    acts[n.host] = { text: `${what}: not started: ${e.message}`, cls: "bad" };
    renderNodes();
  }
}

async function pause(n, secs) {
  const what = secs ? `pause blocking for ${PAUSES.find(p => p[0] === secs)?.[1] || `${secs} s`}` : "resume blocking";
  const lines_ = secs
    ? [`${nodeText(n.host)} (${n.host}) answers every name unblocked (its blocklist and overrides both) until the pause ends, Resume, or a reboot.`]
    : [`${nodeText(n.host)} (${n.host}) blocks again at once.`];
  if (!await confirmDialog(secs ? `Pause blocking on ${nodeText(n.host)}?` : `Resume blocking on ${nodeText(n.host)}?`, lines_, secs ? "Pause" : "Resume", secs ? "btn danger" : "btn primary")) return;
  action(n, "pause", { node: n.host, seconds: secs }, what);
}

async function revert(n, list) {
  const l = list === "overrides" ? obj(n.blocking).overrides : obj(n.blocking).list;
  const ok = await confirmDialog(`Revert the ${list} on ${nodeText(n.host)}?`, [
    `It goes back to the older copy it keeps in its other slot, live (or at its next reboot, coordinated, when two copies don't fit: reboot pending). It runs seq ${num(l.seq)} now.`,
    "The node refuses it when it keeps nothing older (none pushed before, or the one it reverted from), and says why. It keeps to the older copy until a newer one is pushed.",
  ], "Revert", "btn danger");
  if (ok) action(n, "revert", { node: n.host, list }, `revert the ${list}`);
}

// ---- the side: lists and source files ---------------------------------------------------------

function fileOf(name) { return arr(ov && ov.files).find(f => f.name === `${name}.bin`); }

function renderSide() {
  const box = $("lists");
  if (ov && ov.login_needed) {
    // Read-only (no password set): the definitions and the source files need a login.
    box.replaceChildren(el("div", "blkside", "Lists"), el("div", "empty", "The lists' definitions (a feed's URL can hold its key) and the source files need a login: set a password first."));
    $("sources").replaceChildren();
    $("deleted").hidden = true;
    $("newlist").hidden = $("newsrc").hidden = true;
    return;
  }
  const rows = [el("div", "blkside", "Lists")];
  const ls = arr(ov && ov.lists).slice();
  if (draft && draft.isNew && !ls.some(l => l.name === draft.def.name)) ls.push({ ...draft.def, kind: "blocklist", isNew: true });
  for (const l of ls) {
    const b = el("button", "boardrow" + (sel && sel.type === "list" && sel.name === l.name ? " on" : ""));
    b.type = "button";
    const top = el("div", "top");
    top.append(el("strong", "", l.name === OVR ? "Overrides" : str(l.name)),
      l.isNew ? el("span", "pill warn", "new") : l.ready ? el("span", "pill muted", "not ready") : el("span", "sub", l.kind));
    b.append(top);
    const f = fileOf(l.name);
    b.append(el("span", "sub", f ? `${f.name} · ${bytes(f.bytes)} · ${ago(f.modified)}` : `${l.name}.bin: not compiled yet`));
    const j = l.job;
    if (j) {
      const c = j.state === "failed" ? "bad" : "";
      const chips = el("div", "chips");
      const ch = el("span", `chip ${c}`, `last compile ${j.state}${j.ended ? `, ${ago(j.ended)}` : ""}`);
      if (j.error) ch.title = str(j.error);
      chips.append(ch);
      b.append(chips);
    }
    b.onclick = () => openList(l.name);
    rows.push(b);
  }
  if (ov && ov.defs_error) rows.push(el("div", "empty bad", `lists.json: ${ov.defs_error}`));
  box.replaceChildren(...rows);

  const sb = $("sources");
  const srows = [el("div", "blkside", "Source files")];
  const ss = arr(ov && ov.sources).slice();
  if (cur && cur.isNew && !ss.some(s => s.name === cur.name)) ss.push({ name: cur.name, isNew: true, used_by: [] });
  if (!ss.length) srows.push(el("div", "empty", "None yet: create one below (a list to block or allow), or use URLs only."));
  for (const s of ss) {
    const b = el("button", "boardrow" + (sel && sel.type === "source" && sel.name === s.name ? " on" : ""));
    b.type = "button";
    const top = el("div", "top");
    top.append(el("strong", "mono", str(s.name)), s.isNew ? el("span", "pill warn", "new") : el("span", "sub", bytes(s.size)));
    b.append(top);
    const used = arr(s.used_by);
    b.append(el("span", "sub", used.length ? `read by ${used.join(", ")}` : "no list reads it"));
    b.onclick = () => openSource(s.name);
    srows.push(b);
  }
  sb.replaceChildren(...srows);

  const del = $("deleted");
  del.hidden = !arr(ov && ov.deleted).length;
  if (!del.hidden) {
    const out = [el("strong", "", "Deleted (kept in the history)")];
    for (const v of ov.deleted) {
      const f = str(v.file);
      const name = f.slice(0, f.lastIndexOf(".", f.lastIndexOf(".") - 1));
      const row = el("div", "row tight");
      row.append(el("span", "mono", name), el("span", "sub", new Date(v.time).toLocaleString()), btn("Restore…", "btn quiet small", () => restore(name, f)));
      out.push(row);
    }
    del.replaceChildren(...out);
  }
  $("newlist").hidden = $("newsrc").hidden = !can();
}

// ---- leaving an edit -----------------------------------------------------------------------------

function listDirty() { return !!(draft && (draft.isNew || JSON.stringify(readForm()) !== draft.orig)); }
function srcDirty() {
  if (!cur) return false;
  if (cur.upload !== undefined || cur.isNew) return true;
  const t = $("srctext");
  return !!t && !cur.partial && t.value !== cur.text;
}
function ovrDirty() { return [OVR_BLOCK, OVR_ALLOW].some(n => { const t = $(`ovr-${n}`); return t && ovr[n] && t.value !== ovr[n].text; }); }
const dirty = () => (sel && sel.type === "list" && (sel.name === OVR ? ovrDirty() : listDirty())) || (sel && sel.type === "source" && srcDirty());

async function leave() {
  return !dirty() || confirmDialog("Drop the edits?", ["What isn't saved is dropped."], "Drop the edits");
}

// ---- a list ---------------------------------------------------------------------------------------

function defOf(l) {
  const d = { name: l.name };
  for (const k of ["sources", "allow"]) if (arr(l[k]).length) d[k] = arr(l[k]).map(str);
  for (const k of ["popular", "must_resolve"]) if (l[k]) d[k] = str(l[k]);
  for (const k of ["xor", "max_change", "min_change"]) if (typeof l[k] === "number") d[k] = l[k];
  return d;
}

async function openList(name, opts = {}) {
  if (!opts.force && !await leave()) return;
  opening++;
  sel = { type: "list", name };
  cur = null;
  if (name === OVR) {
    draft = null;
    await loadOverrides();
  } else {
    const l = arr(ov.lists).find(x => x.name === name);
    draft = l ? { def: defOf(l), isNew: false } : { def: { name, sources: [] }, isNew: true };
    draft.orig = JSON.stringify(draft.def);
  }
  history.replaceState(null, "", `#list=${encodeURIComponent(name)}`);
  renderSide();
  renderMain();
  showLastJob(name);
}

async function loadOverrides() {
  ovr = {};
  for (const n of [OVR_BLOCK, OVR_ALLOW]) {
    if (!arr(ov.sources).some(s => s.name === n)) { ovr[n] = { text: "", hash: "", exists: false }; continue; }
    try {
      const f = await getJSON(`api/blocking/sources/${encodeURIComponent(n)}`);
      ovr[n] = { text: str(f.text), hash: str(f.hash), exists: true, partial: !!f.partial };
    } catch { ovr[n] = { text: "", hash: "", exists: false }; }
  }
}

function readForm() {
  if (!draft) return null;
  if (!$("f-sources")) return draft.def;
  const d = { name: draft.def.name };
  const s = lines($("f-sources").value), a = lines($("f-allow").value);
  if (s.length) d.sources = s;
  if (a.length) d.allow = a;
  if ($("f-popular").value) d.popular = $("f-popular").value;
  if ($("f-must").value) d.must_resolve = $("f-must").value;
  for (const [id, k] of [["f-xor", "xor"], ["f-max", "max_change"], ["f-min", "min_change"]]) {
    const v = $(id).value.trim();
    if (v !== "") d[k] = Number(v);
  }
  return d;
}

function renderMain() {
  const m = $("main");
  if (!sel) { m.replaceChildren(el("div", "empty", "Choose a list or a source file.")); return; }
  if (sel.type === "source") return renderSource();
  const name = sel.name;
  const l = arr(ov.lists).find(x => x.name === name) || {};
  const head = el("div", "row");
  head.append(el("h2", "", name === OVR ? "Overrides" : name), el("span", "pill muted", name === OVR ? "kind overrides" : "kind blocklist"));
  if (draft && draft.isNew) head.append(el("span", "pill warn", "new, not saved"));
  const unsaved = el("span", "pill warn", "unsaved edits");
  unsaved.id = "unsaved";
  unsaved.hidden = !dirty() || (draft && draft.isNew);
  head.append(unsaved);
  const out = [head];
  if (name === OVR) out.push(...overridesForm());
  else out.push(...listForm(l));
  const cmd = el("pre", "cmd");
  cmd.textContent = l.command ? str(l.command) : "(saved first)";
  const d = el("details");
  d.append(el("summary", "", "The same compile with the CLI"), cmd,
    el("p", "sub", "In the controller's image the data directory is /data (mount files from elsewhere into the container to use them)."));
  out.push(d);
  const cbox = el("div", "pushsect"); cbox.id = "compile";
  const obox = el("div", "pushsect"); obox.id = "outbox";
  out.push(cbox, obox);
  m.replaceChildren(...out);
  renderCompile();
  renderOutput();
}

function sourceOptions(sel_, value) {
  sel_.replaceChildren(new Option("– none –", ""), ...arr(ov.sources).map(s => new Option(s.name, s.name)));
  if (value && !arr(ov.sources).some(s => s.name === value)) sel_.append(new Option(`${value} (missing)`, value));
  sel_.value = value || "";
}

function listForm(l) {
  const def = draft.def;
  const form = el("div", "boardform blkform");
  const ta = (id, label, v, help) => {
    const lab = el("label", "wide");
    lab.append(label);
    const t = el("textarea", "cfgtext small");
    t.id = id;
    t.spellcheck = false;
    t.rows = Math.max(3, arr(v).length + 1);
    t.value = arr(v).join("\n");
    t.oninput = changedForm;
    lab.append(t, el("span", "sub", help));
    return lab;
  };
  const srcHelp = `One per line: kind:file (a source file here) or kind:URL (https, a public address; a server inside your network, or plain http, only with its host in settings.json's internal_sources), kind ${KINDS.join(", ")}.`;
  form.append(ta("f-sources", "Block (sources)", def.sources, srcHelp),
    ta("f-allow", "Allow (allow lists)", def.allow, "The same form; what they name is never blocked by this list."));
  const grid = el("div", "grid");
  const pick = (id, label, v, help) => {
    const lab = el("label");
    lab.append(label);
    const s = el("select");
    s.id = id;
    sourceOptions(s, v);
    s.onchange = changedForm;
    lab.append(s);
    if (help) lab.title = help;
    return lab;
  };
  const numIn = (id, label, v, ph, attrs) => {
    const lab = el("label");
    lab.append(label);
    const i = el("input");
    i.id = id; i.type = "number"; i.placeholder = ph;
    Object.assign(i, attrs);
    i.value = typeof v === "number" ? String(v) : "";
    i.oninput = changedForm;
    lab.append(i);
    return lab;
  };
  grid.append(pick("f-popular", "Popular names", def.popular, "never blocked by accident: a Tranco CSV (rank,name) or one name per line"),
    pick("f-must", "Must resolve", def.must_resolve, "names the list must not block at all: it is refused if it does"),
    numIn("f-xor", "XOR bits (SD tier)", def.xor, "10", { min: 0, max: 16, step: 1 }),
    numIn("f-max", "Max change %", def.max_change, "20", { min: 0, step: "any" }),
    numIn("f-min", "Min change (entries)", def.min_change, "100", { min: 0, step: 1 }));
  form.append(grid, el("p", "sub", "A build that changes size by more than the max change and the min change is refused until accepted once. Empty: the default (20%, 100); max 0: no change."));
  if (l.ready && !(draft && draft.isNew)) form.append(el("div", "banner warn", `Not ready to compile: ${str(l.ready)}`));
  const row = el("div", "acts");
  const save = btn(draft.isNew ? "Create…" : "Save…", "btn primary", saveList);
  save.id = "savelist";
  save.disabled = !can();
  row.append(save);
  if (!draft.isNew) row.append(btn("Revert edits", "btn quiet", () => openList(sel.name, { force: true })));
  const del = btn(draft.isNew ? "Drop" : "Delete list…", "btn quiet", deleteList);
  del.disabled = !can() && !draft.isNew;
  row.append(del);
  if (!can()) row.append(el("span", "sub", "Read-only: log in to change the lists."));
  return [form, row];
}

function changedForm() {
  const u = $("unsaved");
  if (u) u.hidden = !dirty() || (draft && draft.isNew);
  renderCompile();
}

async function saveList() {
  const d = readForm();
  const others = arr(ov.lists).filter(l => l.name !== OVR && l.name !== d.name).map(defOf);
  const all = arr(ov.lists).filter(l => l.name !== OVR).map(l => l.name === d.name ? d : defOf(l));
  if (draft.isNew) all.push(d);
  const lines_ = [`blocking/lists.json is written whole; the version before is kept in blocking/.history/.`];
  if (!draft.isNew) lines_.push(`The other lists (${others.map(l => l.name).join(", ") || "none"}) are saved as they are.`);
  lines_.push("Saving doesn't compile it: Compile does, then Open in Push.");
  if (!await confirmDialog(`Save the list ${d.name}?`, lines_, "Save", "btn primary")) return;
  try {
    await post("api/blocking/defs", { lists: all, hash: str(ov.hash) });
    draft = null;
    await load();
    await openList(d.name, { force: true });
  } catch (e) { await oops("Not saved", e); }
}

async function deleteList() {
  if (draft.isNew) { draft = null; sel = null; history.replaceState(null, "", "#"); renderSide(); renderMain(); return; }
  const name = draft.def.name;
  if (!await confirmDialog(`Delete the list ${name}?`, [
    `Its definition goes from blocking/lists.json (the version before is kept). Its compiled file lists/${name}.bin and its source files stay; a node running it keeps running it.`,
  ], "Delete")) return;
  try {
    await post("api/blocking/defs", { lists: arr(ov.lists).filter(l => l.name !== OVR && l.name !== name).map(defOf), hash: str(ov.hash) });
    draft = null; sel = null;
    history.replaceState(null, "", "#");
    await load();
    renderMain();
  } catch (e) { await oops("Not deleted", e); }
}

// ---- the overrides --------------------------------------------------------------------------------

function overridesForm() {
  const out = [el("p", "sub", "Names to block or allow on every node, whatever its list says: one per line, with its subdomains.")];
  const grid = el("div", "cfgedit");
  for (const [n, label] of [[OVR_BLOCK, "Block"], [OVR_ALLOW, "Allow"]]) {
    const f = ovr[n] || { text: "", exists: false };
    const box = el("div", "ovrbox");
    const h = el("div", "row");
    h.append(el("h3", "", `${label}: ${n}`), f.exists ? el("span", "sub", "saved") : el("span", "pill muted", "no file yet"));
    const t = el("textarea", "cfgtext");
    t.id = `ovr-${n}`;
    t.spellcheck = false;
    t.value = f.text;
    t.rows = Math.min(20, Math.max(8, f.text.split("\n").length + 2));
    t.setAttribute("aria-label", `${label}: ${n}`);
    t.readOnly = !can() || !!f.partial;
    t.oninput = () => { const u = $("unsaved"); if (u) u.hidden = !dirty(); renderCompile(); };
    const row = el("div", "acts");
    const s = btn("Save…", "btn small", () => saveOverride(n));
    s.disabled = !can() || !!f.partial;
    row.append(s);
    if (f.exists) row.append(btn("Open as a file", "btn quiet small", () => openSource(n)));
    box.append(h, t, row);
    grid.append(box);
  }
  out.push(grid);
  if (!can()) out.push(el("p", "sub", "Read-only: log in to change the overrides."));
  return out;
}

async function saveOverride(n) {
  const t = $(`ovr-${n}`), f = ovr[n];
  if (f.exists && t.value === f.text) { await confirmDialog("Nothing to save", ["The text is the same as the saved file."], "OK", "btn"); return; }
  if (!await confirmDialog(`Save ${n}?`, [f.exists ? "The version before is kept in blocking/sources/.history/." : "A new file.", "Then Compile, and push overrides.bin with the Push page."], "Save", "btn primary")) return;
  try {
    await post(`api/blocking/sources/${encodeURIComponent(n)}`, { text: t.value, hash: f.exists ? f.hash : "" });
    const keep = {};
    for (const o of [OVR_BLOCK, OVR_ALLOW]) if (o !== n && $(`ovr-${o}`)) keep[o] = $(`ovr-${o}`).value;
    await load();
    await loadOverrides();
    renderMain();
    for (const [o, v] of Object.entries(keep)) $(`ovr-${o}`).value = v; // the other's edits stay
  } catch (e) { await oops("Not saved", e); }
}

// ---- the compile ------------------------------------------------------------------------------------

function follow(job, onLog, onEnd) {
  const es = events(`api/jobs/${encodeURIComponent(job.id)}/events`);
  es.addEventListener("log", e => { if (onLog) onLog(JSON.parse(e.data)); });
  es.addEventListener("state", e => { if (onLog) onLog(null, JSON.parse(e.data)); });
  es.addEventListener("end", e => { es.close(); onEnd(JSON.parse(e.data)); });
  return es;
}

async function showLastJob(name) {
  const l = arr(ov.lists).find(x => x.name === name);
  const j = l && l.job;
  if (!j || (comp[name] && comp[name].job.id === j.id)) { renderCompile(); return; }
  try {
    const full = await getJSON(`api/jobs/${encodeURIComponent(j.id)}`);
    comp[name] = { job: full, log: arr(full.log).map(x => `${new Date(x.time).toLocaleTimeString()}  ${str(x.text)}`) };
    if (!["done", "failed", "stopped"].includes(full.state)) watch(name, full, true);
  } catch { /* gone */ }
  renderCompile();
}

function watch(name, job, have) {
  const c = comp[name] || (comp[name] = { job, log: [] });
  c.job = job;
  if (!have) c.log = [];
  const seen = new Set();
  c.es = follow(job, (line, state) => {
    if (comp[name] !== c) return;
    if (state) { c.job = state; renderCompile(); return; }
    if (seen.has(line.n)) return;
    seen.add(line.n);
    if (have && c.log.length >= line.n) return; // already had it from the job's record
    c.log.push(`${new Date(line.time).toLocaleTimeString()}  ${str(line.text)}`);
    const pre = $("log");
    if (pre && sel && sel.name === name) { pre.textContent = c.log.join("\n"); pre.scrollTop = pre.scrollHeight; }
  }, end => {
    if (comp[name] !== c) return;
    c.job = end;
    renderCompile();
    load();
  });
}

async function compile(accept) {
  const name = sel.name;
  if (accept) {
    const ch = obj(obj(obj(comp[name] && comp[name].job).result).result).change;
    const ok = await confirmDialog(`Accept this change once for ${name}?`, [
      `The last compile was refused: ${arr(ch.over).join(", ") || "its size changed by more than allowed"}.`,
      `It is compiled again from its sources as they are now, and written over lists/${name}.bin whatever its size. Only this once: the next compile is checked again, against this build.`,
      "Check the sources first: a list that shrank or grew this much is often a feed that broke.",
    ], "Compile and accept", "btn danger");
    if (!ok) return;
  }
  try {
    const j = await post("api/jobs", { kind: "blocklist", params: { list: name, accept_change: !!accept } });
    comp[name] = { job: j, log: [] };
    watch(name, j, false);
    renderCompile();
  } catch (e) { await oops("Not compiled", e); }
}

async function stopCompile() {
  const c = comp[sel.name];
  if (!c) return;
  try { await post(`api/jobs/${encodeURIComponent(c.job.id)}/stop`); } catch (e) { await oops("Not stopped", e); }
}

function renderCompile() {
  const box = $("compile");
  if (!box || !sel || sel.type !== "list") return;
  const name = sel.name;
  const l = arr(ov.lists).find(x => x.name === name) || {};
  const c = comp[name];
  const running = c && !["done", "failed", "stopped"].includes(c.job.state);
  const s = el("div", "sect");
  s.append(el("h3", "", "Compile"));
  let why = "";
  if (!can()) why = "Read-only: log in to compile.";
  else if (draft && draft.isNew) why = "Save the list first.";
  else if (dirty()) why = "Save the edits first: a compile reads the saved files.";
  else if (l.ready) why = str(l.ready);
  else if (running) why = "Compiling…";
  const row = el("div", "acts");
  const go = btn("Compile", "btn", () => compile(false));
  go.disabled = !!why;
  row.append(go);
  if (running) row.append(btn("Stop", "btn quiet", stopCompile));
  row.append(el("span", "sub", why || `Into lists/${name}.bin, checked against the build there now. URLs are fetched by the controller.`));
  s.append(row);
  if (c) {
    const j = c.job;
    const st = el("div", "row");
    st.append(el("span", `pill ${j.state === "failed" ? "bad" : ""}`, j.stopping && running ? "stopping" : str(j.state)),
      el("span", "sub", `${str(j.who)}${j.created ? `, ${new Date(j.created).toLocaleString()}` : ""} · job ${str(j.id)}`));
    s.append(st);
    const pre = el("pre");
    pre.id = "log";
    pre.textContent = c.log.join("\n") || "…";
    s.append(pre);
    s.append(...resultView(name, j));
  }
  box.replaceChildren(s);
  const pre = $("log");
  if (pre) pre.scrollTop = pre.scrollHeight;
}

function rpzLine(z) {
  z = obj(z);
  const take = [["blocked", "blocked"], ["drop", "drop (blocked)"], ["allowed", "passthru (allowed)"], ["wildcard", "of them *.name"]];
  const skip = [["local_data", "local data"], ["tcp_only", "tcp-only"], ["ip", "rpz-ip"], ["client_ip", "rpz-client-ip"], ["nsdname", "rpz-nsdname"],
    ["nsip", "rpz-nsip"], ["outside", "outside the zone"], ["bad_name", "bad names"], ["bad_line", "bad lines"], ["directives", "$INCLUDE/$GENERATE"]];
  const a = take.map(([k, t]) => `${num(z[k] || 0)} ${t}`).join(", ");
  const b = skip.filter(([k]) => z[k] > 0).map(([k, t]) => `${num(z[k])} ${t}`);
  return `rpz: ${a}; skipped: ${b.length ? b.join(", ") : "none"}${z.zone ? `; ${num(z.zone)} SOA/NS of the zone` : ""}`;
}

function resultView(name, j) {
  const out = [];
  const res = obj(j.result), r = obj(res.result);
  if (j.state === "failed" && !res.refused) out.push(el("div", "banner bad", `Failed: ${str(j.error)}`));
  if (j.state === "stopped") out.push(el("div", "banner warn", "Stopped: nothing written."));
  if (arr(r.sources).length) {
    const t = el("table", "mini");
    t.append(rowOf(["Source", "", "Lines", "Entries", "Skipped"], "th"));
    for (const s of r.sources) {
      const src = el("div");
      // A file here by its name (the full path is the CLI command's, above).
      const dir = `${str(ov.sources_dir)}/`;
      src.append(el("div", "mono", str(s.source).replace(dir, "")));
      t.append(rowOf([src, s.allow ? "allow" : "block", num(s.lines), num(s.entries), num(s.skipped)]));
      if (s.rpz) {
        const tr = el("tr", "rpzrow"), td = el("td", "sub", rpzLine(s.rpz));
        td.colSpan = 5;
        tr.append(td);
        t.append(tr);
      }
    }
    out.push(scrollOf(t));
  }
  if (r.file && r.file.Size) {
    const n = (r.blocked_exact || 0) + (r.blocked_suffix || 0);
    const cs = obj(r.compile);
    out.push(el("p", "sub", `${num(n)} domains blocked (${num(r.blocked_exact)} exact, ${num(r.blocked_suffix)} suffix), ${num((r.allowed_exact || 0) + (r.allowed_suffix || 0))} allowed; ` +
      `${bytes(r.file.Size)}; of ${num(cs.In)} entries read: ${num(cs.Duplicates)} duplicates, ${num(cs.Covered)} covered by a parent, ${num(cs.PublicSuffix)} public suffixes, ${num(cs.Overruled)} overruled by an allow; ` +
      `key ${num(r.tries)} tried, ${num(r.dropped)} hash(es) dropped for popular names.`));
  }
  const ch = obj(r.change), oldS = obj(ch.old), newS = obj(ch.new);
  if (res.refused || ch.refused) {
    const b = el("div", "banner bad");
    b.append(el("strong", "", "Refused by the size-change check. "),
      `${arr(ch.over).join(", ")}: more than ${ch.max_change}% (and ${num(ch.min_change)} entries) from lists/${name}.bin. Nothing was written: the file there is the build before.`);
    const row = el("div", "acts");
    const a = btn("Accept this change once…", "btn danger small", () => compile(true));
    a.disabled = !can();
    row.append(a);
    b.append(row);
    out.push(b);
  } else if (ch.accepted) {
    out.push(el("div", "banner warn", `Accepted once: ${arr(ch.over).join(", ")} (over ${ch.max_change}%).`));
  } else if (j.state === "done" && ch.previous) {
    out.push(el("p", "sub", `Size against the build before: blocked ${num(oldS.blocked)} → ${num(newS.blocked)}, allowed ${num(oldS.allowed)} → ${num(newS.allowed)}, bytes ${num(oldS.bytes)} → ${num(newS.bytes)}: within ${ch.max_change}% or ${num(ch.min_change)} entries.`));
  } else if (j.state === "done") {
    out.push(el("p", "sub", "No build before to compare with: any size taken."));
  }
  if (j.state === "done" && r.written) {
    const b = el("div", "banner ok");
    b.append(`Wrote lists/${str(res.file)}. `, pushLink(res.kind, res.file));
    out.push(b);
  }
  return out;
}

function pushLink(kind, file) {
  const a = el("a", "btn small", "Open in Push");
  a.href = `push.html#kind=${encodeURIComponent(kind === "overrides" ? "overrides" : "blocklist")}&file=${encodeURIComponent(file)}`;
  return a;
}

function renderOutput() {
  const box = $("outbox");
  if (!box || !sel || sel.type !== "list") return;
  const name = sel.name;
  const f = fileOf(name);
  const s = el("div", "sect");
  s.append(el("h3", "", `lists/${name}.bin`));
  if (!f) {
    s.append(el("p", "sub", "Not compiled yet."));
  } else {
    s.append(el("p", "sub", f.error ? `Not a list the push takes: ${str(f.error)}` :
      `${bytes(f.bytes)}, ${num(f.entries)} entries, ${f.hash_bits}-bit hashes, ${f.xor_bits ? `${f.xor_bits}-bit xor` : "no xor filter"}; compiled ${ago(f.modified)} (${new Date(f.modified).toLocaleString()}).`));
    const kind = name === OVR ? "overrides" : "blocklist";
    const on = arr(ov.nodes).filter(n => obj(n.runs)[kind] === f.name).map(n => str(n.host));
    s.append(el("p", "sub", on.length ? `Running it: ${on.join(", ")}.` : `No node runs this build (by its hash).`));
    if (!f.error) {
      const row = el("div", "acts");
      row.append(pushLink(kind, f.name), el("span", "sub", "A dry run first, then the rollout: canary, soak, and every node that took it sent back on a failure."));
      s.append(row);
    }
  }
  box.replaceChildren(s);
}

// ---- a source file -------------------------------------------------------------------------------

async function openSource(name, opts = {}) {
  if (!opts.force && !await leave()) return;
  const n = ++opening;
  try {
    const f = await getJSON(`api/blocking/sources/${encodeURIComponent(name)}`);
    if (n !== opening) return;
    cur = { name, text: str(f.text), hash: str(f.hash), size: f.size, modified: f.modified, partial: !!f.partial, history: arr(f.history), isNew: false };
  } catch (e) {
    $("main").replaceChildren(el("div", "banner bad", e.message));
    return;
  }
  sel = { type: "source", name };
  draft = null;
  history.replaceState(null, "", `#source=${encodeURIComponent(name)}`);
  renderSide();
  renderMain();
}

function editNew(name, text, note) {
  opening++;
  cur = { name, text, hash: "", size: text.length, partial: false, history: [], isNew: true, note };
  sel = { type: "source", name };
  draft = null;
  history.replaceState(null, "", `#source=${encodeURIComponent(name)}`);
  renderSide();
  renderMain();
}

function syntaxHelp(name) {
  if (name.endsWith(".rpz") || name.endsWith(".zone")) return "A Response Policy Zone or other master file, for kind rpz: QNAME triggers only (CNAME . or *. or rpz-drop. block, rpz-passthru. allows); the rest is skipped and counted.";
  if (name.endsWith(".csv")) return "Popular names: Tranco's rank,name lines, or one name per line.";
  if (name.endsWith(".hosts")) return "A hosts file, for kind hosts: 0.0.0.0 name lines.";
  return "One entry per line in the kind a list reads it as (domains: the name only; wildcard: its subdomains too; adblock: ||name^ and @@||name^; hosts: 0.0.0.0 name). # starts a comment. An allow list is one too.";
}

function renderSource() {
  const m = $("main");
  const s = arr(ov.sources).find(x => x.name === cur.name) || { used_by: [] };
  const head = el("div", "row");
  head.append(el("h2", "mono", cur.name));
  if (cur.isNew) head.append(el("span", "pill warn", "new, not saved"));
  else head.append(el("span", "sub", `${bytes(cur.size)}, saved ${new Date(cur.modified).toLocaleString()}`));
  const unsaved = el("span", "pill warn", "unsaved edits");
  unsaved.id = "unsaved";
  unsaved.hidden = !srcDirty() || cur.isNew;
  head.append(unsaved);
  const used = el("div", "chips");
  for (const u of arr(s.used_by)) {
    const c = btn(u === OVR ? "overrides" : `list ${u}`, "chip info", () => openList(u));
    used.append(c);
  }
  if (!arr(s.used_by).length) used.append(el("span", "chip info", "no list reads it"));
  const out = [head, used, el("p", "sub", syntaxHelp(cur.name))];
  if (cur.note) out.push(el("div", "banner warn", cur.note));
  if (cur.partial) out.push(el("div", "banner warn", `${bytes(cur.size)}: too big to edit here, only its start is shown. Replace it whole from a file.`));
  const ta = el("textarea", "cfgtext");
  ta.id = "srctext";
  ta.spellcheck = false;
  ta.value = cur.upload !== undefined && cur.upload.length > (ov.show_max || 0) ? "" : cur.upload !== undefined ? cur.upload : cur.text;
  ta.readOnly = !can() || cur.partial || (cur.upload !== undefined && cur.upload.length > (ov.show_max || 0));
  ta.rows = Math.min(36, Math.max(14, ta.value.split("\n").length + 2));
  ta.setAttribute("aria-label", `${cur.name}, text`);
  ta.oninput = () => { $("unsaved").hidden = !srcDirty() || cur.isNew; };
  if (cur.upload !== undefined && cur.upload.length > (ov.show_max || 0)) out.push(el("div", "banner ok", `${bytes(cur.upload.length)} read from the file, ready to save (too big to show here).`));
  out.push(ta);
  const row = el("div", "acts");
  const save = btn(cur.isNew ? "Create…" : "Save…", "btn primary", saveSource);
  save.disabled = !can();
  const file = el("input");
  file.type = "file";
  file.accept = ".txt,.zone,.rpz,.csv,.hosts,.list,text/plain";
  file.hidden = true;
  file.onchange = () => upload(file.files[0]);
  const up = btn("Replace from a file…", "btn quiet", () => file.click());
  up.disabled = !can();
  row.append(save, up, file);
  if (!cur.isNew) {
    row.append(btn("Revert", "btn quiet", () => openSource(cur.name, { force: true })));
    const del = btn("Delete…", "btn quiet", deleteSource);
    const users = arr(s.used_by).filter(u => u !== OVR);
    del.disabled = !can() || users.length > 0;
    if (users.length) del.title = `read by ${users.join(", ")}: take it out of those lists first`;
    row.append(del);
  }
  if (!can()) row.append(el("span", "sub", "Read-only: log in to change the files."));
  out.push(row);
  if (arr(cur.history).length) {
    const d = el("details");
    d.append(el("summary", "", `${cur.history.length} earlier version(s) kept in blocking/sources/.history/`));
    const t = el("table", "mini");
    for (const v of cur.history) t.append(rowOf([new Date(v.time).toLocaleString(), bytes(v.size), btn("Open", "btn quiet small", () => openVersion(v.file))]));
    d.append(scrollOf(t));
    out.push(d);
  }
  m.replaceChildren(...out);
}

async function upload(f) {
  if (!f) return;
  if (f.size > (ov.max_source || 0)) { await oops("Not read", new Error(`${f.name} is ${bytes(f.size)}: a source file here is at most ${bytes(ov.max_source)}. Use its URL instead.`)); return; }
  try {
    cur.upload = await f.text();
    cur.note = `Read from ${f.name}: save it to replace ${cur.name}.`;
    renderSource();
  } catch (e) { await oops("Not read", e); }
}

async function openVersion(file) {
  try {
    const v = await getJSON(`api/blocking/sources/${encodeURIComponent(cur.name)}?version=${encodeURIComponent(file)}`);
    if (v.partial) { await oops("Too big to restore here", new Error("Only its start can be shown; restore it from blocking/sources/.history/ by hand.")); return; }
    cur.upload = str(v.text);
    cur.note = `The version kept ${file}: save it to have it back.`;
    renderSource();
  } catch (e) { await oops("Not opened", e); }
}

async function restore(name, file) {
  if (!await leave()) return;
  try {
    const v = await getJSON(`api/blocking/sources/${encodeURIComponent(name)}?version=${encodeURIComponent(file)}`);
    editNew(name, str(v.text), `Restored from the history (${file}): save it to have it back.`);
  } catch (e) { await oops("Not restored", e); }
}

async function saveSource() {
  const text = cur.upload !== undefined && cur.upload.length > (ov.show_max || 0) ? cur.upload : $("srctext").value;
  if (!cur.isNew && cur.upload === undefined && text === cur.text) { await confirmDialog("Nothing to save", ["The text is the same as the saved file."], "OK", "btn"); return; }
  const s = arr(ov.sources).find(x => x.name === cur.name);
  const lines_ = [cur.isNew ? `A new file, blocking/sources/${cur.name} (${bytes(text.length)}).` : `${bytes(text.length)}; the version before is kept in blocking/sources/.history/.`];
  if (s && arr(s.used_by).length) lines_.push(`Read by ${s.used_by.join(", ")}: compile them for it to count.`);
  if (!await confirmDialog(`Save ${cur.name}?`, lines_, "Save", "btn primary")) return;
  try {
    await post(`api/blocking/sources/${encodeURIComponent(cur.name)}`, { text, hash: cur.isNew ? "" : cur.hash });
    const name = cur.name;
    cur = null;
    await load();
    await openSource(name, { force: true });
  } catch (e) { await oops("Not saved", e); }
}

async function deleteSource() {
  if (!await confirmDialog(`Delete ${cur.name}?`, [`It is removed from blocking/sources/; kept in its history, where Restore has it back.`], "Delete")) return;
  try {
    await post(`api/blocking/sources/${encodeURIComponent(cur.name)}/delete`, { hash: cur.hash });
    cur = null; sel = null;
    history.replaceState(null, "", "#");
    await load();
    renderMain();
  } catch (e) { await oops("Not deleted", e); }
}

// ---- new ones -------------------------------------------------------------------------------------

$("newlist").addEventListener("submit", async e => {
  e.preventDefault();
  const input = $("newlistname");
  const name = input.value.trim().toLowerCase().replace(/\.bin$/, "");
  if (!/^[a-z0-9]([a-z0-9._-]{0,58}[a-z0-9])?$/.test(name) || name.includes("..") || name === OVR) {
    input.setCustomValidity(name === OVR ? "overrides is the overrides' own" : "1 to 60 lowercase letters, digits, '.', '_' and '-'");
    input.reportValidity();
    return;
  }
  input.setCustomValidity("");
  input.value = "";
  if (arr(ov.lists).some(l => l.name === name)) return openList(name);
  if (!await leave()) return;
  opening++;
  sel = { type: "list", name };
  cur = null;
  draft = { def: { name, sources: [] }, isNew: true };
  draft.orig = JSON.stringify(draft.def);
  renderSide();
  renderMain();
});
$("newlistname").addEventListener("input", () => $("newlistname").setCustomValidity(""));

$("newsrc").addEventListener("submit", async e => {
  e.preventDefault();
  const input = $("newsrcname");
  let name = input.value.trim().toLowerCase();
  if (!/\.(txt|zone|rpz|csv|hosts|list)$/.test(name)) name += ".txt";
  if (!/^[a-z0-9][a-z0-9._-]*\.(txt|zone|rpz|csv|hosts|list)$/.test(name) || name.includes("..") || name.length > 100) {
    input.setCustomValidity("lowercase letters, digits, '.', '_' and '-', ending .txt, .zone, .rpz, .csv, .hosts or .list");
    input.reportValidity();
    return;
  }
  input.setCustomValidity("");
  input.value = "";
  if (arr(ov.sources).some(s => s.name === name)) return openSource(name);
  if (!await leave()) return;
  editNew(name, "# one entry per line; # starts a comment\n", "A new file: write or paste its entries, or replace it from a file, then save.");
});
$("newsrcname").addEventListener("input", () => $("newsrcname").setCustomValidity(""));

window.addEventListener("beforeunload", e => { if (dirty()) e.preventDefault(); });

// ---- loading ----------------------------------------------------------------------------------------

async function load() {
  try {
    ov = await getJSON("api/blocking");
  } catch (e) {
    $("banner").replaceChildren(el("div", "banner bad", e.message));
    return;
  }
  const bans = [];
  if (!sess.logged_in) bans.push(el("div", "banner warn", sess.password_set ? "Log in to change the lists or act on the nodes." : "Read-only: no password is set. The nodes' blocking is shown; the lists and their files need a login."));
  if (ov.defs_error) bans.push(el("div", "banner bad", `blocking/lists.json doesn't parse, so its lists can't be compiled or saved here until it is fixed by hand: ${ov.defs_error}`));
  $("banner").replaceChildren(...bans);
  renderNodes();
  renderSide();
  renderOutput();
  if (sel && sel.type === "list") renderCompile();
}

async function start() {
  sess = await session;
  if (sess.password_set && !sess.logged_in) return; // the login page
  await load();
  if (!ov) return;
  if (ov.login_needed) {
    $("main").replaceChildren(el("div", "empty", "Read-only: the lists and the source files need a login (espdns passwd: docs/getting-started.md, step 6)."));
    return;
  }
  const h = new URLSearchParams(location.hash.slice(1));
  const l = h.get("list"), s = h.get("source");
  if (l && (l === OVR || arr(ov.lists).some(x => x.name === l))) return openList(l);
  if (s && arr(ov.sources).some(x => x.name === s)) return openSource(s);
  const first = arr(ov.lists).find(x => x.name !== OVR);
  openList(first ? first.name : OVR);
}

start();
setInterval(() => { if (!document.hidden) load(); }, 10000);
