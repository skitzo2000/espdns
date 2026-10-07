// Adoption: choose a node the controller found that isn't adopted, its config and its
// address; see the address it would get and the config checked for it (read-only); a dry
// run (the zone primary read, what it would change shown per zone, nothing changed); then the
// adoption after it, followed step by step. The server builds the adoption make fleet-adopt
// builds (internal/adoption) and refuses one that isn't what its dry run checked. The zone
// primary's lists are under System (system.html, primary.js).
import { header, el, post, getJSON, session, confirmDialog, waitJob, nodeLabel, nodeText, statePill, events } from "./common.js";
import { primaryFacts } from "./primary.js";

header("adopt.html");

const $ = id => document.getElementById(id);
const arr = v => Array.isArray(v) ? v : [];
const STEP_PILL = { failed: "bad", waiting: "muted", skipped: "muted" };

let src = null;     // /api/adopt
let pv = null;      // the last preview
let lastDry = null; // {id, key, ended, manual}
let running = null;
const form = { node: "", config: "", mode: "auto", address: "", gateway: "", reserved: false };

// ---- the request ------------------------------------------------------------------------

function nodeOf(h) { return arr(src && src.nodes).find(n => n.host === h); }

function params() {
  const n = nodeOf(form.node);
  const p = { node: form.node, node_id: n ? n.id : "", config: form.config };
  if (form.mode === "static") {
    if (form.address) p.address = form.address.trim();
    if (form.gateway) p.gateway = form.gateway.trim();
  } else if (form.mode === "dhcp") {
    p.address = "dhcp";
    if (form.reserved) p.reserved = true;
  }
  return p;
}
const keyOf = p => JSON.stringify([p.node, p.node_id, p.config, p.address || "", p.gateway || "", !!p.reserved]);

// noDHCPOf is the network with no DHCP server (settings.json's no_dhcp) the node is on, or
// "" if it is on none of them (none set: DHCP is offered anywhere).
function noDHCPOf(host) {
  const toInt = a => a.split(".").reduce((x, o) => (x << 8) + Number(o), 0) >>> 0;
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(host || "")) return "";
  for (const n of arr(src.no_dhcp)) {
    const [net, bits] = n.split("/");
    const mask = bits === "0" ? 0 : (~0 << (32 - Number(bits))) >>> 0;
    if (((toInt(host) & mask) >>> 0) === ((toInt(net) & mask) >>> 0)) return n;
  }
  return "";
}

// ---- the nodes --------------------------------------------------------------------------

function rowOf(cells) {
  const tr = el("tr");
  for (const c of cells) {
    const td = el("td");
    if (c instanceof Node) td.append(c); else td.textContent = c;
    tr.append(td);
  }
  return tr;
}

function renderNodes() {
  // Only nodes read: one whose /status isn't in yet (just found, or offline) may be
  // adopted already.
  const cands = arr(src.nodes).filter(n => !n.adopted && n.read);
  const rows = cands.map(n => {
    const rb = el("input"); rb.type = "radio"; rb.name = "node"; rb.checked = form.node === n.host;
    rb.disabled = arr(n.refusals).length > 0;
    rb.setAttribute("aria-label", `adopt ${nodeText(n.host, n.hostname)}`);
    rb.onchange = () => { form.node = n.host; if (!form.config && n.config) form.config = n.config; renderAll(); };
    const who = nodeLabel(n.host, n.hostname);
    const fw = el("div"); fw.append(el("div", "", n.version ? `v${n.version}` : "–"), el("div", "sub", n.net || ""));
    const at = el("div"); at.append(el("div", "mono", n.address || "–"));
    at.append(el("div", "sub", [n.gateway && `gateway ${n.gateway}`, n.from && `from its ${n.from}`].filter(Boolean).join(", ")));
    const st = el("div");
    st.append(statePill(n.online, n.state));
    for (const r of arr(n.refusals)) st.append(el("div", "sub bad", r));
    const id = el("button", "btn small", "Identify");
    id.type = "button";
    id.disabled = !src.key || !n.online || arr(n.refusals).length > 0;
    id.title = src.key ? "flicker its LED for 30 s" : "no release key";
    id.onclick = () => identify(n.host, id);
    const tr = rowOf([rb, who, `${n.board || "?"} · ${n.image || "?"}`, fw, at, st, id]);
    tr.children[2].className = "wide";
    if (rb.disabled) tr.classList.add("dim");
    return tr;
  });
  $("nodes").replaceChildren(...(rows.length ? rows : [rowOf(["No node to adopt: every node found runs a pushed config. A new board shows here once it is flashed and on the network (Builder)."])]));
  if (!rows.length) $("nodes").firstChild.firstChild.colSpan = 7;
  const unread = arr(src.nodes).filter(n => !n.read).map(n => n.host);
  if (unread.length) {
    const tr = rowOf([`Not read yet (no /status: just found, or not answering): ${unread.join(", ")}`]);
    tr.firstChild.colSpan = 7;
    tr.firstChild.className = "sub";
    $("nodes").append(tr);
  }

  // Adopted, but not in settings.json: rollouts don't count or change them.
  const un = arr(src.nodes).filter(n => n.adopted && !n.listed);
  const box = $("unlisted");
  if (!un.length) { box.replaceChildren(); return; }
  const d = el("div", "banner warn");
  d.append(el("strong", "", "Adopted, not in settings.json: "), "rollouts don't count these nodes as peers nor change them, and the controller's actions don't take them.");
  const t = el("table", "mini");
  for (const n of un) {
    const b = el("button", "btn small", "Add to settings.json");
    b.type = "button";
    b.onclick = () => addToSettings(n.host, n.id);
    t.append(rowOf([nodeLabel(n.host), n.config || "", b]));
  }
  box.replaceChildren(d, t);
}

async function identify(host, btn) {
  try {
    const j = await post("api/jobs", { kind: "identify", params: { node: host, seconds: 30 } });
    btn.textContent = "Flickering…";
    setTimeout(() => { btn.textContent = "Identify"; }, 30000);
    waitJob(j.id).catch(() => {});
  } catch (e) { await confirmDialog("Not started", [e.message], "OK", "btn"); }
}

async function addToSettings(host, id) {
  if (!await confirmDialog(`Add ${host} to settings.json?`, [
    `Node ${id} on ${host} runs a pushed config. In settings.json, rollouts count it as a peer and change it, and the controller polls it and takes its actions (flush, reboot, config push).`,
    "settings.json is written whole, as it is now with this address added."], "Add", "btn primary")) return;
  try {
    const j = await waitJob((await post("api/jobs", { kind: "settings-add", params: { node: host } })).id);
    if (j.state !== "done") throw new Error(j.error || j.state);
    await load();
  } catch (e) { await confirmDialog("Not added", [e.message], "OK", "btn"); }
}

// ---- config, address, preview ----------------------------------------------------------

function renderConfig() {
  const sel = $("config");
  sel.replaceChildren(new Option("– choose –", ""), ...arr(src.configs).map(c => {
    const o = new Option(c.error ? `${c.name} (${c.error})` : `${c.name}${c.address ? " · " + c.address : ""}${arr(c.zones).length ? " · " + c.zones.length + " zones" : ""}`, c.name);
    o.disabled = !!c.error;
    return o;
  }));
  sel.value = form.config;
  const n = nodeOf(form.node);
  const c = arr(src.configs).find(c => c.name === form.config);
  $("auto-text").textContent = c && c.address ? `The config's: ${c.address}${c.gateway ? ", gateway " + c.gateway : ""}`
    : n && n.address ? `The one it runs on: ${n.address}${n.gateway ? ", gateway " + n.gateway : ""}` : "The config's, else the one it runs on";
  const noDHCP = n ? noDHCPOf(n.host) : "";
  const dr = $("dhcp-row").querySelector("input");
  dr.disabled = !n || !!noDHCP;
  $("dhcp-note").textContent = noDHCP ? `not on ${noDHCP}: that network has no DHCP server (settings.json, no_dhcp)` : "only on a network with a DHCP server, which reserves its address";
  if (dr.disabled && form.mode === "dhcp") form.mode = "auto";
  for (const r of document.querySelectorAll('input[name="addr"]')) r.checked = r.value === form.mode;
  $("static-opts").hidden = form.mode !== "static";
  $("reserved-row").hidden = form.mode !== "dhcp";
}

let pvTimer = null, pvSeq = 0;
function changed() {
  renderConfig();
  updateGo();
  clearTimeout(pvTimer);
  pvTimer = setTimeout(preview, 300);
}

async function preview() {
  const seq = ++pvSeq;
  const box = $("preview");
  pv = null;
  const p = params();
  if (!p.node || !p.config) { box.replaceChildren(el("p", "sub", "Choose the node and its config.")); renderPrimary(); updateGo(); return; }
  if (form.mode === "static" && !p.address) { box.replaceChildren(el("p", "sub", "Give the address, with its prefix length.")); updateGo(); return; }
  box.classList.add("loading");
  try {
    const r = await post("api/adopt/preview", p);
    if (seq !== pvSeq) return;
    pv = r;
    box.replaceChildren(...previewOf(r));
  } catch (e) {
    if (seq !== pvSeq) return;
    box.replaceChildren(el("div", "banner bad", e.message));
  } finally {
    if (seq === pvSeq) box.classList.remove("loading");
  }
  renderPrimary();
  updateGo();
}

function previewOf(r) {
  const out = [];
  const ad = el("div", "sect");
  ad.append(el("h3", "", "Address"));
  if (r.address) {
    const l = el("div"); l.append(el("span", "mono", r.address), r.gateway ? el("span", "", `, gateway `) : "", r.gateway ? el("span", "mono", r.gateway) : "");
    ad.append(l, el("div", "sub", `${r.how === "new" ? "new" : r.how}${r.from ? " · " + r.from : ""}`));
  }
  for (const n of arr(r.notes)) ad.append(el("div", "sub warn", n));
  out.push(ad);
  if (r.refusal) out.push(el("div", "banner bad", `Can't be adopted so: ${r.refusal}`));
  const ck = r.check || {};
  const cs = el("div", "sect");
  cs.append(el("h3", "", `Config check: ${ck.ok ? "passes" : "fails"}`));
  cs.lastChild.className = ck.ok ? "ok" : "bad";
  if (ck.error) cs.append(el("div", "bad", ck.error));
  if (ck.node && ck.node.refusal) cs.append(el("div", "bad", ck.node.refusal));
  if (arr(ck.services).length) {
    const chips = el("div", "chips");
    for (const s of ck.services) chips.append(el("span", "chip", s));
    cs.append(el("div", "sub", "Services it runs:"), chips);
  }
  for (const m of arr(ck.memory)) {
    const d = el("div", m.fits ? "sub" : "bad");
    d.textContent = `Memory on ${m.board} (${m.from}): ${m.fits ? "fits" : "doesn't fit"} · internal ${m.internal_kb[0]} of ${m.internal_kb[1]} KB · PSRAM ${m.psram_kb[0]} of ${m.psram_kb[1]} KB${m.error ? " · " + m.error : ""}`;
    cs.append(d);
  }
  if (ck.bytes) cs.append(el("div", "sub", `${ck.bytes} bytes pushed`));
  out.push(cs);
  return out;
}

// ---- the zone primary -------------------------------------------------------------------

function renderPrimary() {
  const box = $("primary");
  const t = src.primary || {};
  const out = [primaryFacts(t, el("table", "facts"))];
  const zones = pv ? arr(pv.zones) : [];
  if (pv && !zones.length) out.push(el("p", "sub", "The config carries no secondary zones: nothing to allow on a primary."));
  if (zones.length) {
    out.push(el("p", "sub", `Secondary zones of ${form.config}${pv.primary ? `, from the primary ${pv.primary}` : ""}: ${zones.join(", ")}.`));
    if (pv.primary_api) {
      out.push(el("p", "", "The adoption adds the node's address to each zone's zone transfer and NOTIFY lists through the API; the dry run reads them and shows what it would change."));
    } else {
      const d = el("div", "banner warn");
      d.append(el("strong", "", "By hand: "), `${pv.primary_why}. Make these changes on the zone primary, then tick that they are done before you adopt:`);
      const ul = el("ul", "hints");
      for (const m of arr(pv.manual)) ul.append(el("li", "", m));
      d.append(ul);
      out.push(d);
    }
  }
  box.replaceChildren(...out);
  $("done-row").hidden = !(pv && zones.length && !pv.primary_api);
}

// ---- dry run and adoption ---------------------------------------------------------------

function updateGo() {
  const p = params();
  const ok = p.node && p.config && pv && !pv.refusal;
  const fresh = lastDry && lastDry.key === keyOf(p) && Date.now() - lastDry.ended < src.dry_run_valid_s * 1000;
  const manual = pv && arr(pv.zones).length && !pv.primary_api;
  $("dry").disabled = !ok || !!running;
  $("go").disabled = !ok || !fresh || !src.key || !!running || (manual && !$("primary-done").checked);
  const note = $("gonote");
  $("what").textContent = p.node ? `Adopt ${p.node}${p.node_id ? " (" + p.node_id + ")" : ""}${p.config ? " with " + p.config : ""}${pv && pv.address ? ", on " + pv.address : ""}.` : "";
  if (running) note.textContent = "Running: follow it below.";
  else if (!p.node) note.textContent = "Choose the node.";
  else if (!p.config) note.textContent = "Choose its config.";
  else if (pv && pv.refusal) note.textContent = "Fix what the check says first.";
  else if (!src.key) note.textContent = `No release key: dry runs only (${src.key_error || "import it with espdns key import: docs/getting-started.md, step 7"}).`;
  else if (fresh && manual && !$("primary-done").checked) note.textContent = "Make the changes on the zone primary by hand, then tick that they are done.";
  else if (fresh) note.textContent = `Dry run ${lastDry.id} passed for exactly this: adopt within ${Math.round(src.dry_run_valid_s / 60)} minutes of it.`;
  else if (lastDry) note.textContent = "The choices changed since the dry run, or it is too old: run it again.";
  else note.textContent = "A dry run first.";
}
setInterval(() => src && updateGo(), 15000);

async function startDry() {
  const p = params();
  try { follow(await post("api/jobs", { kind: "adopt", params: { ...p, dry_run: true } }), keyOf(p)); }
  catch (e) { await confirmDialog("Not started", [e.message], "OK", "btn"); }
}

async function startAdopt() {
  const p = params();
  const addr = pv && pv.address ? pv.address.split("/")[0] : p.node;
  const lines = [`Adopt ${p.node} (${p.node_id}) with ${p.config}, on ${pv.address}.`];
  if (pv.how === "new") lines.push(`It moves to ${addr} with a reboot, and keeps it only once it is reached there; otherwise it goes back to what it runs now within its trial window.`);
  else lines.push("It keeps the address it runs on: the config applies without a reboot.");
  if (arr(pv.zones).length) lines.push(pv.primary_api ? `The zone primary (${pv.primary_kind}, ${pv.primary_api}) allows it to transfer ${pv.zones.join(", ")} and sends it their NOTIFYs.` : "The changes on the zone primary are made by hand, as you confirmed.");
  const lab = el("label", "radio");
  const cb = el("input"); cb.type = "checkbox"; cb.checked = true;
  const n = nodeOf(p.node);
  const listed = n && n.listed;
  lab.append(cb, el("span", "", listed && addr !== p.node
    ? `Once it is adopted, change its entry in settings.json from ${p.node} to ${addr}, the address it moves to`
    : listed ? `It is in settings.json already, as ${addr}` : `Once it is adopted, add ${addr} to settings.json (rollouts then count it and change it)`));
  if (listed && addr === p.node) cb.disabled = true;
  lines.push(lab);
  if (!await confirmDialog(`Adopt ${p.node}?`, lines, "Adopt", "btn primary")) return;
  const body = { ...p, after: lastDry.id, add_to_settings: cb.checked };
  if ($("primary-done").checked && !$("done-row").hidden) body.primary_done = true;
  try { follow(await post("api/jobs", { kind: "adopt", params: body }), null); }
  catch (e) { await confirmDialog("Not started", [e.message], "OK", "btn"); }
}

let es = null, prog = null;
function follow(j, dryKey) {
  if (es) es.close();
  prog = null;
  running = j;
  $("run").hidden = false;
  $("log").textContent = "";
  $("run-outcome").replaceChildren();
  $("run-primary").replaceChildren();
  history.replaceState(null, "", `#job=${encodeURIComponent(j.id)}`);
  setRun(j);
  es = events(`api/jobs/${encodeURIComponent(j.id)}/events`);
  es.addEventListener("state", e => { const s = JSON.parse(e.data); setRun(s); if (s.progress) setProgress(s.progress); });
  es.addEventListener("progress", e => setProgress(JSON.parse(e.data)));
  es.addEventListener("log", e => {
    const l = JSON.parse(e.data);
    const pre = $("log");
    const atEnd = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
    pre.textContent += `${new Date(l.time).toLocaleTimeString()}  ${l.text}\n`;
    if (atEnd) pre.scrollTop = pre.scrollHeight;
  });
  es.addEventListener("end", e => {
    const s = JSON.parse(e.data);
    es.close(); es = null;
    setRun(s);
    if (s.progress) setProgress(s.progress);
    running = null;
    if (dryKey && s.state === "done") lastDry = { id: s.id, key: dryKey, ended: new Date(s.ended).getTime() };
    else lastDry = null; // a failed dry run, or an adoption, is done with
    if (!dryKey) { $("primary-done").checked = false; load(); }
    updateGo();
  });
  updateGo();
  $("run").scrollIntoView({ behavior: "smooth", block: "start" });
}

function setRun(j) {
  let p = {};
  try { p = JSON.parse((j.args || [])[0] || "{}") || {}; } catch { /* not JSON */ }
  $("run-title").textContent = `${p.dry_run ? "Dry run" : "Adoption"}: ${p.node || ""} · ${j.id}`;
  const st = $("run-state");
  st.textContent = j.state;
  st.className = `pill ${j.state === "failed" ? "bad" : ""}`;
  $("run-sub").textContent = `started by ${j.who}${j.started ? ", " + new Date(j.started).toLocaleString() : ""}${j.error ? " — " + j.error : ""}`;
}

function setProgress(p) { prog = p; renderRun(); }

function renderRun() {
  const p = prog;
  if (!p) return;
  $("run-steps").replaceChildren(...arr(p.steps).map(s => {
    const li = el("li", `step ${s.state}`);
    const top = el("div", "row");
    top.append(el("span", "sub", `${s.n}.`), el("strong", "", s.title), el("span", `pill ${STEP_PILL[s.state] || "warn"}`, s.state === "running" ? "running…" : s.state));
    li.append(top);
    if (s.detail) li.append(el("div", s.state === "failed" ? "bad" : "sub", s.detail));
    return li;
  }));
  const t = p.primary || {};
  const tech = [];
  if (arr(t.edits).length) {
    const tb = el("table", "mini");
    tb.append(rowOf(["Zone", t.api ? `${t.kind || "zone primary"} ${t.api}` : "Zone primary", ""]));
    tb.firstChild.querySelectorAll("td").forEach(td => td.className = "sub");
    for (const e of t.edits) {
      const what = arr(e.changes).length ? e.changes.join("; ") : `${e.addr} already in both lists`;
      tb.append(rowOf([el("span", "mono", e.zone), what, el("span", `pill ${e.applied ? "ok" : "muted"}`,
        e.applied ? "set" : arr(e.changes).length ? "would set" : "as wanted")]));
    }
    tech.push(el("h3", "", "The zone primary's lists"), tb);
  }
  if (arr(t.manual).length) {
    const d = el("div", `banner ${t.done ? "ok" : "warn"}`);
    d.append(el("strong", "", t.done ? "Made by hand (confirmed): " : "To make by hand on the zone primary: "), t.why || "");
    const ul = el("ul", "hints");
    for (const m of t.manual) ul.append(el("li", "", m));
    d.append(ul);
    tech.push(d);
    if (!t.done && p.dry_run) $("done-row").hidden = false;
  }
  $("run-primary").replaceChildren(...tech);
  const out = [];
  if (p.outcome) out.push(el("div", `banner ${/^(stopped|not started)/.test(p.outcome) ? "bad" : "ok"}`, p.outcome));
  if (arr(p.hints).length) {
    const ul = el("ul", "hints");
    for (const h of p.hints) ul.append(el("li", "", h));
    out.push(ul);
  }
  $("run-outcome").replaceChildren(...out);
}

// ---- loading ----------------------------------------------------------------------------

function renderAll() { renderNodes(); changed(); }

async function load() {
  try { src = await getJSON("api/adopt"); } catch (e) { $("banner").replaceChildren(el("div", "banner warn", e.message)); return; }
  $("form").hidden = false;
  if (form.node && !arr(src.nodes).some(n => n.host === form.node && !n.adopted)) form.node = "";
  const bans = [];
  if (!src.key) bans.push(el("div", "banner warn", `No release key: dry runs only. ${src.key_error || ""}`));
  $("banner").replaceChildren(...bans);
  renderAll();
}

$("config").onchange = e => { form.config = e.target.value; changed(); };
for (const r of document.querySelectorAll('input[name="addr"]')) r.onchange = () => { form.mode = r.value; changed(); };
$("address").oninput = e => { form.address = e.target.value; changed(); };
$("gateway").oninput = e => { form.gateway = e.target.value; changed(); };
$("reserved").onchange = e => { form.reserved = e.target.checked; changed(); };
$("primary-done").onchange = updateGo;
$("dry").onclick = startDry;
$("go").onclick = startAdopt;

session.then(s => {
  if (s.password_set && !s.logged_in) return;
  load().then(() => {
    const want = new URLSearchParams(location.hash.slice(1)).get("job");
    if (want) getJSON(`api/jobs/${encodeURIComponent(want)}`).then(j => { if (j.kind === "adopt") follow(j, null); }).catch(() => {});
  });
});
