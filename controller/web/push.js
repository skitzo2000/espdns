// The rolling push: choose what (firmware, a config per node, a blocklist, overrides or
// the hosted zones), the nodes and their order, the canary, the soak and the checks; see
// what each node would get (its /status, read-only); a dry run; then the push after it,
// followed live per node, with Stop at the next safe point. The server builds the plan the
// CLI's make fleet-rollout builds (internal/rolling) and refuses a push that isn't the
// one its dry run checked.
import { header, el, post, getJSON, session, confirmDialog, nodeLabel, nodeText, statePill, events } from "./common.js";

header("push.html");

const KINDS = [["firmware", "Firmware"], ["config", "Config"], ["blocklist", "Blocklist"], ["overrides", "Overrides"], ["zones", "Hosted zones"]];
const ACTIVE = ["gate", "pushing", "rebooting", "checking", "soaking", "reverting"];
const STATE_TEXT = {
  waiting: "waiting", gate: "checking the rule", "would-push": "would push now", pushing: "pushing", rebooting: "rebooting",
  checking: "checking", checked: "checked", soaking: "soaking", done: "done", skipped: "skipped", failed: "failed",
  left: "not touched", refused: "refused", reverting: "reverting", reverted: "reverted", "not-reverted": "not reverted",
};
// A node's state in a run: the steps plain, waiting or left muted, a revert warn, a failure bad.
const pillOf = s => ({ skipped: "muted", left: "muted", waiting: "muted", reverted: "warn",
  failed: "bad", refused: "bad", "not-reverted": "bad" })[s] || "";
const isList = k => k === "blocklist" || k === "overrides";
const arr = v => Array.isArray(v) ? v : [];
const $ = id => document.getElementById(id);

let src = null;          // /api/push/sources
const form = { kind: "firmware", nodes: [], order: [], canary: "", soak: 60, firmware: new Set(), configs: {}, file: "",
  zones: new Set(), blocked: "", must: "" };
let lastDry = null;      // {id, key, ended}: the dry run that passed, and for what
let running = null;      // the job followed

// ---- the request ------------------------------------------------------------------------

function params() {
  const p = { kind: form.kind, nodes: form.order.filter(h => form.nodes.includes(h)) };
  if (form.canary && p.nodes.includes(form.canary)) p.canary = form.canary;
  if (form.soak && form.soak !== src.soak_s) p.soak_s = form.soak;
  const blocked = form.blocked.split(/[\s,]+/).map(s => s.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean);
  if (blocked.length) p.check_blocked = [...new Set(blocked)];
  if (form.must) p.must_resolve = form.must;
  switch (form.kind) {
    case "firmware": p.firmware = [...form.firmware].sort(); break;
    case "config": p.configs = Object.fromEntries(p.nodes.map(h => [h, form.configs[h] || ""])); break;
    case "blocklist": case "overrides": p.file = form.file; break;
    case "zones": p.zones = [...form.zones].sort(); break;
  }
  return p;
}
const keyOf = p => JSON.stringify(p);
function order(p) {
  const o = p.canary ? [p.canary] : [];
  for (const h of p.nodes) if (!o.includes(h)) o.push(h);
  return o;
}

// ---- the form ---------------------------------------------------------------------------

function nodeOf(h) { return arr(src.nodes).find(n => n.host === h) || { host: h }; }

function renderKinds() {
  const box = $("kinds");
  box.replaceChildren(...KINDS.map(([k, name]) => {
    const b = el("button", "segbtn", name);
    b.type = "button";
    b.setAttribute("role", "radio");
    b.setAttribute("aria-checked", String(form.kind === k));
    b.onclick = () => { form.kind = k; renderKinds(); renderWhat(); changed(); };
    return b;
  }));
}

function fileNote(text, cls = "sub") { return el("p", cls, text); }

function renderWhat() {
  const box = $("what");
  const s = src.sources;
  const out = [];
  if (form.kind === "firmware") {
    out.push(fileNote(`One per chip image: each node gets the one for the chip image it runs. Builds of the boards are in ${s.dirs.builds}; chip images (loaded with espdns release import) in ${s.dirs.images}.`));
    if (!arr(s.firmware).length) out.push(fileNote("No firmware there yet."));
    const t = el("table", "mini pickt");
    t.append(rowOf(["", "Firmware", "Chip image", "Version · elf", "Built", "Fits"], "th"));
    for (const f of arr(s.firmware)) {
      const fits = arr(src.nodes).filter(n => n.image && n.image === f.image).map(n => nodeText(n.host));
      const cb = el("input"); cb.type = "checkbox"; cb.checked = form.firmware.has(f.source); cb.disabled = !!f.error;
      cb.setAttribute("aria-label", f.source);
      cb.onchange = () => {
        if (cb.checked) {
          // One per chip image, as the rollout picks a node's firmware by it.
          for (const o of arr(s.firmware)) if (o.image === f.image) form.firmware.delete(o.source);
          form.firmware.add(f.source);
        } else form.firmware.delete(f.source);
        renderWhat(); changed();
      };
      const name = el("div"); name.append(el("div", "mono", f.source), el("div", "sub", f.board ? `board ${f.board}` : (f.chip || "")));
      const ver = el("div"); ver.append(el("div", "", `${f.project || ""} ${f.version || ""}`.trim() || "–"), el("div", "sub mono", f.elf || ""));
      const fit = el("div", "sub", fits.length ? fits.join(", ") : "no node in settings runs it");
      const tr = rowOf([cb, name, el("span", "mono", f.image || "?"), ver, el("span", "sub", f.built || ""), fit]);
      if (f.error) { tr.classList.add("dim"); tr.lastChild.replaceChildren(el("span", "bad", f.error)); }
      t.append(tr);
    }
    out.push(scrollOf(t));
  } else if (form.kind === "config") {
    out.push(fileNote(`Each node's config from ${s.dirs.configs} (edit and check them on the Configs page). Only these nodes are changed; a config that moves a node to another address is refused here (push it from the Configs page, which confirms the new address).`));
    const t = el("table", "mini pickt");
    t.append(rowOf(["Node", "Config"], "th"));
    for (const h of form.order.filter(h => form.nodes.includes(h))) {
      const sel = el("select");
      sel.append(new Option("– choose –", ""), ...arr(s.configs).map(c => new Option(c, c)));
      sel.value = form.configs[h] || "";
      sel.setAttribute("aria-label", `config for ${h}`);
      sel.onchange = () => { form.configs[h] = sel.value; changed(); };
      t.append(rowOf([el("span", "mono", h), sel]));
    }
    if (!form.nodes.length) out.push(fileNote("Choose the nodes below first."));
    out.push(scrollOf(t));
  } else if (form.kind === "blocklist" || form.kind === "overrides") {
    out.push(fileNote(form.kind === "blocklist"
      ? `A list built by espdns blocklist … -out ${s.dirs.lists}/<name>.bin. Each node places it as it will (RAM tier, SD tier, or refused) from its board's blocking memory and the lists it holds: below, per node.`
      : `Overrides built by espdns blocklist … -xor 0 -out ${s.dirs.lists}/<name>.bin: applied live, in the RAM tier next to everything the node holds, at most 1 MB.`));
    const sel = el("select");
    sel.append(new Option("– choose –", ""), ...arr(s.lists).map(l => {
      const o = new Option(l.error ? `${l.name} (${l.error})` : `${l.name} · ${kb(l.bytes)} · ${num(l.entries)} names · xor ${l.xor_bits}`, l.name);
      o.disabled = !!l.error;
      return o;
    }));
    sel.value = form.file;
    sel.setAttribute("aria-label", "list file");
    sel.onchange = () => { form.file = sel.value; renderWhat(); changed(); };
    const lab = el("label", "pick"); lab.append("File ", sel); out.push(lab);
    const l = arr(s.lists).find(x => x.name === form.file);
    if (l) out.push(fileNote(`${l.name}: format v${l.version}, ${l.hash_bits}-bit hashes, xor filter ${l.xor_bits ? l.xor_bits + "-bit" : "none"}, ${num(l.entries)} blocked names, ${kb(l.bytes)}, modified ${new Date(l.modified).toLocaleString()}.`));
    if (!arr(s.lists).length) out.push(fileNote(`No list files in ${s.dirs.lists}.`));
  } else if (form.kind === "zones") {
    out.push(fileNote(`The hosted zones' master files in ${s.dirs.zones}, each named <zone>.zone (edit and check them on the Zones page). The set replaces each node's hosted zones: choose every zone it should serve.`));
    const t = el("table", "mini pickt");
    t.append(rowOf(["", "File", "Zone", "Serial", "Records"], "th"));
    for (const z of arr(s.zones)) {
      const cb = el("input"); cb.type = "checkbox"; cb.checked = form.zones.has(z.name); cb.disabled = !!z.error;
      cb.setAttribute("aria-label", z.name);
      cb.onchange = () => { cb.checked ? form.zones.add(z.name) : form.zones.delete(z.name); changed(); };
      const tr = rowOf([cb, el("span", "mono", z.name), z.zone || "", String(z.serial || ""), String(z.records || "")]);
      if (z.error) tr.lastChild.replaceChildren(el("span", "bad", z.error));
      t.append(tr);
    }
    if (!arr(s.zones).length) out.push(fileNote(`No zone files in ${s.dirs.zones}.`));
    out.push(scrollOf(t));
  }
  box.replaceChildren(...out);
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
function kb(n) { return n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`; }
function num(n) { return typeof n === "number" ? n.toLocaleString() : "–"; }

function renderNodes() {
  const body = $("nodes");
  const rows = form.order.map((h, i) => {
    const n = nodeOf(h);
    const cb = el("input"); cb.type = "checkbox"; cb.checked = form.nodes.includes(h);
    cb.setAttribute("aria-label", `change ${nodeText(h)}`);
    cb.onchange = () => {
      form.nodes = cb.checked ? [...form.nodes, h] : form.nodes.filter(x => x !== h);
      // The canary is chosen, never picked for you: a node left out takes it with it.
      if (!form.nodes.includes(form.canary)) form.canary = "";
      renderNodes(); renderWhat(); changed();
    };
    const who = nodeLabel(h);
    const runs = el("div"); runs.append(el("div", "", n.version ? `v${n.version}` : "–"), el("div", "sub mono", n.elf || ""));
    const st = el("div");
    st.append(statePill(n.online, n.state));
    if (arr(n.reboot).length) st.append(el("div", "sub", `reboot pending (${n.reboot.join(", ")})`));
    if (arr(n.off).length) st.append(el("div", "sub", `off: ${n.off.join(", ")}`));
    const mv = el("div", "row tight");
    const up = el("button", "btn small", "↑"), down = el("button", "btn small", "↓");
    up.type = down.type = "button";
    up.title = "earlier"; down.title = "later";
    up.setAttribute("aria-label", `move ${nodeText(h)} earlier`); down.setAttribute("aria-label", `move ${nodeText(h)} later`);
    up.disabled = i === 0; down.disabled = i === form.order.length - 1;
    const move = d => { const o = form.order; [o[i], o[i + d]] = [o[i + d], o[i]]; renderNodes(); renderWhat(); changed(); };
    up.onclick = () => move(-1); down.onclick = () => move(1);
    mv.append(up, down);
    const tr = rowOf([cb, who, `${n.board || "?"} · ${n.image || "?"}`, runs, st, mv]);
    tr.children[2].className = "wide";
    if (!form.nodes.includes(h)) tr.classList.add("dim");
    return tr;
  });
  body.replaceChildren(...(rows.length ? rows : [rowOf(["No nodes in settings.json: add them there."])]));
  const sel = $("canary");
  const chosen = form.order.filter(h => form.nodes.includes(h));
  sel.replaceChildren(new Option("– choose –", ""), ...chosen.map(h => new Option(nodeText(h), h)));
  sel.firstChild.disabled = true;
  sel.value = form.canary;
}

// ---- the preview ------------------------------------------------------------------------

let previewTimer = null, previewSeq = 0;
function changed() {
  const p = params();
  $("order").replaceChildren(...order(p).flatMap((h, i) => {
    const parts = [];
    if (i) parts.push(el("span", "sub", " → "));
    parts.push(el("span", "", nodeText(h)));
    if (i === 0 && p.canary) parts.push(el("span", "sub", " (canary)"));
    return parts;
  }));
  if (!p.nodes.length) $("order").textContent = "No nodes chosen.";
  const soak = p.soak_s || src.soak_s;
  const after = `After each node: it is in service with the change, answers its zones' SOA, resolves example.com${p.check_blocked ? ", blocks " + p.check_blocked.join(", ") : ""}${p.must_resolve ? ", and resolves the names in " + p.must_resolve : ""}.`;
  $("optnote").textContent = isList(p.kind)
    ? `${after} The canary gets the ${p.kind} first. Every node, the last one too, then soaks ${soak} s (at least ${src.soak_s} s), watched (in service, the ${p.kind} still on, no reboot, servfail and dropped queries not jumping), and is checked again before the next starts. On a failure every node that took it goes back to the ${p.kind} it had (the revert), the rollout stops and the nodes after it are not touched.`
    : `Each changed node soaks ${soak} s (at least ${src.soak_s} s) and is checked again before the next starts; the last one isn't soaked. ${after}`;
  updateGo();
  clearTimeout(previewTimer);
  previewTimer = setTimeout(preview, 350);
}

async function preview() {
  const seq = ++previewSeq;
  const box = $("preview");
  const p = params();
  if (!p.nodes.length) { box.replaceChildren(); return; }
  // Nothing chosen to push yet: say what to choose, without asking the server.
  const none = p.kind === "firmware" && !p.firmware.length ? "Choose the firmware, one per chip image."
    : (p.kind === "blocklist" || p.kind === "overrides") && !p.file ? `Choose the ${p.kind} file.`
    : p.kind === "zones" && !p.zones.length ? "Choose the zones." : "";
  if (none) { box.classList.remove("loading"); box.replaceChildren(el("p", "sub", none)); return; }
  box.classList.add("loading");
  try {
    const r = await post("api/push/preview", p);
    if (seq !== previewSeq) return;
    box.replaceChildren(...arr(r.nodes).map((n, i) => {
      const d = el("div", "pv");
      const top = el("div", "row");
      top.append(el("span", "sub", `${i + 1}`), nodeLabel(n.host, "", { inline: true }));
      if (i === 0 && p.canary) top.append(el("span", "pill", "canary"));
      top.append(el("span", "sub", [n.board, n.image].filter(Boolean).join(" · ")));
      d.append(top);
      if (n.refused) d.append(el("div", "bad", `Refused: ${n.refused}`));
      else if (n.expect) d.append(el("div", "", n.expect));
      if (n.note) d.append(el("div", "sub warn", n.note));
      return d;
    }));
  } catch (e) {
    if (seq !== previewSeq) return;
    box.replaceChildren(el("div", "banner warn", e.message));
  } finally {
    if (seq === previewSeq) box.classList.remove("loading");
  }
}

function updateGo() {
  const go = $("go"), note = $("gonote");
  const p = params();
  const fresh = lastDry && lastDry.key === keyOf(p) && Date.now() - lastDry.ended < src.dry_run_valid_s * 1000;
  const noCanary = !p.canary;
  go.disabled = !fresh || !src.key || !!running || noCanary;
  $("dry").disabled = !!running || noCanary;
  if (running) note.textContent = "A rollout is running: follow it below.";
  else if (!p.nodes.length) note.textContent = "Choose the nodes to change.";
  else if (noCanary) note.textContent = "Choose the canary, the node changed first (settings.json's \"canary\" chooses it for you).";
  else if (!src.key) note.textContent = `No release key: dry runs only (${src.key_error || "import it with espdns key import: docs/getting-started.md, step 7"}).`;
  else if (fresh) note.textContent = `Dry run ${lastDry.id} passed for exactly this push: roll out within ${Math.round(src.dry_run_valid_s / 60)} minutes of it.`;
  else if (lastDry) note.textContent = "The choices changed since the dry run, or it is too old: run it again.";
  else note.textContent = "A dry run of this push first.";
}
setInterval(() => src && updateGo(), 15000);

// ---- the run ----------------------------------------------------------------------------

async function startDry() {
  try {
    const j = await post("api/jobs", { kind: "rollout", params: { ...params(), dry_run: true } });
    follow(j, keyOf(params()));
  } catch (e) { await confirmDialog("Not started", [e.message], "OK", "btn"); }
}

async function startPush() {
  const p = params();
  const o = order(p);
  const what = { firmware: "firmware", config: "configs", blocklist: "the blocklist " + p.file, overrides: "the overrides " + p.file,
    zones: "the hosted zones " + arr(p.zones).join(", ") }[p.kind];
  const lines = [`Push ${what} to ${o.length} node${o.length > 1 ? "s" : ""}, one at a time: ${o.join(", then ")}.`,
    isList(p.kind)
      ? `Each node, the last one too, must pass its checks and a watched soak of ${p.soak_s || src.soak_s} s before the next starts; the first failure sends every node that took it back to the ${p.kind} it had and stops there, the nodes after it untouched. Stop ends it at the next safe point (no revert).`
      : `Each node must pass its checks and soak ${p.soak_s || src.soak_s} s before the next starts; the first failure stops it there, the nodes after it untouched. Stop ends it at the next safe point.`];
  if (!await confirmDialog(`Roll out ${p.kind}?`, lines, "Roll out")) return;
  try {
    const j = await post("api/jobs", { kind: "rollout", params: { ...p, after: lastDry.id } });
    follow(j, null);
  } catch (e) { await confirmDialog("Not started", [e.message], "OK", "btn"); }
}

let es = null, prog = null, job = null, tick = null;
function follow(j, dryKey) {
  if (es) es.close();
  job = j; prog = null;
  running = j;
  $("run").hidden = false;
  $("log").textContent = "";
  $("run-outcome").replaceChildren();
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
    else if (dryKey) lastDry = null;
    if (!dryKey) lastDry = null; // a push is done with its dry run
    load(false);
    updateGo();
  });
  updateGo();
  $("run").scrollIntoView({ behavior: "smooth", block: "start" });
}

function setRun(j) {
  job = j;
  let p = {};
  try { p = JSON.parse((j.args || [])[0] || "{}") || {}; } catch { /* not JSON */ }
  const dry = p.dry_run === true;
  $("run-title").textContent = `${dry ? "Dry run" : "Rollout"}: ${p.kind || ""} · ${j.id}`;
  const st = $("run-state");
  const ended = ["done", "failed", "stopped"].includes(j.state);
  st.textContent = j.stopping && !ended ? "stopping" : j.state;
  st.className = `pill ${j.state === "failed" ? "bad" : ""}`;
  $("stop").hidden = ended || j.stopping || !["queued", "running"].includes(j.state);
  $("run-sub").textContent = `started by ${j.who}${j.started ? ", " + new Date(j.started).toLocaleString() : ""}` +
    (j.stopping && !ended ? " — stopping at the next safe point: the node being changed is finished and checked first" : "") +
    (j.error ? ` — ${j.error}` : "");
}

function setProgress(p) {
  prog = p;
  renderRun();
}

function renderRun() {
  const p = prog;
  if (!p) return;
  // How it goes (the dry run says it too): the canary, the soak, what a failure does.
  const plan = $("run-plan");
  plan.hidden = !arr(p.plan).length;
  plan.replaceChildren(...arr(p.plan).map(l => el("li", "", l)));
  const body = $("run-nodes");
  body.replaceChildren(...arr(p.order).map((h, i) => {
    const n = (p.nodes || {})[h] || {};
    const st = el("div");
    let text = STATE_TEXT[n.state] || n.state;
    if (ACTIVE.includes(n.state)) text += "…";
    st.append(el("span", `pill ${pillOf(n.state)}`, text));
    if (n.state === "soaking" && n.until) {
      const left = Math.max(0, Math.round((new Date(n.until) - Date.now()) / 1000));
      st.append(el("div", "sub", `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} left`));
    }
    if (n.detail && !["soaking"].includes(n.state)) st.append(el("div", "sub", n.detail));
    if (n.revert) st.append(el("div", n.revert.startsWith("not reverted") ? "bad" : "sub", n.revert));
    const what = el("div");
    if (n.refused) what.append(el("div", "bad", n.refused));
    else if (n.expect) what.append(el("div", "", n.expect));
    if (n.note) what.append(el("div", "sub warn", n.note));
    const checks = el("div", n.checks ? "" : "sub", n.checks || (n.state === "failed" ? "" : "–"));
    const name = nodeLabel(h);
    if (i === 0 && p.canary === h) name.append(el("div", "sub", "canary"));
    return rowOf([String(i + 1), name, st, what, checks]);
  }));
  const out = [];
  if (p.outcome) {
    const bad = /failed|stopped:|not started/.test(p.outcome), stopped = p.outcome.startsWith("stopped on request");
    out.push(el("div", `banner ${bad ? "bad" : stopped ? "warn" : "ok"}`, p.outcome));
  }
  if (arr(p.left).length) {
    const d = el("div", "banner warn");
    d.append(el("strong", "", "Not touched: "), arr(p.left).join(", "));
    out.push(d);
  }
  if (arr(p.hints).length) {
    const ul = el("ul", "hints");
    for (const h of p.hints) {
      const li = el("li", "", h);
      if (/reboot pending/.test(h)) { const a = el("a", "", " Open the Nodes page."); a.href = "index.html"; li.append(a); }
      ul.append(li);
    }
    out.push(ul);
  }
  $("run-outcome").replaceChildren(...out);
}

$("stop").onclick = async () => {
  if (!job) return;
  try { setRun(await post(`api/jobs/${encodeURIComponent(job.id)}/stop`)); } catch (e) { alert(e.message); }
};
$("dry").onclick = startDry;
$("go").onclick = startPush;
$("canary").onchange = e => { form.canary = e.target.value; changed(); };
$("soak").onchange = e => { form.soak = Math.max(src.soak_s, Math.min(src.max_soak_s, Number(e.target.value) || src.soak_s)); e.target.value = form.soak; changed(); };
$("blocked").oninput = e => { form.blocked = e.target.value; changed(); };
$("must").onchange = e => { form.must = e.target.value; changed(); };
tick = setInterval(() => { if (prog && Object.values(prog.nodes || {}).some(n => n.state === "soaking")) renderRun(); }, 1000);

// ---- loading ----------------------------------------------------------------------------

// The page opened from another with what to push: #kind=zones&zones=a.zone,b.zone (the
// zone editor's "Open in Push"), #kind=blocklist&file=list.bin or #kind=overrides&file=...
// (the Blocking page's). Only files the page offers are taken; the rest are named.
let handoff = null;
function fromAddress() {
  const h = new URLSearchParams(location.hash.slice(1));
  const kind = h.get("kind");
  if ((kind === "blocklist" || kind === "overrides") && h.get("file")) {
    const file = h.get("file");
    const ok = arr(src.sources.lists).some(l => !l.error && l.name === file);
    history.replaceState(null, "", location.pathname);
    if (!ok) return el("div", "banner warn", `From the Blocking page: ${file} is not offered here (missing, or not a list file the push takes).`);
    form.kind = kind;
    form.file = file;
    return el("div", "banner ok", `From the Blocking page: ${file} chosen, pushed as ${kind}. A dry run first.`);
  }
  if (kind !== "zones" || !h.get("zones")) return null;
  const want = h.get("zones").split(",").filter(Boolean);
  const ok = arr(src.sources.zones).filter(z => !z.error && want.includes(z.name)).map(z => z.name);
  const bad = want.filter(n => !ok.includes(n));
  form.kind = "zones";
  form.zones = new Set(ok);
  history.replaceState(null, "", location.pathname);
  return el("div", `banner ${bad.length ? "warn" : "ok"}`,
    `From the zone editor: the hosted zones ${ok.join(", ") || "(none)"} chosen; the set replaces each node's hosted zones. A dry run first.` +
    (bad.length ? ` Not offered here (missing, or not passing its checks): ${bad.join(", ")}.` : ""));
}

async function load(first) {
  try {
    src = await getJSON("api/push/sources");
  } catch (e) {
    $("banner").replaceChildren(el("div", "banner warn", e.message));
    return;
  }
  $("form").hidden = false;
  if (first) {
    form.order = arr(src.nodes).map(n => n.host);
    form.nodes = [...form.order];
    // settings.json's "canary" (as the Makefile's CANARY); without one, the canary is
    // yours to choose: the first node in settings.json may be the one you least want first.
    form.canary = src.canary && form.order.includes(src.canary) ? src.canary : "";
    form.soak = src.soak_s;
    $("soak").value = form.soak;
    $("soak").min = src.soak_s; $("soak").max = src.max_soak_s;
    // Defaults: each node's matching config; the builds for the chip images the nodes run;
    // every zone; the newest list.
    for (const n of arr(src.nodes)) if (n.config) form.configs[n.host] = n.config;
    const imgs = new Set(arr(src.nodes).map(n => n.image).filter(Boolean));
    for (const img of imgs) {
      const f = arr(src.sources.firmware).find(f => !f.error && f.image === img && f.source.startsWith("builds/")) ||
        arr(src.sources.firmware).find(f => !f.error && f.image === img);
      if (f) form.firmware.add(f.source);
    }
    for (const z of arr(src.sources.zones)) if (!z.error) form.zones.add(z.name);
    const lists = arr(src.sources.lists).filter(l => !l.error).sort((a, b) => b.modified.localeCompare(a.modified));
    if (lists.length) form.file = lists[0].name;
    handoff = fromAddress();
  }
  $("peers").textContent = arr(src.dns_peers).length ? ` and the DNS peers (${src.dns_peers.join(", ")})` : " (no DNS peers in settings.json)";
  const must = $("must");
  must.replaceChildren(new Option("– none –", ""), ...arr(src.sources.must_resolve).map(m =>
    new Option(m.error ? `${m.name} (${m.error})` : `${m.name} (${m.names} names)`, m.name)));
  must.value = form.must;
  const bans = [];
  if (handoff) bans.push(handoff);
  if (!src.key) bans.push(el("div", "banner warn", `No release key: dry runs only. ${src.key_error || ""}`));
  $("banner").replaceChildren(...bans);
  renderKinds(); renderWhat(); renderNodes(); changed();
}

session.then(s => {
  if (s.password_set && !s.logged_in) return;
  load(true).then(() => {
    // A rollout named in the address (#job=<id>): followed again.
    const want = new URLSearchParams(location.hash.slice(1)).get("job");
    if (want) getJSON(`api/jobs/${encodeURIComponent(want)}`).then(j => {
      if (j.kind !== "rollout") return;
      let p = {};
      try { p = JSON.parse((j.args || [])[0] || "{}") || {}; } catch { /* not JSON */ }
      follow(j, p.dry_run ? keyOf(Object.fromEntries(Object.entries(p).filter(([k]) => k !== "dry_run"))) : null);
    }).catch(e => console.error(e));
  });
});
