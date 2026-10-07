// The config editor (configs.html): the node configs in the data directory, each edited as
// JSON with a summary beside it. Every check is the controller's (POST
// /api/configs/<name>/check: espdns config -check, the memory plan, a rollout's refusals,
// live or reboot): nothing is checked here. A push is a "config-push" job: a dry run, shown,
// then the push after it, both followed live. The Wi-Fi password never comes to the page
// unless revealed, which asks for the login password again: the text has a stand-in for
// it, which the controller puts back.
import { header, el, post, getJSON, session, releaseKey, confirmDialog, nodeText, events, askPassword } from "./common.js";

header("configs.html");

const HIDDEN = "••••••••";
const SERVICES = ["dns", "forwarding", "forward_zones", "secondary", "hosted", "blocking"];
const RUNS = {
  file: ["ok", "runs it"],
  older: ["warn", "an earlier version"],
  other: ["warn", "another config"],
  defaults: ["warn", "no pushed config"],
  unrecorded: ["warn", "not recorded here"],
  unknown: ["muted", "no configs"],
};

let sess = {}, keyInfo = null;
let list = { configs: [], nodes: [] };
let cur = null;        // {name, text, hash, password, revealed, history, isNew}
let result = null;     // the last check
let checking = 0;      // the check in flight (only the newest is shown)
let push = null;       // {node, dry: job, real: job, log: [], error}
let target = "";       // what the check runs against: "node:<addr>", "board:<name>" or ""
let boardNames = [];

const $ = id => document.getElementById(id);
const arr = v => Array.isArray(v) ? v : [];
const obj = v => v && typeof v === "object" && !Array.isArray(v) ? v : {};
const ended = s => ["done", "failed", "stopped"].includes(s);
const pillOf = s => (s === "failed" ? "bad" : "");

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

// ---- the list ---------------------------------------------------------------------

function renderList() {
  const box = $("list");
  if (!list.configs.length) {
    box.replaceChildren(el("div", "empty", "No configs yet: create one below (docs/getting-started.md, step 10)."));
    return;
  }
  box.replaceChildren(...list.configs.map(c => {
    const b = el("button", "boardrow" + (cur && cur.name === c.name ? " on" : ""));
    b.type = "button";
    const top = el("div", "top");
    top.append(el("strong", "", c.name), c.error ? el("span", "pill bad", "invalid") : el("span", "sub", c.config_name || ""));
    b.append(top);
    b.append(el("span", "sub", [c.address || "no network (the board's address)", `${arr(c.services).length} services`].join(" · ")));
    const chips = el("div", "chips");
    for (const n of arr(c.nodes)) {
      const [cls, text] = RUNS[n.runs && n.runs.state] || ["muted", "?"];
      chips.append(chip(`${nodeText(n.host)}: ${text}`, cls, n.runs ? n.runs.text : ""));
    }
    for (const n of arr(c.at_address)) {
      chips.append(chip(`${n.host}: runs ${n.name || "another config"}`, "warn",
        `On this config's address, ${n.host} reports the config name ${n.name || "(none)"}, not ${c.config_name || c.name}: it doesn't run this file, and a push of it there renames the node.`));
    }
    if (!arr(c.nodes).length) chips.append(chip("no node runs it", "info"));
    b.append(chips);
    b.onclick = () => open(c.name);
    return b;
  }));
}

async function loadList() {
  try {
    list = await getJSON("api/configs");
  } catch (e) {
    $("list").replaceChildren(el("div", "empty bad", e.message));
    return;
  }
  renderList();
}

// ---- one config -------------------------------------------------------------------

const dirty = () => cur && $("text") && $("text").value !== cur.text;

async function open(name, opts = {}) {
  if (cur && dirty() && !opts.force && !await confirmDialog(`Leave ${cur.name}?`, ["Its edits aren't saved: they are dropped."], "Drop the edits")) return;
  let headers = {};
  if (opts.reveal) { // the password again (askPassword): a session taken over can't read it
    const grant = await askPassword("Enter your login password to show the Wi-Fi password.");
    if (!grant) return;
    headers = { "X-Reauth": grant };
  }
  try {
    const c = await getJSON(`api/configs/${encodeURIComponent(name)}${opts.reveal ? "?reveal=1" : ""}`, headers);
    cur = { ...c, isNew: false };
  } catch (e) {
    $("main").replaceChildren(el("div", "banner bad", e.message));
    return;
  }
  history.replaceState(null, "", `#config=${encodeURIComponent(name)}`);
  push = null;
  result = null;
  pickTarget();
  renderMain();
  renderList();
  check();
}

// pickTarget: the check runs against the config's node if one runs it (else the one the
// page was opened for), else nothing.
function pickTarget(want) {
  const entry = list.configs.find(c => cur && c.name === cur.name);
  const ns = arr(entry && entry.nodes);
  if (want) target = `node:${want}`;
  else if (ns.length) target = `node:${(ns.find(n => n.listed) || ns[0]).host}`;
  else if (!target.startsWith("board:")) target = "";
}

function renderMain() {
  const m = $("main");
  if (!cur) { m.replaceChildren(el("div", "empty", "Choose a config.")); return; }
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
  ta.setAttribute("aria-label", `${cur.name}, JSON`);
  ta.rows = Math.min(40, Math.max(16, cur.text.split("\n").length + 2));
  let timer = 0;
  ta.addEventListener("input", () => {
    $("unsaved").hidden = !dirty();
    renderPush();
    clearTimeout(timer);
    timer = setTimeout(check, 600);
  });

  const sel = el("select");
  sel.id = "target";
  sel.setAttribute("aria-label", "Check against");
  sel.append(new Option("the config alone", ""));
  const g1 = el("optgroup");
  g1.label = "a node (its memory plan, a rollout's refusals, live or reboot)";
  for (const n of list.nodes) g1.append(new Option(`${nodeText(n.host, n.name)} (${n.host})${n.listed ? "" : ", mDNS only"}`, `node:${n.host}`));
  const g2 = el("optgroup");
  g2.label = "a catalog board (its memory plan, as -check -board)";
  for (const b of boardNames) g2.append(new Option(b, `board:${b}`));
  sel.append(g1, g2);
  sel.value = target;
  sel.onchange = () => { target = sel.value; check(); };

  const ck = el("button", "btn", "Check");
  ck.type = "button";
  ck.onclick = check;
  const save = el("button", "btn primary", cur.isNew ? "Create…" : "Save…");
  save.type = "button";
  save.id = "save";
  save.onclick = saveDialog;
  const revert = el("button", "btn quiet", "Revert");
  revert.type = "button";
  revert.onclick = () => cur.isNew ? null : open(cur.name, { force: true });
  const bar = el("div", "acts");
  const lab = el("label", "inline", "Check against ");
  lab.append(sel);
  bar.append(lab, ck, save, revert);
  if (cur.password && !cur.revealed && !cur.isNew) {
    const rv = el("button", "btn quiet small", "Show the Wi-Fi password");
    rv.type = "button";
    rv.title = `The text has ${HIDDEN} in its place, which a check or save keeps as saved`;
    rv.onclick = () => open(cur.name, { reveal: true });
    bar.append(rv);
  }

  const notes = el("div", "sub");
  if (cur.password && cur.isNew) notes.append(`A copy: type the Wi-Fi password in place of ${HIDDEN} (a new config has no saved one to keep). `);
  else if (cur.password && !cur.revealed) notes.append(`The Wi-Fi password shows as ${HIDDEN}: leave it so to keep the saved one, or type a new one. `);
  if (arr(cur.history).length) notes.append(`${cur.history.length} earlier version(s) kept in configs/.history/ (the newest ${new Date(cur.history[0].time).toLocaleString()}).`);

  const out = el("div", "cfgresult");
  out.id = "result";
  const pushBox = el("div");
  pushBox.id = "push";
  m.replaceChildren(head, bar, notes, el("div", "cfgedit"), pushBox);
  const edit = m.querySelector(".cfgedit");
  edit.append(ta, out);
  renderResult();
  renderPush();
}

// ---- the check --------------------------------------------------------------------

async function check() {
  if (!cur) return;
  const n = ++checking;
  const [kind, val] = target ? [target.slice(0, target.indexOf(":")), target.slice(target.indexOf(":") + 1)] : ["", ""];
  try {
    const r = await post(`api/configs/${encodeURIComponent(cur.name)}/check`, {
      text: $("text").value, board: kind === "board" ? val : "", node: kind === "node" ? val : "",
    });
    if (n !== checking) return;
    result = r;
  } catch (e) {
    if (n !== checking) return;
    result = { ok: false, error: e.message, request: true };
  }
  renderResult();
}

function kb(v) { return typeof v === "number" ? `${v} KB` : "–"; }

function bar(used, total, label) {
  const w = el("div", "barwrap");
  const b = el("div", "bar"), f = el("div", "fill");
  const pct = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
  f.style.width = `${pct}%`;
  if (used > total) f.classList.add("high");
  b.append(f);
  w.append(b, el("span", "sub", label));
  return w;
}

function list_(v, none) {
  return arr(v).length ? arr(v).join(", ") : none;
}

// summary is the config's settings in words: what a key left out means is the board's or
// the firmware's.
function summary(c, r) {
  const net = obj(c.network), wifi = obj(c.wifi), sec = obj(c.secondary), time = obj(c.time), blk = obj(c.blocking);
  const cpu = obj(c.cpu);
  const lower = "the board's or firmware's";
  const fz = arr(c.forward_zones);
  const svc = el("div", "chips");
  for (const s of SERVICES) svc.append(chip(s, arr(r.services).includes(s) ? "ok" : "muted", arr(r.services).includes(s) ? "on" : "off"));
  return facts([
    ["Name", c.name || "–"],
    ["Network", c.network ? net.address === "dhcp" ? "DHCP" : `${net.address} via ${net.gateway}` : `${lower} address`],
    ["Wi-Fi", c.wifi ? [
      wifi.ssid !== undefined ? `network ${wifi.ssid}` : "the network saved over USB",
      wifi.password === undefined ? "" : wifi.password === "" ? "open" : wifi.password === HIDDEN ? "password set (hidden)" : "password set",
      wifi.tx_power_dbm !== undefined ? `${wifi.tx_power_dbm} dBm` : "",
      wifi.power_save !== undefined ? `power save ${wifi.power_save ? "on" : "off"}` : "",
    ].filter(Boolean).join(", ") : "–"],
    ["Forwarders", c.forwarders === undefined ? `${lower}` : list_(c.forwarders, "none: forwarding off")],
    ["Upstream timeout", c.upstream_timeout_ms !== undefined ? `${c.upstream_timeout_ms} ms` : lower],
    ["Forward zones", c.forward_zones === undefined ? lower : fz.length ? fz.map(z => `${z.zone} → ${z.forwarder}`).join(", ") : "none"],
    ["Secondary", c.secondary ? [
      sec.primary ? `primary ${sec.primary}` : "",
      sec.zones !== undefined ? `zones: ${list_(sec.zones, "none")}` : "",
      sec.soa_poll_s !== undefined ? `SOA poll ${sec.soa_poll_s} s` : "", sec.retry_s !== undefined ? `retry ${sec.retry_s} s` : "",
    ].filter(Boolean).join("; ") || lower : lower],
    ["Services", svc],
    ["Time", c.time ? [time.ntp !== undefined ? `NTP ${list_(time.ntp, "none (the gateway, then pool.ntp.org)")}` : "",
      time.tz ? `TZ ${time.tz}` : ""].filter(Boolean).join("; ") || lower : lower],
    ["Blocking", c.blocking ? [blk.enabled === false ? "off" : "on", blk.answer ? `answer ${blk.answer}` : "", blk.ttl !== undefined ? `TTL ${blk.ttl} s` : ""]
      .filter(Boolean).join(", ") : "on, the firmware's answer and TTL"],
    ["Clock scaling", cpu.dfs !== undefined ? (cpu.dfs ? "on" : "off") : `${lower} (cpu left out)`],
  ]);
}

function renderResult() {
  const box = $("result");
  if (!box) return;
  const r = result;
  if (!r) { box.replaceChildren(el("div", "empty", "Checking…")); return; }
  const out = [];
  if (r.error) {
    out.push(el("div", "banner bad", r.request ? r.error : `Refused: ${r.error}`));
  } else {
    const n = obj(r.node);
    const fine = r.ok ? `Passes: ${r.bytes} bytes${n.host ? `, and ${nodeText(n.host)} takes it` : ""}.` : "Doesn't pass: see below.";
    out.push(el("div", `banner ${r.ok ? "ok" : "bad"}`, fine));
    if (n.refusal) out.push(el("div", "banner bad", `A rollout refuses it for ${nodeText(n.host)}: ${n.refusal}`));
    if (n.address) out.push(el("div", "banner bad", `A push refuses its address for ${nodeText(n.host)}: ${n.address}`));
  }
  const sects = el("div", "sects one");
  if (r.config) sects.append(section("Summary", summary(r.config, r)));
  for (const mem of arr(r.memory)) {
    const rows = [["From", mem.from]];
    if (mem.error) rows.push(["Doesn't fit", mem.error, "bad"]);
    if (arr(mem.internal_kb).length) rows.push(["Internal RAM", bar(mem.internal_kb[0], mem.internal_kb[1], `${kb(mem.internal_kb[0])} of ${kb(mem.internal_kb[1])}`)]);
    if (arr(mem.psram_kb).length && mem.psram_kb[1] > 0) rows.push(["PSRAM", bar(mem.psram_kb[0], mem.psram_kb[1], `${kb(mem.psram_kb[0])} of ${kb(mem.psram_kb[1])}`)]);
    const shares = Object.entries(obj(mem.shares_kb)).map(([s, v]) => `${s} ${v[0]}+${v[1]}`).join(", ");
    if (shares) rows.push(["Per service (KB, internal+PSRAM)", shares]);
    sects.append(section(`Memory plan on ${mem.board} ${mem.fits ? "✓" : "✗"}`, facts(rows)));
  }
  for (const c of arr(r.cpu)) {
    sects.append(section(`Clock on ${c.on}`, facts([
      ["Scaling", c.known ? (c.dfs ? "on" : "off") : "the default (only the node knows)"],
      ["From", c.from],
      ["Clock / idle", c.max_mhz ? `${c.max_mhz} / ${c.min_mhz} MHz` : "–"],
    ])));
  }
  if (r.node) {
    const n = r.node, ch = obj(n.change), runs = obj(n.running);
    const [cls] = RUNS[runs.state] || ["muted"];
    const rows = [["Runs", runs.text || "–", cls]];
    if (runs.assumed) rows.push(["Compared with", "the file as saved (what the node runs isn't recorded here)", "warn"]);
    rows.push(["Applies live", list_(ch.live, "nothing")]);
    rows.push(["Needs a reboot", list_(ch.reboot, "no")]);
    if (arr(ch.maybe).length) rows.push(["May need a reboot", `${ch.maybe.join(", ")} (unless the board's or firmware's value is the same)`, "warn"]);
    if (n.moves) rows.push(["Moves the node", `to ${n.moves}: the push reboots it there (coordinated) and confirms it before its trial ends`, "warn"]);
    if (arr(n.pending).length) rows.push(["Already waits for a reboot", n.pending.join(", "), "warn"]);
    sects.append(section(`On ${nodeText(n.host)}`, facts(rows),
      arr(ch.reboot).length || arr(ch.maybe).length
        ? el("p", "sub", "The node keeps serving on what it runs and waits; the push reboots it only while another node or a DNS peer answers, then checks it.") : null));
  }
  if (r.payload) {
    const d = el("details");
    d.append(el("summary", "", `Payload (${r.bytes} bytes, as the node gets it)`), el("pre", "raw", r.payload));
    sects.append(d);
  }
  out.push(sects);
  if (arr(r.diff).length) out.push(diffView(r.diff, "Changes against the saved file"));
  else if (cur && !cur.isNew && !r.request) out.push(el("p", "sub", "Same as the saved file."));
  box.replaceChildren(...out);
}

function diffView(lines, title) {
  const wrap = el("div", "diffwrap");
  wrap.append(el("h3", "", title));
  const pre = el("pre", "diff");
  for (const l of arr(lines)) {
    const d = el("div", l.op === "+" ? "add" : l.op === "-" ? "del" : "same", `${l.op} ${l.text}`);
    pre.append(d);
  }
  wrap.append(pre);
  return wrap;
}

// ---- save ---------------------------------------------------------------------------

async function saveDialog() {
  await check();
  const r = result || {};
  if (r.error) { await confirmDialog("Not saved", [`The config doesn't pass its own checks: ${r.error}`], "OK", "btn"); return; }
  if (!cur.isNew && !arr(r.diff).length) { await confirmDialog("Nothing to save", ["The text is the same as the saved file."], "OK", "btn"); return; }
  const lines = [];
  if (!r.ok) lines.push(el("p", "bad", "It passes its own checks, but not against the node or board checked: it can be saved, a push will be refused until it does."));
  if (arr(r.diff).length) lines.push(diffView(r.diff, "What changes in the file"));
  else lines.push(`A new file, ${cur.name}.`);
  lines.push("The version before is kept in configs/.history/. Saving doesn't push it.");
  if (!await confirmDialog(`Save ${cur.name}?`, lines, "Save", "btn primary")) return;
  try {
    const s = await post(`api/configs/${encodeURIComponent(cur.name)}`, { text: $("text").value, hash: cur.isNew ? "" : cur.hash });
    cur = { ...cur, text: s.text, hash: s.hash, modified: s.modified, isNew: false, revealed: false };
    await loadList();
    await open(cur.name, { force: true });
  } catch (e) {
    await confirmDialog("Not saved", [e.message], "OK", "btn");
  }
}

// ---- push ---------------------------------------------------------------------------

function listedNodes() {
  return list.nodes.filter(n => n.listed);
}

function renderPush() {
  const box = $("push");
  if (!box || !cur) return;
  const s = el("div", "sect pushsect");
  s.append(el("h3", "", "Push to a node"));
  let why = "";
  if (!sess.logged_in) why = "Log in to push.";
  else if (cur.isNew) why = "Save it first: a push sends the saved file.";
  else if (dirty()) why = "Save the edits first: a push sends the saved file.";
  else if (!listedNodes().length) why = "No node in settings.json: configs are pushed only to the nodes listed there.";
  const busy = push && [push.dry, push.real].some(j => j && !ended(j.state));
  const sel = el("select");
  sel.setAttribute("aria-label", "The node to push to");
  const entry = list.configs.find(c => c.name === cur.name);
  const mine = arr(entry && entry.nodes).filter(n => n.listed).map(n => n.host);
  for (const n of listedNodes()) sel.append(new Option(`${nodeText(n.host, n.name || n.host)} (${n.host})${mine.includes(n.host) ? "" : " — not this config's node"}`, n.host));
  sel.value = push ? push.node : mine[0] || (listedNodes()[0] || {}).host || "";
  sel.disabled = Boolean(why) || busy;
  const dry = el("button", "btn", "Dry run");
  dry.type = "button";
  dry.disabled = Boolean(why) || busy;
  dry.onclick = () => startDry(sel.value);
  const row = el("div", "acts");
  row.append(sel, dry);
  s.append(row);
  s.append(el("p", "sub", why || "The dry run checks the config against the node and the rule (another node or a DNS peer answering), and pushes nothing. Then push: live where it can, else with a coordinated reboot, then the node's checks. As espdns rollout -kind config."));
  if (!why && keyInfo && !keyInfo.present) s.append(el("p", "sub warn", "No release key: a dry run works, a push doesn't (espdns key import: docs/getting-started.md, step 7)."));
  if (push) {
    for (const [what, j] of [["Dry run", push.dry], ["Push", push.real]]) {
      if (!j) continue;
      const line = el("div", "act");
      const state = j.stopping && !ended(j.state) ? "stopping" : j.state;
      line.append(el("span", `pill ${pillOf(j.state)}`, `${what} · ${state}`), " ");
      if (ended(j.state) && j.error) line.append(el("span", j.state === "failed" ? "bad" : "", j.error), " ");
      const a = el("a", "", "job");
      a.href = `jobs.html#job=${encodeURIComponent(j.id)}`;
      line.append(a);
      s.append(line);
    }
    if (push.error) s.append(el("div", "banner bad", push.error));
    const pre = el("pre", "", push.log.join("\n"));
    pre.id = "log";
    s.append(pre);
    requestAnimationFrame(() => { pre.scrollTop = pre.scrollHeight; });
    if (push.dry && push.dry.state === "done" && !push.real && !dirty()) {
      const go = el("button", "btn danger", `Push to ${push.node}`);
      go.type = "button";
      go.onclick = confirmPush;
      s.append(el("div", "acts"));
      s.lastChild.append(go, el("span", "sub", "The dry run passed."));
    }
  }
  box.replaceChildren(s);
}

function follow(job, which) {
  const es = events(`api/jobs/${encodeURIComponent(job.id)}/events`);
  const mine = () => push && push[which] && push[which].id === job.id;
  es.addEventListener("state", e => { if (!mine()) { es.close(); return; } push[which] = JSON.parse(e.data); renderPush(); });
  es.addEventListener("log", e => {
    if (!mine()) { es.close(); return; }
    const l = JSON.parse(e.data);
    push.log.push(`${new Date(l.time).toLocaleTimeString()}  ${l.text}`);
    const pre = $("log");
    if (pre) { pre.textContent = push.log.join("\n"); pre.scrollTop = pre.scrollHeight; }
  });
  es.addEventListener("end", e => {
    es.close();
    if (!mine()) return;
    push[which] = JSON.parse(e.data);
    renderPush();
    // The node list polls /status every 10 s: again once it has the node as it is now.
    if (which === "real") { loadList().then(() => check()); setTimeout(() => { if (!dirty()) loadList().then(() => check()); }, 11000); }
  });
}

async function startDry(node) {
  push = { node, dry: null, real: null, log: [], error: "" };
  renderPush();
  try {
    push.dry = await post("api/jobs", { kind: "config-push", params: { node, config: cur.name, dry_run: true } });
    follow(push.dry, "dry");
  } catch (e) { push.error = e.message; }
  renderPush();
}

async function confirmPush() {
  const r = obj(result), n = obj(r.node), ch = obj(n.change);
  const lines = [`${cur.name} goes to ${push.node}, signed with the release key${keyInfo && keyInfo.fingerprint ? ` ${keyInfo.fingerprint}` : ""}.`];
  if (n.host === push.node) {
    if (obj(n.running).assumed) lines.push("What the node runs isn't recorded here, so whether this applies live isn't known until the node says: if it waits for a reboot, it is rebooted coordinated, only while another node or a DNS peer answers.");
    if (arr(ch.live).length) lines.push(`Applies live: ${ch.live.join(", ")}.`);
    if (arr(ch.reboot).length || arr(ch.maybe).length) lines.push(`Needs a reboot (${[...arr(ch.reboot), ...arr(ch.maybe)].join(", ")}): the node waits, and is rebooted only while another node or a DNS peer answers; clients asking it get no answer while it reboots.`);
    if (n.moves) lines.push(`It moves the node to ${n.moves}: it comes up there on trial and keeps the config only once reached there. settings.json keeps the old address until you change it.`);
  }
  lines.push("Then the node's checks: healthy, the config seq applied, DNS answering.");
  if (!await confirmDialog(`Push ${cur.name} to ${push.node}?`, lines, "Push")) return;
  try {
    push.real = await post("api/jobs", { kind: "config-push", params: { node: push.node, config: cur.name, after: push.dry.id } });
    push.log.push("", "---- push ----");
    follow(push.real, "real");
  } catch (e) { push.error = e.message; }
  renderPush();
}

// ---- a new config -------------------------------------------------------------------

// A name refused once is checked again at the next submit: the message goes with the edit,
// or the form would never submit again.
$("newname").addEventListener("input", () => $("newname").setCustomValidity(""));
$("new").addEventListener("submit", async e => {
  e.preventDefault();
  const name = $("newname").value.trim();
  if (!/^[a-z0-9][a-z0-9._-]*\.json$/.test(name)) { $("newname").setCustomValidity("<name>.json: lowercase letters, digits, '.', '_' and '-'"); $("newname").reportValidity(); return; }
  $("newname").setCustomValidity("");
  if (list.configs.some(c => c.name === name)) { open(name); return; }
  if (cur && dirty() && !await confirmDialog(`Leave ${cur.name}?`, ["Its edits aren't saved: they are dropped."], "Drop the edits")) return;
  const base = $("newcopy").checked && cur ? $("text").value : `{\n  "name": "${name.replace(/\.json$/, "")}"\n}\n`;
  cur = { name, text: base, hash: "", password: cur && $("newcopy").checked ? cur.password : false, history: [], isNew: true };
  // A copy keeps the stand-in: it has no saved password to put back, so the check and the
  // save refuse it until the password is typed (blanking it would make an open network).
  history.replaceState(null, "", `#config=${encodeURIComponent(name)}`);
  push = null;
  result = null;
  target = "";
  renderMain();
  renderList();
  check();
});

window.addEventListener("beforeunload", e => { if (dirty()) e.preventDefault(); });

// ---- start --------------------------------------------------------------------------

async function start() {
  sess = await session;
  if (!sess.logged_in) {
    $("list").replaceChildren(el("div", "empty", sess.password_set ? "Log in to see the configs." : "The node configs need a login (they can hold a Wi-Fi password), and no password is set: espdns passwd: docs/getting-started.md, step 6."));
    $("main").replaceChildren();
    $("new").hidden = true;
    return;
  }
  releaseKey().then(k => { keyInfo = k; renderPush(); });
  try {
    const bs = await getJSON("api/boards");
    boardNames = arr(bs).filter(b => b.source === "catalog").map(b => obj(b.board).name).filter(Boolean).sort();
  } catch { /* no boards to check on: the nodes still are */ }
  await loadList();
  const h = new URLSearchParams(location.hash.slice(1));
  const node = h.get("node"), name = h.get("config");
  if (name) return open(name);
  if (node) {
    const n = list.nodes.find(x => x.host === node);
    if (n && n.config) { await open(n.config); pickTarget(node); renderMain(); return check(); }
  }
  if (list.configs.length) open(list.configs[0].name);
}

start();
setInterval(() => { if (!dirty()) loadList(); }, 15000);
