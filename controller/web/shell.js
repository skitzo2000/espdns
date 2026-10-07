// The shell every page of the redesign shares (docs/plan.md, The GUI redesign and The
// prototype; shell.css): the top bar (Nodes · Zones · Blocking · Query log, the changes
// waiting to apply, the account), the band of what's wrong across the fleet, and the parts
// the pages are built from: the slide-out panel, the copyable address, the node's LED as a
// dot and the toast. The pending changes are collected by the pages (POST /api/changes,
// /api/updates) and sent by one Apply from the header's panel (the apply job, apply.go).
// Zones, Blocking and Query log open the older pages until theirs are built.
// Everything from a node or the controller is put in as text.
import { api, getJSON, post, session, events, el, loggedIn, onNodes, watchNodes, every, answering, wired, ended, nodeText } from "./common.js";

const PAGES = [["index.html", "Nodes"], ["zones.html", "Zones"], ["blocklists.html", "Blocking"], ["querylog.html", "Query log"]];
const SVG = "http://www.w3.org/2000/svg";
export const arr = v => (Array.isArray(v) ? v : []);
export const obj = v => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
export const str = v => (typeof v === "string" ? v : "");
export const hostOnly = a => str(a).replace(/:\d+$/, "");

// h makes an element: attrs are its class ("class"), handlers ("on" + event: a function)
// and attributes; children are elements, strings (as text) or nothing (null, false).
export function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else if (k in e && typeof v !== "string") e[k] = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) e.append(c);
  return e;
}

// icon draws one of the few line icons: copy, x.
const ICONS = {
  copy: [16, ["rect", { x: 5, y: 5, width: 9, height: 9, rx: 1.5 }], ["path", { d: "M11 3.5V3a1 1 0 0 0-1-1H3a1 1 0 0 0-1 1v7a1 1 0 0 0 1 1h.5" }]],
  x: [14, ["path", { d: "M2 2l10 10M12 2L2 12", "stroke-linecap": "round" }]],
};
function icon(name) {
  const [size, ...parts] = ICONS[name];
  const s = document.createElementNS(SVG, "svg");
  for (const [k, v] of Object.entries({ width: 14, height: 14, viewBox: `0 0 ${size} ${size}`, "aria-hidden": "true", fill: "none", stroke: "currentColor", "stroke-width": name === "x" ? 1.8 : 1.5 })) s.setAttribute(k, v);
  for (const [tag, at] of parts) {
    const p = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(at)) p.setAttribute(k, v);
    s.append(p);
  }
  return s;
}

// ---- the node's LED ---------------------------------------------------------------------
// The board's RGB LED as a plain dot, with the colours and rhythms of firmware led.c; its
// title spells out the pattern.
const LEDTXT = {
  healthy: "Its light: a green blip every 5 s (healthy)",
  degraded: "Its light: two amber blinks every 2 s (degraded)",
  fault: "Its light: solid red (fault) or slow red (no network)",
  nonet: "Its light: slow red blink (no network)",
  booting: "Its light: fast blue blink (starting)",
  updating: "Its light: three quick blue blinks (updating)",
  identify: "Its light: white flicker (identify)",
  unknown: "Old firmware: its light doesn't follow espDNS's patterns yet",
};
export function led(kind) {
  const k = Object.hasOwn(LEDTXT, kind) ? kind : "unknown";
  return h("span", { class: `led ${k}`, role: "img", title: LEDTXT[k], "aria-label": LEDTXT[k] });
}

// ---- copying ----------------------------------------------------------------------------
// copyText puts text on the clipboard: the Clipboard API where the page may use it (https,
// or localhost), else the older copy command (the controller is often on plain http).
export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
  } catch { /* the fallback below */ }
  const t = h("textarea", { class: "offscreen", readonly: true, "aria-hidden": "true" });
  t.value = text;
  document.body.append(t);
  t.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  t.remove();
  return ok;
}

// copyable is text with a copy button: what the button names (what), and the box's class.
function copyable(text, what, cls) {
  const b = h("button", { class: "cp", type: "button", title: "Copy", "aria-label": `Copy ${what}` }, icon("copy"));
  b.addEventListener("click", async e => {
    e.preventDefault();
    e.stopPropagation();
    toast(await copyText(text) ? `Copied ${what}` : `Couldn't copy: select ${text} and copy it`);
  });
  return h("span", { class: cls }, h("span", { class: "ip" }, text), b);
}

// addr is an address shown prominently, with a copy button.
export function addr(ip) { return copyable(ip, ip, "ipc"); }

// MACHINT says what a node's MAC is for.
export const MACHINT = "For a DHCP reservation in your router, or to set a static address.";

// mac is a node's MAC (its interface's, from /api/nodes or /api/nodes/found), smaller than
// an address, with a copy button; null for none.
export function mac(m) {
  if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(str(m))) return null;
  const c = copyable(m, `MAC ${m}`, "ipc mac");
  c.title = MACHINT;
  c.prepend(h("span", { class: "k" }, "MAC"));
  return c;
}

// ---- the toast --------------------------------------------------------------------------
let toastTimer = null;
export function toast(msg) {
  const old = document.getElementById("toast");
  if (old) old.remove();
  clearTimeout(toastTimer);
  if (!msg) return;
  const d = h("div", { class: "toast", id: "toast", role: "status" }, h("span", {}, msg));
  if (pending.changes.length) d.append(h("button", { type: "button", onclick: () => { toast(""); openReview(); } }, "Review"));
  document.body.append(d);
  toastTimer = setTimeout(() => d.remove(), 6000);
}

// ---- the slide-out panel ----------------------------------------------------------------
// panel opens a slide-out panel: straight-edged, full height (a bottom sheet on a phone),
// closed by its x, Esc or a click outside. It returns {body, footer, title, close}; the
// caller fills body and footer. onClose hears it close. One is open at a time.
let openOne = null;
export function panel(title, onClose) {
  if (openOne) openOne.close();
  const back = document.activeElement;
  const h2 = h("h2", { id: "panel-title" }, title);
  const x = h("button", { class: "x", type: "button", "aria-label": "Close" }, icon("x"));
  const body = h("div", { class: "body" });
  const footer = h("footer", {});
  const aside = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "panel-title" },
    h("header", {}, h2, x), body, footer);
  const scrim = h("div", { class: "scrim" });
  const key = e => { if (e.key === "Escape") { e.preventDefault(); p.close(); } };
  const p = {
    body, footer, aside,
    title: t => { h2.textContent = t; },
    close: () => {
      if (openOne !== p) return;
      openOne = null;
      document.removeEventListener("keydown", key);
      aside.remove(); scrim.remove();
      if (back && back.isConnected) back.focus();
      if (onClose) onClose();
    },
  };
  x.addEventListener("click", p.close);
  scrim.addEventListener("click", p.close);
  document.addEventListener("keydown", key);
  document.body.append(scrim, aside);
  openOne = p;
  x.focus();
  return p;
}

// ---- the pending changes and the apply --------------------------------------------------
const pending = { changes: [], restarts: [], apply: null, read: false, error: null, listeners: new Set() };
const follow = { id: null, job: null, progress: null, es: null };
let changesBox = null, canWrite = false;

// onChanges calls f({changes, restarts, apply}) after every read of /api/changes.
export function onChanges(f) { pending.listeners.add(f); if (pending.read) f(pending); }

// refreshChanges reads /api/changes now (after a page added one).
export async function refreshChanges() {
  try {
    const r = await getJSON("api/changes");
    pending.changes = arr(r.changes);
    pending.restarts = arr(r.restarts);
    pending.apply = r.apply && typeof r.apply === "object" ? r.apply : null;
    pending.error = null;
  } catch (e) {
    pending.error = e;
  }
  pending.read = true;
  if (pending.apply && !ended(pending.apply.state) && follow.id !== pending.apply.id) followApply(pending.apply);
  // The apply followed has ended though its events didn't say so (the stream dropped): take
  // the controller's word for it.
  else if (pending.apply && follow.id === pending.apply.id && ended(pending.apply.state) && follow.job && !ended(follow.job.state)) {
    if (follow.es) { follow.es.close(); follow.es = null; }
    follow.job = pending.apply;
    if (pending.apply.progress) follow.progress = pending.apply.progress;
    if (applyView) applyView();
  }
  renderChip();
  for (const f of pending.listeners) { try { f(pending); } catch (e) { console.error(e); } }
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const applying = () => follow.job && !ended(follow.job.state);

// The step an apply is on, in words, for the chip: the node being sent to while it pushes.
const STEP = { check: "checking", write: "writing", compile: "compiling", "dry run": "trying it", push: "sending" };
function applyWhere() {
  const p = obj(follow.progress);
  for (const r of arr(p.rollouts)) {
    for (const host of arr(r.order)) {
      const st = obj(obj(r.nodes)[host]).state;
      if (["pushing", "rebooting", "checking", "soaking"].includes(st)) return nodeText(host);
    }
  }
  const s = arr(p.steps).find(x => x.state === "running");
  return s ? STEP[s.name] || s.name : "";
}

function renderChip() {
  if (!changesBox) return;
  if (applying()) {
    const w = applyWhere();
    changesBox.replaceChildren(h("button", { class: "chip-btn running", type: "button", onclick: openApply },
      h("span", { class: "spin", "aria-hidden": "true" }), w ? `Applying · ${w}` : "Applying"));
  } else if (pending.changes.length) {
    changesBox.replaceChildren(h("button", { class: "chip-btn pending", type: "button", onclick: openReview },
      `${plural(pending.changes.length, "change", "changes")} to apply`));
  } else changesBox.replaceChildren();
}

// The rollout options: which node goes first, how long each is watched (the apply's
// params); the first is settings.json's canary until one is chosen.
const rollout = { first: "", soak: 60, read: false };
async function readRollout() {
  if (rollout.read) return;
  try { rollout.first = str(obj((await getJSON("api/settings")).settings).canary); rollout.read = true; } catch { /* the first listed */ }
}
const listedNodes = () => arr(fleetNodes).filter(n => n.source === "settings");

function rolloutRow() {
  const ns = listedNodes();
  if (!rollout.first || !ns.some(n => n.addr === rollout.first)) rollout.first = ns.length ? ns[0].addr : "";
  const val = h("span", { class: "val" });
  const say = () => {
    val.textContent = `${rollout.first ? `${nodeText(rollout.first)} first · ` : ""}watched ${rollout.soak / 60} min each`;
  };
  const first = h("select", { class: "t", id: "ro-first", onchange: e => { rollout.first = e.target.value; say(); } },
    ns.map(n => h("option", { value: n.addr, selected: n.addr === rollout.first }, nodeText(n))));
  const watch = h("select", { class: "t", id: "ro-watch", onchange: e => { rollout.soak = Number(e.target.value); say(); } },
    [[60, "1 minute"], [300, "5 minutes"], [900, "15 minutes"]].map(([v, t]) => h("option", { value: String(v), selected: v === rollout.soak }, t)));
  say();
  return h("details", { class: "ex" }, h("summary", {}, h("b", {}, "How it rolls out"), val),
    h("div", { class: "exb" },
      h("p", { class: "small" }, "One node at a time: each is checked and watched before the next. If a node fails its checks, the apply stops there and the changes keep waiting."),
      h("div", { class: "grid2" },
        ns.length ? h("label", { class: "f" }, h("span", {}, "Start with"), first) : null,
        h("label", { class: "f" }, h("span", {}, "Watch each node for"), watch))));
}

function openReview() {
  if (applying()) { openApply(); return; }
  const p = panel("Changes to apply");
  const list = h("div", {});
  const note = h("p", { class: "small" });
  const msg = h("p", { class: "hint bad", role: "status" });
  const discardAll = h("button", { class: "btn", type: "button" }, "Discard all");
  const go = h("button", { class: "btn primary", type: "button" });
  const fill = () => {
    if (!pending.changes.length) { p.close(); return; }
    list.replaceChildren(...pending.changes.map(c => {
      const b = h("button", { class: "btn small", type: "button", disabled: !canWrite }, "Discard");
      b.addEventListener("click", () => act(b, () => post(`api/changes/${encodeURIComponent(c.id)}/discard`)));
      return h("div", { class: "change" }, h("div", {}, str(c.summary) || str(c.name) || str(c.kind), h("div", { class: "hint" }, str(c.effect))), b);
    }));
    const rs = pending.restarts.map(x => nodeText(x));
    note.textContent = rs.length
      ? `${rs.join(", ")} restart${rs.length === 1 ? "s" : ""} for a few seconds, one at a time; the other nodes keep answering.`
      : "No restart needed: DNS keeps answering throughout.";
    go.textContent = `Apply ${plural(pending.changes.length, "change", "changes")}`;
    go.disabled = discardAll.disabled = !canWrite;
  };
  async function act(btn, f) {
    btn.disabled = true;
    msg.textContent = "";
    try { await f(); await refreshChanges(); fill(); } catch (e) { msg.textContent = e.message; btn.disabled = false; }
  }
  discardAll.addEventListener("click", () => act(discardAll, () => post("api/changes/discard")));
  go.addEventListener("click", async () => {
    go.disabled = true;
    msg.textContent = "";
    try {
      const params = { soak_s: rollout.soak };
      if (rollout.first) params.canary = rollout.first;
      startApply(await post("api/jobs", { kind: "apply", params }));
    } catch (e) { msg.textContent = e.message; go.disabled = false; }
  });
  p.body.append(list, note, msg);
  p.footer.append(discardAll, go);
  fill();
  // The row now, with the first listed node; again once settings.json's canary is read.
  let row = rolloutRow();
  note.after(row);
  readRollout().then(() => {
    if (openOne !== p || !row.isConnected) return;
    const again = rolloutRow();
    again.open = row.open;
    row.replaceWith(again);
    row = again;
  });
}

function startApply(j) {
  followApply(j);
  openApply();
}

// followApply follows an apply's progress (its events) while it runs.
function followApply(j) {
  if (follow.es) follow.es.close();
  follow.id = j.id;
  follow.job = j;
  follow.progress = j.progress ? j.progress : null;
  const es = events(`api/jobs/${encodeURIComponent(j.id)}/events`);
  follow.es = es;
  const upd = () => { renderChip(); if (applyView) applyView(); };
  es.addEventListener("state", e => { const s = JSON.parse(e.data); follow.job = s; if (s.progress) follow.progress = s.progress; upd(); });
  es.addEventListener("progress", e => { follow.progress = JSON.parse(e.data); upd(); });
  es.addEventListener("end", e => {
    const s = JSON.parse(e.data);
    es.close();
    if (follow.es === es) follow.es = null;
    follow.job = s;
    if (s.progress) follow.progress = s.progress;
    upd();
    refreshChanges();
    if (s.state === "done" && !applyView) toast("All changes applied");
  });
  // The controller no longer has the job (it restarted): the apply isn't running, whatever
  // its last state said; /api/changes says what there is now.
  es.addEventListener("gone", () => {
    if (follow.es === es) follow.es = null;
    if (follow.id !== j.id) return;
    follow.job = { ...follow.job, state: "failed", error: "The controller no longer has this apply: it may have restarted. The changes not sent are still waiting." };
    upd();
    refreshChanges();
  });
  renderChip();
}

// What each apply step and a node's state in a rollout are, in words.
const STEPWORDS = { check: "Check the changes", write: "Write the files", compile: "Compile the blocklists", "dry run": "Try it against every node", push: "Send to the nodes" };
const NODEWORDS = { waiting: "Waiting", gate: "Waiting for the others to answer", "would-push": "Would be sent", pushing: "Sending", rebooting: "Restarting",
  checking: "Checking its answers", checked: "Sent, answering, checked", soaking: "Watching", done: "Sent, answering, checked", skipped: "Already has it",
  failed: "Failed", left: "Left as it was", refused: "Refused", reverting: "Going back", reverted: "Back as it was", "not-reverted": "Not back as it was" };
const liState = s => (["done", "checked", "skipped", "reverted"].includes(s) ? "done" : ["failed", "refused", "not-reverted"].includes(s) ? "failed"
  : ["running", "now", "gate", "pushing", "rebooting", "checking", "soaking", "reverting"].includes(s) ? "now" : "");

let applyView = null;
function openApply() {
  if (!follow.job) return;
  const p = panel("Applying changes", () => { applyView = null; });
  const steps = h("ol", { class: "steps" });
  const after = h("div", { class: "stack" });
  const msg = h("p", { class: "hint bad", role: "status" });
  p.body.append(steps, after, msg);
  applyView = () => {
    const j = follow.job, pr = obj(follow.progress), run = !ended(j.state);
    p.title(run ? "Applying changes" : j.state === "done" ? "Changes applied" : j.state === "stopped" ? "Apply stopped" : "Apply failed");
    const items = [];
    for (const s of arr(pr.steps)) {
      if (s.name === "push") {
        items.push(h("li", { class: liState(s.state === "running" ? "now" : s.state) }, h("span", { class: "m" }),
          h("div", {}, h("b", {}, STEPWORDS.push), s.detail ? h("div", { class: "hint" }, str(s.detail)) : null)));
        for (const r of arr(pr.rollouts)) {
          for (const host of arr(r.order)) {
            const ns = obj(obj(r.nodes)[host]);
            items.push(h("li", { class: liState(str(ns.state)) }, h("span", { class: "m" }),
              h("div", {}, h("b", {}, nodeText(host)), h("div", { class: "hint" },
                [str(r.what), NODEWORDS[ns.state] || str(ns.state), str(ns.detail)].filter(Boolean).join(" · ")))));
          }
        }
        continue;
      }
      items.push(h("li", { class: liState(s.state === "running" ? "now" : s.state) }, h("span", { class: "m" }),
        h("div", {}, h("b", {}, STEPWORDS[s.name] || str(s.name)), s.detail ? h("div", { class: "hint" }, str(s.detail)) : null)));
    }
    if (!items.length) items.push(h("li", { class: "now" }, h("span", { class: "m" }), h("div", {}, h("b", {}, "Starting"))));
    steps.replaceChildren(...items);
    const out = [];
    for (const q of arr(pr.questions)) {
      const b = h("button", { class: "btn primary", type: "button" }, "Apply, taking this change");
      b.addEventListener("click", async () => {
        b.disabled = true;
        try { startApply(await post("api/jobs", { kind: "apply", params: obj(q.params) })); }
        catch (e) { msg.textContent = e.message; b.disabled = false; }
      });
      out.push(h("div", { class: "alert-box" }, h("p", {}, str(q.text)), h("div", { class: "row" }, b)));
    }
    if (run) out.push(h("p", { class: "hint" }, "You can close this; progress stays at the top of every page."));
    else if (j.state === "done") out.push(h("p", {}, "Every node is answering with the new changes."));
    else if (pr.outcome || j.error) out.push(h("p", {}, str(pr.outcome) || str(j.error)));
    if (!run && arr(pr.hints).length) out.push(h("ul", { class: "hint" }, arr(pr.hints).map(x => h("li", {}, str(x)))));
    after.replaceChildren(...out);
    if (run) {
      const stop = h("button", { class: "btn danger", type: "button", disabled: !!j.stopping }, j.stopping ? "Stopping after this node" : "Stop after this node");
      stop.addEventListener("click", async () => {
        stop.disabled = true;
        try { await post(`api/jobs/${encodeURIComponent(j.id)}/stop`); } catch (e) { msg.textContent = e.message; stop.disabled = false; }
      });
      p.footer.replaceChildren(stop);
    } else p.footer.replaceChildren(h("button", { class: "btn primary", type: "button", onclick: p.close }, "Done"));
  };
  applyView();
}

// ---- the fleet's band -------------------------------------------------------------------
let fleetNodes = null, bandBox = null, sessBand = null;
function renderBand(error) {
  if (!bandBox) return;
  const out = [];
  if (sessBand) out.push(sessBand);
  const band = (cls, strong, text) => h("div", { class: `band ${cls}` }, h("div", { class: "band-in" }, h("strong", {}, strong), text ? h("span", {}, text) : null));
  if (error) out.push(band("warn", "The controller isn't answering.", "What this page shows may be out of date."));
  const ns = listedNodes();
  if (ns.length && !ns.some(answering)) {
    out.push(band("bad", "No espDNS node is answering.", `Check power and network cables on ${ns.map(n => nodeText(n)).join(" and ")}.`));
  } else {
    // A node never read since the controller started may be wired: it counts as one here.
    const w = ns.filter(n => wired(n) || !n.status);
    if (w.length && !w.some(answering)) out.push(band("bad", "No wired node is answering.", "Only Wi-Fi nodes answer DNS queries now."));
  }
  bandBox.replaceChildren(...out);
}

// ---- the shell --------------------------------------------------------------------------
// shell draws the top bar for the page current (one of PAGES), the band and the skip link,
// and starts reading the nodes and the pending changes every 5 s.
export function shell(current) {
  const nav = h("nav", { class: "main", "aria-label": "Main" },
    PAGES.map(([href, name]) => h("a", { href: href === "index.html" ? "./" : href, "aria-current": href === current ? "page" : null }, name)));
  changesBox = h("div", { class: "changes" });
  const who = h("div", { class: "who" });
  const top = h("header", { class: "top" }, h("div", { class: "top-in" }, h("a", { class: "brand", href: "./" }, "espDNS"), nav, changesBox, who));
  bandBox = h("div", { class: "bands" });
  const main = document.querySelector("main");
  if (main) { if (!main.id) main.id = "content"; main.tabIndex = -1; }
  document.body.prepend(h("a", { class: "skip", href: `#${main ? main.id : "content"}` }, "Skip to the page"), top, bandBox);

  session.then(s => {
    canWrite = !!s.logged_in;
    if (s.logged_in) {
      who.append(h("button", { class: "chip-btn", type: "button", "aria-label": `Account: ${s.user}`, onclick: () => openAccount(s.user) }, `${s.user} ▾`));
    } else if (!s.password_set) {
      who.append(h("span", { class: "chip-btn" }, "read-only"));
      sessBand = h("div", { class: "band warn" }, h("div", { class: "band-in" }, h("strong", {}, "Read-only."),
        h("span", {}, "No password is set, so the controller takes no actions. Set one with ", h("code", {}, "espdns passwd"), " (docs/getting-started.md, step 6), then log in.")));
    } else if (s.error) {
      sessBand = h("div", { class: "band bad" }, h("div", { class: "band-in" }, h("strong", {}, "The login can't be used."), h("span", {}, str(s.error))));
    }
    renderBand(null);
    renderChip();
    if (s.logged_in) every(refreshChanges);
  });
  onNodes((ns, st) => { fleetNodes = ns; renderBand(st.error); renderChip(); });
  watchNodes();
}

// The account: who is logged in, and logging out. Its password, the release key and backup,
// and the recent changes come here with the account's own PR (docs/plan.md, The prototype).
function openAccount(user) {
  const p = panel(user);
  const out = h("button", { class: "btn", type: "button" }, "Log out");
  out.addEventListener("click", async () => {
    out.disabled = true;
    try { await post("api/logout"); } catch { /* gone anyway */ }
    loggedIn(null);
    location.href = "login.html";
  });
  p.footer.append(out);
}

export { api, getJSON, post, session, events, el, nodeText, ended, answering, wired };
