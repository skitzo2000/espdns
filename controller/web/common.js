// Shared by the pages: the header (the top bar, the login, the fleet's warnings and the
// running job), the fleet's nodes and their one name, the API helpers, and small formatting
// helpers. Everything from a node (names, reasons, log lines) is hostile: text only.

// ---- the session ------------------------------------------------------------------------
// A session has two halves (internal/auth): the cookie, which the browser keeps for the host
// (so whatever listens on another port of it gets it too), and the session's token, which
// the login gives this page and which is kept here in localStorage: per origin, the port
// included, so another port can't read it. Every API request carries it in X-Session-Token
// (api); without it the controller answers 401. The device token, kept the same way, names
// this browser to the login's backoff (a failed login elsewhere doesn't lock it out).
const TOKEN = "espdns.session", DEVICE = "espdns.device";
function stored(k) {
  try { return localStorage.getItem(k) || ""; } catch { return ""; }
}
function store(k, v) {
  try { if (v) localStorage.setItem(k, v); else localStorage.removeItem(k); } catch { /* no storage: no session */ }
}
// loggedIn keeps a login's reply: the session's token and the device token.
export function loggedIn(j) {
  store(TOKEN, j && j.token);
  if (j && j.device) store(DEVICE, j.device);
}
export const deviceToken = () => stored(DEVICE);

// api is fetch with the session's token, never cached.
export function api(url, opts = {}) {
  const headers = new Headers(opts.headers || {});
  const t = stored(TOKEN);
  if (t) headers.set("X-Session-Token", t);
  return fetch(url, { cache: "no-store", ...opts, headers });
}

// session is /api/session: {password_set, logged_in, user, expires, error}. Loaded once per
// page; every page but the login page needs a session once a password is set (the
// controller redirects there), and without a password set the controller is read-only.
export const session = api("api/session")
  .then(r => r.json())
  .catch(() => ({ password_set: false, logged_in: false }));

// key is /api/key: whether there is a release key to sign actions with.
export const releaseKey = () => getJSON("api/key").catch(e => ({ present: false, error: e.message }));

function toLogin() {
  location.href = `login.html?next=${encodeURIComponent(location.pathname + location.search + location.hash)}`;
}

// getJSON reads an API; a 401 (the session ended) goes to the login page. headers adds to
// the request's (X-Reauth).
export async function getJSON(url, headers = {}) {
  const r = await api(url, { headers });
  if (r.status === 401) { toLogin(); throw new Error("log in first"); }
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
    throw new Error(`${url}: ${msg}`);
  }
  return r.json();
}

// post sends JSON with the session's token; a 401 goes to the login page. It returns the
// reply, or throws its error. headers adds to the request's (X-Reauth).
export async function post(url, body, headers = {}) {
  const r = await api(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body || {}) });
  let j = {};
  try { j = await r.json(); } catch { /* not JSON */ }
  if (r.status === 401) { toLogin(); throw new Error(j.error || "log in first"); }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

// askPassword asks for the login password again, for what gives secrets away (a backup:
// the release key and the Wi-Fi passwords; a config shown with its Wi-Fi password): POST
// /api/reauth. It resolves to the grant, for one request in X-Reauth within two minutes, or
// null when cancelled. A wrong password asks
// again; three in a row end the session (then the login page).
export function askPassword(why) {
  return new Promise(resolve => {
    const d = el("dialog", "confirm reauth");
    const form = el("form");
    const label = el("label", "", "Password");
    const input = el("input");
    input.type = "password";
    input.autocomplete = "current-password";
    input.required = true;
    input.spellcheck = false;
    label.append(input);
    const msg = el("p", "sub");
    msg.setAttribute("role", "status");
    const row = el("div", "row");
    const no = el("button", "btn", "Cancel"), yes = el("button", "btn primary", "Continue");
    no.type = "button";
    yes.type = "submit";
    row.append(no, yes);
    form.append(el("h2", "", "Your password again"), el("p", "", why), label, msg, row);
    d.append(form);
    const done = v => { d.close(); d.remove(); resolve(v); };
    no.onclick = () => done(null);
    d.addEventListener("cancel", e => { e.preventDefault(); done(null); });
    form.addEventListener("submit", async e => {
      e.preventDefault();
      yes.disabled = true;
      msg.className = "sub";
      msg.textContent = "Checking…";
      try {
        const r = await api("api/reauth", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: input.value }) });
        const j = await r.json().catch(() => ({}));
        if (r.ok && j.reauth) { done(j.reauth); return; }
        if (r.status === 401) { done(null); toLogin(); return; }
        msg.className = "sub bad";
        msg.textContent = j.error || r.statusText;
        input.select();
      } catch (err) {
        msg.className = "sub bad";
        msg.textContent = `Can't reach the controller: ${err.message}`;
      }
      yes.disabled = false;
    });
    document.body.append(d);
    d.showModal();
    input.focus();
  });
}

// events follows a job's Server-Sent Events as an EventSource would, with the session's
// token (an EventSource sends no header of its own): addEventListener(type, f) calls f with
// {data} for each event of the type; close() stops. A stream that drops is taken up again
// after the last line seen (?after=, as Last-Event-ID), until close(); one refused (the job
// gone: the controller restarted, say) stops, with a "gone" event, so a page waiting for
// "end" isn't left waiting.
export function events(url) {
  const handlers = new Map();
  let closed = false, after = 0, ctl = null;
  const emit = (type, data) => {
    for (const f of handlers.get(type) || []) {
      try { f({ data }); } catch (e) { console.error(e); }
    }
  };
  const block = text => {
    let type = "message", id = null;
    const data = [];
    for (const line of text.split("\n")) {
      if (line.startsWith(":")) continue;
      const c = line.indexOf(":");
      const field = c < 0 ? line : line.slice(0, c);
      let v = c < 0 ? "" : line.slice(c + 1);
      if (v.startsWith(" ")) v = v.slice(1);
      if (field === "event") type = v;
      else if (field === "data") data.push(v);
      else if (field === "id") id = v;
    }
    if (id !== null && Number(id) > after) after = Number(id);
    if (data.length) emit(type, data.join("\n"));
  };
  (async () => {
    while (!closed) {
      ctl = new AbortController();
      try {
        const r = await api(after ? `${url}${url.includes("?") ? "&" : "?"}after=${after}` : url, { signal: ctl.signal });
        if (r.status === 401) { toLogin(); return; }
        if (r.status >= 400 && r.status < 500) { console.error(`${url}: ${r.status}`); closed = true; emit("gone", String(r.status)); return; }
        if (!r.ok || !r.body) throw new Error(r.statusText);
        const rd = r.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { value, done } = await rd.read();
          if (done) break;
          buf = (buf + value).replace(/\r\n?/g, "\n");
          let i;
          while (!closed && (i = buf.indexOf("\n\n")) >= 0) {
            block(buf.slice(0, i));
            buf = buf.slice(i + 2);
          }
          if (closed) { ctl.abort(); return; }
        }
      } catch (e) {
        if (closed) return;
        console.error(e);
      }
      if (!closed) await new Promise(res => setTimeout(res, 3000));
    }
  })();
  return {
    addEventListener(type, f) {
      if (!handlers.has(type)) handlers.set(type, []);
      handlers.get(type).push(f);
    },
    close() { closed = true; if (ctl) ctl.abort(); },
  };
}

export function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// ---- the fleet: /api/nodes, read every 5 s by the header -----------------------------------

const POLL = 5000;
const fleet = { nodes: null, text: "", error: null, byRef: new Map(), listeners: new Set() };
const str = v => (typeof v === "string" ? v : "");
const hostOnly = a => str(a).replace(/:\d+$/, "");

// onNodes calls f(nodes, {changed, error}) after every read of /api/nodes (nodes is the last
// list read, null before the first), and at once if one was read.
export function onNodes(f) {
  fleet.listeners.add(f);
  if (fleet.nodes) f(fleet.nodes, { changed: true, error: fleet.error });
}

// findNode is the node a page's reference names: its polled address (with or without the
// port), its node ID (the chip MAC), or its host name (with or without ".local").
export function findNode(ref) {
  if (ref && typeof ref === "object") return ref;
  if (typeof ref !== "string" || !ref) return undefined;
  return fleet.byRef.get(ref) || fleet.byRef.get(ref.toLowerCase());
}

// The references go in by how much a node controls them: the addresses the controller polls
// first, then node IDs, then host names (a node names itself anything), each kind for every
// node before the next, so a node naming itself after another's ID or address can't take
// that reference.
function indexNodes(ns) {
  fleet.byRef.clear();
  const add = (k, n) => { if (k && !fleet.byRef.has(k)) fleet.byRef.set(k, n); };
  for (const n of ns) add(str(n.addr), n);
  for (const n of ns) add(hostOnly(n.addr), n);
  for (const n of ns) add(str(n.id).toLowerCase(), n);
  for (const n of ns) {
    const h = str(n.hostname).toLowerCase();
    add(h, n);
    add(h.replace(/\.local\.?$/, ""), n);
  }
}

// nodeName is a node's one name, the same on every page: its config's name leads, else its
// host name, else its address; sub is the host name and address it isn't (small text).
// ref is a node from /api/nodes or a reference findNode takes; fallback names a node the
// controller doesn't know (yet).
export function nodeName(ref, fallback) {
  const n = findNode(ref);
  if (!n) {
    const name = str(fallback) || (typeof ref === "string" ? ref : "") || "?";
    const sub = typeof ref === "string" && ref !== name ? ref : "";
    return { name, sub, node: undefined };
  }
  const cfg = n.status && typeof n.status.config === "object" && n.status.config ? n.status.config : {};
  const host = str(n.hostname) || str(n.status && n.status.net && n.status.net.hostname);
  const name = str(cfg.name) || host || str(n.addr) || str(fallback) || "?";
  const sub = [host !== name ? host : "", n.addr !== name ? str(n.addr) : ""].filter(Boolean).join(" · ");
  return { name, sub, node: n };
}

// nodeText is the name alone, for a sentence, an option or a dialog.
export const nodeText = (ref, fallback) => nodeName(ref, fallback).name;

// nodeLabel is the name with the host name and address under it, as an element kept up to
// date as the nodes are read (a page can make it before the first read).
export function nodeLabel(ref, fallback, opts = {}) {
  const d = el(opts.inline ? "span" : "div", "nname");
  if (typeof ref === "string") d.dataset.nref = ref;
  if (fallback) d.dataset.nfall = fallback;
  if (opts.inline) d.dataset.ninline = "1";
  fillLabel(d, nodeName(ref, fallback));
  return d;
}

function fillLabel(d, nm) {
  const main = el("span", "nn", nm.name);
  if (!nm.sub) { d.replaceChildren(main); return; }
  d.replaceChildren(main, d.dataset.ninline ? " " : "", el("span", "sub", nm.sub));
}

function relabel() {
  for (const d of document.querySelectorAll(".nname[data-nref]")) fillLabel(d, nodeName(d.dataset.nref, d.dataset.nfall));
}

// answering: a node that answers DNS queries now (read, and its health says it answers).
export function answering(n) {
  if (!n.online || !n.status) return false;
  const h = n.status.health;
  return !(h && typeof h === "object" && h.answering === false);
}
export const wired = n => !!(n.status && n.status.net && n.status.net.kind === "ethernet");

// A node's state in one word, the same on every page: "offline" when the controller can't
// read it, else the health state its /status gives ("answering" on firmware from before
// health states). stateClass is its colour: none for the normal states, warn for degraded,
// bad for the rest (colour only when abnormal).
// A state that isn't a string (a node's hostile or broken /status) is "unknown", coloured
// as a problem, never shown as normal.
const stateText = s => (s === undefined || s === null || s === "" ? "answering" : typeof s === "string" ? s : "unknown");
export const stateWord = (online, state) => (!online ? "offline" : stateText(state));
export function stateClass(online, state) {
  if (!online) return "bad";
  const s = stateText(state);
  return ["healthy", "answering", "updating", "booting"].includes(s) ? "" : s === "degraded" ? "warn" : "bad";
}
export const statePill = (online, state) => el("span", `pill ${stateClass(online, state)}`, stateWord(online, state));

async function pollNodes() {
  let changed = false;
  try {
    const r = await api("api/nodes", { signal: AbortSignal.timeout(POLL * 3) });
    if (r.status === 401) { toLogin(); return; }
    if (!r.ok) throw new Error(`api/nodes: ${r.status} ${r.statusText}`);
    const text = await r.text();
    fleet.error = null;
    if (text !== fleet.text) {
      const ns = JSON.parse(text);
      fleet.nodes = Array.isArray(ns) ? ns.filter(n => n && typeof n === "object") : [];
      fleet.text = text;
      changed = true;
      indexNodes(fleet.nodes);
      relabel();
    }
  } catch (e) {
    fleet.error = e;
    console.error(e);
  }
  renderAlerts();
  for (const f of fleet.listeners) {
    try { f(fleet.nodes, { changed, error: fleet.error }); } catch (e) { console.error(e); }
  }
}

// ---- jobs ------------------------------------------------------------------------------

export const ended = s => ["done", "failed", "stopped"].includes(s);
// A job's state as a pill's class: only a failure is coloured.
export const jobPill = s => (s === "failed" ? "bad" : "");

export function jobParams(j) {
  try { const p = JSON.parse((j.args || [])[0] || "{}"); return p && typeof p === "object" ? p : {}; } catch { return {}; }
}

// jobWhat is what a job does, in words: its kind and its target (a node by its one name).
export function jobWhat(j) {
  const p = jobParams(j);
  const parts = [str(j.kind)];
  if (typeof p.node === "string") parts.push(nodeText(p.node));
  if (typeof p.seconds === "number") parts.push(`${p.seconds} s`);
  if (typeof p.config === "string") parts.push(p.config);
  if (typeof p.zone === "string") parts.push(p.zone);
  if (j.kind === "rollout" && typeof p.kind === "string") {
    parts.push(p.kind, `to ${Array.isArray(p.nodes) ? p.nodes.length : 0} node(s)`);
    if (typeof p.file === "string") parts.push(p.file);
  }
  if (p.dry_run === true) parts.push("(dry run)");
  return parts.join(" ");
}

// waitJob polls a job until it ends, and returns it.
export async function waitJob(id) {
  for (;;) {
    const j = await getJSON(`api/jobs/${encodeURIComponent(id)}`);
    if (ended(j.state)) return j;
    await new Promise(r => setTimeout(r, 500));
  }
}

const busy = { job: null, queued: 0, lock: null };

async function pollJobs() {
  try {
    const r = await api("api/jobs", { signal: AbortSignal.timeout(POLL * 3) });
    if (!r.ok) throw new Error(r.statusText);
    const js = await r.json();
    const live = (Array.isArray(js) ? js : []).filter(j => !ended(j.state));
    busy.job = live.find(j => j.state === "running") || live[live.length - 1] || null;
    busy.queued = live.filter(j => j !== busy.job).length;
    busy.lock = null;
    if (!busy.job) {
      const l = await api("api/lock", { signal: AbortSignal.timeout(POLL * 3) }).then(x => (x.ok ? x.json() : null));
      if (l && l.held) busy.lock = str(l.text) || "another process";
    }
  } catch {
    busy.job = null; busy.lock = null;
  }
  renderBusy();
}

// ---- the header ------------------------------------------------------------------------

// The top bar's destinations; the pages under ⚙ (System) mark it, with System above their
// title. Traffic holds the charts and the query log.
const TOP = [["index.html", "Nodes"], ["zones.html", "Zones"], ["blocklists.html", "Blocklists"], ["traffic.html", "Traffic"], ["system.html", "System"]];
const UNDER = { "nodes.html": "index.html", "querylog.html": "traffic.html", "jobs.html": "system.html", "backup.html": "system.html", "builder.html": "system.html",
  "configs.html": "system.html", "push.html": "system.html", "adopt.html": "system.html" };

let alertBox = null, busyBox = null;

export function header(current) {
  const top = UNDER[current] || current;
  const h = el("header", "top");
  const bar = el("div", "topbar");
  const brand = el("a", "brand", "espDNS");
  brand.href = "./";
  const nav = el("nav");
  nav.setAttribute("aria-label", "Main");
  for (const [href, name] of TOP) {
    const a = el("a");
    a.href = href === "index.html" ? "./" : href;
    if (href === "system.html") {
      const g = el("span", "gear", "⚙");
      g.setAttribute("aria-hidden", "true");
      a.append(g, " ", name);
    } else a.textContent = name;
    if (href === top) a.setAttribute("aria-current", "page");
    nav.append(a);
  }
  const who = el("div", "who");
  bar.append(brand, nav, who);
  alertBox = el("div", "alerts");
  alertBox.setAttribute("role", "status");
  busyBox = el("div", "busy");
  busyBox.hidden = true;
  h.append(bar, alertBox, busyBox);
  document.body.prepend(h);
  // A skip link, first in the tab order, past the top bar to the page.
  const main0 = document.querySelector("main");
  if (main0) {
    if (!main0.id) main0.id = "content";
    main0.tabIndex = -1;
    const skip = el("a", "skip", "Skip to the page");
    skip.href = `#${main0.id}`;
    document.body.prepend(skip);
  }
  if (UNDER[current] === "system.html") {
    const main = document.querySelector("main");
    const c = el("a", "crumb", "System");
    c.href = "system.html";
    if (main) main.prepend(c);
  }
  session.then(s => {
    if (s.logged_in) {
      const out = el("button", "btn small", "Log out");
      out.type = "button";
      out.onclick = async () => {
        try { await post("api/logout"); } catch { /* gone anyway */ }
        loggedIn(null);
        location.href = "login.html";
      };
      const u = el("span", "sub", s.user);
      u.title = `Logged in as ${s.user}`;
      who.append(u, out);
    } else if (!s.password_set) {
      who.append(el("span", "sub", "read-only"));
      const b = el("div", "banner warn topbanner");
      b.append("Read-only: no password is set, so the controller takes no actions. Set one with ",
        el("code", "", "espdns passwd"), " (docs/getting-started.md, step 6), then log in.");
      h.append(b);
    } else if (s.error) {
      h.append(el("div", "banner bad topbanner", `The login can't be used: ${s.error}`));
    }
  });
  every(pollNodes);
  every(pollJobs);
}

// watchNodes reads /api/nodes every 5 s for a page without this header (shell.js): onNodes
// hears each read.
export function watchNodes() { every(pollNodes); }

// every runs a poll now and every 5 s (or ms): one at a time (a slow controller doesn't
// stack them up), not while the tab is hidden, and at once when it is shown again.
export function every(f, ms = POLL) {
  let running = false;
  const run = async () => {
    if (running || document.hidden) return;
    running = true;
    try { await f(); } finally { running = false; }
  };
  setInterval(run, ms);
  document.addEventListener("visibilitychange", run);
  run();
}

let alertText = "";
function renderAlerts() {
  if (!alertBox) return;
  const lines = [];
  if (fleet.error) lines.push(["warn", "The controller isn't answering: what this page shows may be out of date."]);
  const ns = fleet.nodes || [];
  if (ns.length && !ns.some(answering)) {
    lines.push(["bad", ns.length === 1 ? "No node is answering: the one node isn't answering DNS queries." : `No node is answering: none of the ${ns.length} nodes answers DNS queries.`]);
  } else {
    // A node never read since the controller started may be wired: it counts as one here.
    const w = ns.filter(n => wired(n) || !n.status);
    if (w.length && !w.some(answering)) lines.push(["bad", "No wired node is answering: only Wi-Fi nodes answer DNS queries."]);
  }
  const text = JSON.stringify(lines);
  if (text === alertText) return;
  alertText = text;
  alertBox.replaceChildren(...lines.map(([cls, t]) => {
    const d = el("div", `alert ${cls}`);
    const a = el("a", "", t);
    a.href = "./";
    d.append(a);
    return d;
  }));
}

function renderBusy() {
  if (!busyBox) return;
  if (!busy.job && !busy.lock) { busyBox.hidden = true; busyBox.replaceChildren(); return; }
  busyBox.hidden = false;
  if (!busy.job) {
    busyBox.replaceChildren(el("span", "busyk", "Fleet locked"), el("span", "busyt", busy.lock));
    return;
  }
  const j = busy.job;
  const a = el("a", "busylink");
  a.href = `jobs.html#job=${encodeURIComponent(j.id)}`;
  a.append(el("span", "busyk", j.state === "running" ? (j.stopping ? "Stopping" : "Running") : "Queued"),
    el("span", "busyw", jobWhat(j)));
  if (j.last) a.append(el("span", "busyt", str(j.last)));
  if (busy.queued) a.append(el("span", "sub", `+${busy.queued} queued`));
  busyBox.replaceChildren(a);
}

// ---- dialogs and formatting ------------------------------------------------------------

// confirmDialog asks before a change to a node; resolves true to go on. lines are strings
// or elements.
export function confirmDialog(title, lines, go, goClass = "btn danger") {
  return new Promise(resolve => {
    const d = el("dialog", "confirm");
    d.append(el("h2", "", title), ...lines.map(l => typeof l === "string" ? el("p", "", l) : l));
    const row = el("div", "row");
    const no = el("button", "btn", "Cancel"), yes = el("button", goClass, go);
    no.type = yes.type = "button";
    row.append(no, yes);
    d.append(row);
    const done = v => { d.close(); d.remove(); resolve(v); };
    no.onclick = () => done(false);
    yes.onclick = () => done(true);
    d.addEventListener("cancel", e => { e.preventDefault(); done(false); });
    document.body.append(d);
    d.showModal();
    no.focus();
  });
}

export function secs(ms) {
  return typeof ms !== "number" ? "–" : `${(ms / 1000).toFixed(2)} s`;
}

export function uptime(s) {
  if (typeof s !== "number") return "–";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${s % 60}s`;
}

export function ago(t) {
  if (!t || t.startsWith("0001")) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(t)) / 1000));
  return s < 60 ? `${s} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago`
    : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`;
}
