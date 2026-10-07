// Nodes, the home page (index.html; docs/plan.md, The GUI redesign and The prototype): one
// sentence first (whether DNS is answering, or what needs attention), Copy DNS servers and
// + Add node at the top right, a firmware update offered as versions, the fleet's facts, one
// row per node (its LED, state and reason, its address to copy, its load, and its MAC to copy
// while it is on DHCP), the nodes found on the network and not added yet (with their MACs to
// copy, for a DHCP reservation or a static address), and the last hour's charts. A node
// opens its details (nodes.html, until the node page is built). Read from /api/nodes and
// /api/nodes/found every 5 s, /api/dashboard every 10 s, /api/updates every 30 s.
import { shell, h, arr, obj, str, hostOnly, led, addr, mac, copyText, toast, panel, refreshChanges, onChanges,
  getJSON, post, session, nodeText, answering } from "./shell.js";
import { onNodes, every } from "./common.js";
import { addNode } from "./addnode.js";

shell("index.html");

const $ = id => document.getElementById(id);
const data = { nodes: null, found: [], updates: null, dash: null, boards: new Map(), sess: {} };

// ---- a node in words --------------------------------------------------------------------

// boardName is a board's title from the catalog (/api/boards), else its name.
const boardName = b => data.boards.get(str(b)) || str(b);
const linkWord = k => (k === "ethernet" ? "Wired" : k === "wifi" ? "Wi-Fi" : "");
const nodeKey = n => n.id || n.addr;
const sentenceCase = s => (s ? s[0].toUpperCase() + s.slice(1) : s);

function upFor(sec) {
  if (typeof sec !== "number" || sec < 0) return "";
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d} d ${hh} h` : hh ? `${hh} h ${m} m` : `${m} m`;
}
function sinceWords(t) {
  const s = Math.max(0, Math.round((Date.now() - new Date(t)) / 1000));
  return s < 90 ? `${s} s` : s < 5400 ? `${Math.round(s / 60)} min` : s < 129600 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`;
}

// Reasons that don't make a node abnormal (docs/design.md, Health and fault indication).
const INFO = ["config on trial", "reboot pending", "service restarting"];

// stateOf is a node's state as its LED shows it: the LED pattern, a word, why, and the row's
// tint ("" normal, warn, bad).
function stateOf(n) {
  const s = obj(n.status), hh = obj(s.health);
  if (!n.online) {
    const why = n.status ? `No reply for ${sinceWords(n.last_seen)}` : "No reply since the controller started";
    return { led: "fault", word: "Not answering", why, tint: "bad" };
  }
  const reasons = arr(hh.reasons).filter(r => typeof r === "string");
  const words = rs => rs.map(sentenceCase).join(", ");
  const st = hh.state;
  if (st === undefined || st === null || st === "") {
    // Firmware from before health states: its degraded flag.
    return s.degraded ? { led: "unknown", word: "Degraded", why: "Old firmware: update it", tint: "warn" }
      : { led: "unknown", word: "Answering", why: "Old firmware: update it", tint: "" };
  }
  switch (st) {
    case "healthy": return { led: "healthy", word: "Healthy", why: words(reasons.filter(r => INFO.includes(r))), tint: "" };
    case "degraded": return { led: "degraded", word: "Degraded", why: words(reasons) || "Something it runs failed", tint: "warn" };
    case "no network": return { led: "nonet", word: "No network", why: words(reasons), tint: "bad" };
    case "fault": return { led: "fault", word: "Fault", why: words(reasons), tint: "bad" };
    case "updating": return { led: "updating", word: "Updating", why: "Receiving new firmware", tint: "" };
    case "booting": return { led: "booting", word: "Starting", why: "", tint: "" };
    default: return { led: "unknown", word: typeof st === "string" ? sentenceCase(st) : "Unknown state", why: words(reasons), tint: "bad" };
  }
}

// updateOf is a node's firmware update in versions (/api/updates), or "".
function updateOf(n) {
  const u = arr(obj(data.updates).nodes).find(x => x.host === n.addr);
  if (!u) return "";
  const from = str(obj(u.runs).version), to = str(obj(u.newest).version);
  if (u.pending) return `Update waiting to apply: ${from} → ${to}`;
  if (u.state === "available") return `Update available: ${from} → ${to}`;
  return "";
}

const listed = () => arr(data.nodes).filter(n => n.source === "settings");
const names = ns => ns.map(n => nodeText(n));
const both = ns => (ns.length === 2 ? "both nodes" : `all ${ns.length} nodes`);
const andList = xs => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

// ---- the head: the sentence, Copy DNS servers, + Add node --------------------------------

function renderHead() {
  const ns = listed();
  const sentence = $("sentence"), sub = $("sentence-sub");
  const copy = $("copy-dns");
  const ips = ns.map(n => hostOnly(n.addr));
  copy.disabled = !ips.length;
  copy.title = ips.join(", ");
  if (data.nodes === null) return;
  const up = ns.filter(answering);
  const attention = ns.map(n => [n, stateOf(n)]).filter(([, s]) => s.tint);
  if (!ns.length) {
    sentence.textContent = "No node yet";
    sub.textContent = "Add a node to start answering DNS on your network.";
  } else if (!up.length) {
    sentence.textContent = "DNS is not answering on your espDNS nodes";
    sub.textContent = `Check power and network cables on ${andList(names(ns))}.`;
  } else if (attention.length) {
    const [n, s] = attention[0];
    sentence.textContent = `DNS is answering · ${andList(attention.map(([x]) => nodeText(x)))} need${attention.length === 1 ? "s" : ""} attention`;
    sub.textContent = `${nodeText(n)}: ${s.why || s.word}. Clients still get answers from ${up.length === ns.length ? both(ns) : andList(names(up))}.`;
  } else if (ns.length === 1) {
    sentence.textContent = `DNS is answering on ${nodeText(ns[0])}`;
    sub.textContent = "With one node, DNS stops while it restarts: add a second node to keep it answering.";
  } else {
    sentence.textContent = `DNS is answering on ${both(ns)}`;
    sub.textContent = "Every node is healthy.";
  }
}

$("copy-dns").addEventListener("click", async () => {
  const ips = listed().map(n => hostOnly(n.addr));
  if (!ips.length) return;
  const t = ips.join(", ");
  toast(await copyText(t) ? `Copied ${t}: give ${ips.length === 2 ? "both" : ips.length === 1 ? "it" : "them all"} to your router as its DNS servers`
    : `Couldn't copy: your DNS servers are ${t}`);
});

const adder = addNode($("add-node"), {
  found: () => data.found,
  nodes: () => listed(),
  boardName,
  nodeKey,
  done: () => { readFound(); refreshChanges(); },
});

// ---- the update -------------------------------------------------------------------------

function renderUpdate() {
  const box = $("update");
  const rep = obj(data.updates);
  const offered = arr(rep.nodes).filter(u => u.state === "available" && u.listed && !u.pending);
  if (!offered.length) { box.hidden = true; box.replaceChildren(); return; }
  const others = listed().filter(n => !offered.some(u => u.host === n.addr));
  const nm = u => nodeText(u.host);
  const b = h("button", { class: "btn primary", type: "button", onclick: openUpdate }, offered.length === 1 ? `Update ${nm(offered[0])}` : "Update all");
  let line;
  if (offered.length === 1) {
    const u = offered[0];
    line = h("div", {}, h("b", {}, `Firmware ${str(obj(u.newest).version)} for ${nm(u)}`), " ",
      h("span", { class: "muted" }, `(now ${str(obj(u.runs).version)}). Applies with a restart${others.length ? `; ${andList(names(others))} keep${others.length === 1 ? "s" : ""} answering meanwhile` : ""}.`));
  } else {
    line = h("div", {}, h("b", {}, `New firmware for ${andList(offered.map(nm))}`), " ",
      h("span", { class: "muted" }, "Applies with a restart each, one node at a time; the others keep answering."));
  }
  box.className = "panel pad row spread accent";
  box.replaceChildren(line, b);
  box.hidden = false;
}

// The Update panel: which nodes, from which version to which; adds the updates to the
// changes to apply (POST /api/updates).
function openUpdate() {
  const rep = obj(data.updates);
  const p = panel("Update firmware");
  const picks = new Map();
  const rows = arr(rep.nodes).filter(u => u.listed).map(u => {
    const from = str(obj(u.runs).version), to = str(obj(u.newest).version);
    let right, hint;
    if (u.state === "available" && !u.pending) {
      const cb = h("input", { type: "checkbox", checked: true, "aria-label": `Update ${nodeText(u.host)}` });
      picks.set(u.host, cb);
      right = cb;
      hint = `${from} → ${to} · restarts for a few seconds`;
    } else if (u.pending) {
      right = h("span", { class: "hint" }, "Waiting to apply");
      hint = str(u.pending_summary);
    } else if (u.state === "current") {
      right = h("span", { class: "hint" }, "Up to date");
      hint = `Already on ${from}`;
    } else {
      right = h("span", { class: "hint" }, "–");
      hint = str(u.why);
    }
    return h("div", { class: "change" }, h("div", {}, h("b", {}, nodeText(u.host)), h("div", { class: "hint" }, hint)), right);
  });
  const note = h("p", { class: "small" });
  const msg = h("p", { class: "hint bad", role: "status" });
  const go = h("button", { class: "btn primary", type: "button" }, "Add to changes");
  const say = () => {
    const chosen = [...picks].filter(([, cb]) => cb.checked).map(([host]) => host);
    const rest = listed().filter(n => !chosen.includes(n.addr));
    go.disabled = !chosen.length || !data.sess.logged_in;
    note.textContent = !chosen.length ? "Choose a node to update."
      : rest.length ? `${andList(names(rest))} keep${rest.length === 1 ? "s" : ""} answering while ${andList(chosen.map(x => nodeText(x)))} restart${chosen.length === 1 ? "s" : ""}.`
        : "One node at a time restarts; the others keep answering.";
  };
  for (const cb of picks.values()) cb.addEventListener("change", say);
  go.addEventListener("click", async () => {
    const chosen = [...picks].filter(([, cb]) => cb.checked).map(([host]) => host);
    const builds = {};
    for (const host of chosen) builds[host] = str(obj(arr(rep.nodes).find(u => u.host === host).newest).build);
    go.disabled = true;
    msg.textContent = "";
    try {
      await post("api/updates", { nodes: chosen, builds });
      p.close();
      await Promise.all([refreshChanges(), readUpdates()]);
      toast(`Added to changes to apply: update ${andList(chosen.map(x => nodeText(x)))}`);
    } catch (e) { msg.textContent = e.message; go.disabled = false; }
  });
  p.body.append(h("div", { class: "stack" }, rows), note, msg);
  p.footer.append(h("button", { class: "btn", type: "button", onclick: p.close }, "Not now"), go);
  say();
}

// ---- the facts and the rows -------------------------------------------------------------

const fmtNum = v => (typeof v === "number" && isFinite(v) ? (v < 10 ? v.toFixed(1) : Math.round(v).toLocaleString()) : "–");
const pct = v => (typeof v === "number" && isFinite(v) ? `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%` : "–");

function renderFacts() {
  const ns = listed();
  const f = obj(obj(data.dash).fleet), now = obj(f.now), hour = obj(f.hour);
  const failed = typeof hour.servfail === "number" ? hour.servfail + (hour.dropped || 0) : null;
  const fact = (b, t) => h("span", {}, h("b", {}, b), ` ${t}`);
  $("facts").replaceChildren(
    fact(`${ns.filter(answering).length} of ${ns.length}`, `node${ns.length === 1 ? "" : "s"} answering`),
    fact(fmtNum(now.qps), "queries a second"),
    fact(failed === null ? "–" : failed.toLocaleString(), "failed answers in the last hour"),
    fact(pct(hour.blocked_share), "of queries blocked"));
}

// macLine is a node's MAC to copy, on its own line under its address; null for none.
function macLine(m) {
  const c = mac(m);
  return c ? h("div", { class: "sub" }, c) : null;
}

function nodeRow(n) {
  const s = obj(n.status), net = obj(s.net);
  const st = stateOf(n);
  const why = [st.why, !st.tint ? updateOf(n) : ""].filter(Boolean).join(" · ");
  const href = `nodes.html#${encodeURIComponent(nodeKey(n))}`;
  const up = n.online ? upFor(s.uptime_s) : "";
  return h("div", { class: `r${st.tint ? ` r-${st.tint}` : ""}`, "data-href": href },
    h("div", {}, h("a", { class: "name", href }, nodeText(n)), h("div", { class: "sub" }, boardName(s.board) || "–")),
    h("div", { class: "full-n" }, h("span", { class: "state" }, led(st.led), h("span", { class: "stw" }, st.word)), why ? h("div", { class: "sub" }, why) : null),
    h("div", { class: "full-n" }, addr(hostOnly(n.addr)), h("div", { class: "sub" }, [linkWord(net.kind), up && `up ${up}`].filter(Boolean).join(" · ")),
      obj(s.config).address === "dhcp" ? macLine(n.mac) : null),
    h("div", { class: "hide-n num" }, n.online && typeof n.qps === "number" ? n.qps.toFixed(1) : "–", " ", h("span", { class: "sub" }, "q/s")),
    h("span", { class: "chev", "aria-hidden": "true" }, "›"));
}

// A node found on the network (mDNS, or looked up) and not added: a light-blue row.
function foundRow(f) {
  const link = f.net === "ethernet" ? "Wired" : f.net === "wifi" ? "Wi-Fi" : "";
  const refusal = arr(f.refusals)[0];
  const sub = refusal ? `Can't be added yet: ${refusal}`
    : `Found ${f.source === "lookup" ? "at its address" : "on your network"}${link ? ` over ${link}` : ""}${f.version ? `, firmware ${f.version}` : ""}`;
  return h("div", { class: "r r-new" },
    h("div", {}, h("div", { class: "name" }, f.adopted && f.name ? str(f.name) : "New device found"),
      h("div", { class: "sub" }, [boardName(f.board), str(f.hostname)].filter(Boolean).join(" · "))),
    h("div", { class: "full-n" }, h("span", { class: "state" }, led("unknown"), h("span", { class: "stw" }, "Not added yet")), h("div", { class: "sub" }, sub)),
    h("div", { class: "full-n" }, addr(hostOnly(f.host)), macLine(f.mac)),
    h("div", { class: "hide-n" }, f.next ? h("button", { class: "btn small primary", type: "button", onclick: () => adder.open(f) }, "Add") : null),
    h("div", {}));
}

function renderRows() {
  const box = $("nodes");
  const head = box.firstElementChild;
  const ns = listed();
  const rows = [...ns.map(nodeRow), ...arr(data.found).map(foundRow)];
  if (data.nodes === null) rows.push(h("div", { class: "empty" }, h("p", {}, "Reading the nodes…")));
  else if (!rows.length) rows.push(h("div", { class: "empty" }, h("p", {}, "No node yet. + Add node finds the ones on your network, or installs a new board over USB.")));
  head.hidden = !ns.length && !arr(data.found).length;
  box.replaceChildren(head, ...rows);
}

// A row opens its node; its buttons and links do their own thing.
$("nodes").addEventListener("click", e => {
  const r = e.target.closest(".r[data-href]");
  if (r && !e.target.closest("button, a, input, label")) location.href = r.dataset.href;
});

// ---- the last hour ----------------------------------------------------------------------

function spark(values) {
  const vs = arr(values).map(v => (typeof v === "number" && isFinite(v) ? v : null));
  const known = vs.filter(v => v !== null);
  if (known.length < 2) return null;
  const max = Math.max(...known) || 1, w = 200, hgt = 50;
  const pts = vs.map((y, i) => (y === null ? null : `${(i / (vs.length - 1) * w).toFixed(1)},${(hgt - 4 - y / max * (hgt - 10)).toFixed(1)}`)).filter(Boolean).join(" ");
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  for (const [k, v] of Object.entries({ class: "spark", viewBox: `0 0 ${w} ${hgt}`, preserveAspectRatio: "none", "aria-hidden": "true" })) svg.setAttribute(k, v);
  const first = pts.split(" ")[0].split(",")[0], last = pts.split(" ").at(-1).split(",")[0];
  const poly = document.createElementNS(NS, "polygon");
  poly.setAttribute("points", `${first},${hgt} ${pts} ${last},${hgt}`);
  const line = document.createElementNS(NS, "polyline");
  line.setAttribute("points", pts);
  line.setAttribute("vector-effect", "non-scaling-stroke");
  svg.append(poly, line);
  return svg;
}

function renderHour() {
  const f = obj(obj(data.dash).fleet), hour = obj(f.hour);
  const sec = $("hour");
  if (!listed().length || !data.dash) { sec.hidden = true; return; }
  const ms = v => (typeof v === "number" ? `${Math.round(v)} ms typical` : "–");
  const mini = (t, v, series, title) => h("div", { class: "panel mini", title }, h("span", { class: "small muted" }, t), h("span", { class: "v num" }, v), spark(series));
  $("minis").replaceChildren(
    mini("Queries a second", fmtNum(hour.qps), f.qps),
    mini("Answer time", ms(hour.p50_ms), f.p95_ms, "The line: the slowest answers (95th percentile) each minute"),
    mini("Blocked", pct(hour.blocked_share), f.blocked_qps));
  sec.hidden = false;
}

function render() {
  renderHead();
  renderUpdate();
  renderFacts();
  renderRows();
  renderHour();
}

// ---- reading ----------------------------------------------------------------------------

async function readFound() {
  if (!data.sess.logged_in) return;
  try { data.found = arr(obj(await getJSON("api/nodes/found")).nodes); } catch { /* kept */ }
  render();
}
async function readUpdates() {
  try { data.updates = await getJSON("api/updates"); } catch { data.updates = null; }
  render();
}
async function readDash() {
  try { data.dash = await getJSON("api/dashboard"); } catch { data.dash = null; }
  renderFacts();
  renderHour();
}

onNodes(ns => { data.nodes = ns; render(); });
// A firmware change added or applied changes what is offered: read again then.
let changesKey = null;
onChanges(c => {
  const k = arr(c.changes).map(x => x.id).join(",");
  if (changesKey !== null && k !== changesKey) readUpdates();
  changesKey = k;
});
getJSON("api/boards").then(bs => {
  for (const b of arr(bs)) { const bd = obj(b.board); if (bd.name) data.boards.set(bd.name, str(bd.title) || bd.name); }
  render();
}).catch(() => {});
session.then(s => {
  data.sess = s;
  every(readFound);
  every(readUpdates, 30000);
  every(readDash, 10000);
});
render();
