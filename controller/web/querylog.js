// The query log (querylog.html): the fleet's recent queries from /api/querylog, newest
// first by time, filtered there (node, client, name, result, type), followed live by asking
// for what came after the last read every few seconds, unless paused. Names and addresses
// come from the nodes, so hostile: text only, never markup.
import { header, el, getJSON, nodeName, nodeText } from "./common.js";

header("querylog.html");

const SHOW = 500;     // rows shown at most
const EVERY = 3000;   // ms between follows
const arr = v => (Array.isArray(v) ? v : []);
const obj = v => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
// A result's class: blocking is normal (plain); a refusal or a failure is bad.
const RESULT = { refused: "bad", servfail: "bad", error: "bad", dropped: "bad" };
const lookup = (t, k) => (typeof k === "string" && Object.hasOwn(t, k) ? t[k] : "");

const $ = id => document.getElementById(id);
const fields = { node: $("f-node"), client: $("f-client"), name: $("f-name"), result: $("f-result"), qtype: $("f-qtype") };
let rows = [], last = 0, run = "", matched = 0, paused = false, names = new Map(), gen = 0, timer = null;
let clients = ""; // each node's client setting as last read: one made stricter reloads the rows

// The filters from the address (Traffic links a name here), then kept in it.
const want = new URLSearchParams(location.search);
for (const [k, f] of Object.entries(fields)) if (want.get(k)) {
  if (f.tagName === "SELECT" && ![...f.options].some(o => o.value === want.get(k))) f.append(new Option(want.get(k), want.get(k)));
  f.value = want.get(k);
}

function query(after) {
  const q = new URLSearchParams();
  for (const [k, f] of Object.entries(fields)) if (f.value.trim()) q.set(k, f.value.trim());
  const shown = q.toString();
  history.replaceState(null, "", shown ? `?${shown}` : location.pathname);
  if (after) { q.set("after", String(after)); q.set("run", run); }
  q.set("limit", String(after ? 1000 : SHOW));
  return `api/querylog?${q}`;
}

function when(e) {
  const d = new Date(e.at);
  if (Number.isNaN(d.getTime())) return "–";
  const today = d.toDateString() === new Date().toDateString();
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return (e.estimated ? "~" : "") + (today ? t : `${d.toLocaleDateString()} ${t}`);
}

function row(e) {
  const tr = el("tr");
  const td = (text, cls) => { const c = el("td", cls || "", text); tr.append(c); return c; };
  const t = td(when(e), "mono");
  if (e.estimated) t.title = "The node's clock wasn't set: estimated from its uptime.";
  // The node's one name; its host name and address on hover (a column of them is noise).
  const nd = names.get(e.node);
  const nm = nd ? nodeName(nd.addr || nd.key, nd.name) : { name: String(e.node || "–"), sub: "" };
  const nc = td(nm.name, "qnode");
  nc.title = nm.sub ? `${nm.name} · ${nm.sub}` : nm.name;
  if (typeof e.client === "string") td(e.client, "mono"); else td("hidden", "muted");
  const n = td("", "qname");
  n.append(el("span", "mono", String(e.qname ?? "")));
  if (e.truncated) {
    const c = el("span", "chip info", "cut");
    c.title = "The name was longer than the node keeps: its last labels.";
    n.append(" ", c);
  }
  td(String(e.qtype ?? ""), "mono");
  const r = td("");
  r.append(el("span", `pill ${lookup(RESULT, e.result)}`, String(e.result ?? "?")));
  const extra = [e.rcode && e.rcode !== "NOERROR" ? e.rcode : "", e.rule ? `by ${e.rule}` : ""].filter(Boolean).join(" · ");
  if (extra) r.append(el("div", "sub", extra));
  td(typeof e.latency_us === "number" ? `${(e.latency_us / 1000).toFixed(e.latency_us < 10000 ? 1 : 0)} ms` : "–", "num");
  return tr;
}

function render() {
  const body = $("rows");
  if (!rows.length) {
    body.replaceChildren(el("tr"));
    body.firstChild.append(Object.assign(el("td", "empty", "No queries match."), { colSpan: 7 }));
    return;
  }
  body.replaceChildren(...rows.map(row));
}

// clientsOf is each node's client setting, to see one change.
const clientsOf = v => arr(v.nodes).map(n => `${n.key}=${n.client}`).sort().join(" ");

function nodesState(v) {
  names = new Map(arr(v.nodes).map(n => [n.key, n]));
  const sel = fields.node, cur = sel.value;
  const opts = [new Option("every node", "")];
  for (const n of arr(v.nodes)) opts.push(new Option(nodeText(n.addr || n.key, n.name || n.addr), n.key));
  if (cur && !arr(v.nodes).some(n => n.key === cur)) opts.push(new Option(cur, cur));
  sel.replaceChildren(...opts);
  sel.value = cur;
  const box = $("qlnodes");
  box.replaceChildren(...arr(v.nodes).map(n => {
    const c = el("span", "chip");
    let text = `${nodeText(n.addr || n.key, n.name || n.addr)}: `, cls = "";
    switch (n.state) {
      case "ok":
        text += n.enabled ? `clients ${n.client || "?"}` : "query log off";
        if (n.lost) { text += `, ${n.lost.toLocaleString()} lost`; cls = "warn"; }
        if (n.skipped) text += `, ${n.skipped.toLocaleString()} older not read`;
        if (n.behind) { text += ", catching up"; cls = "warn"; }
        if (n.restarts) text += `, ${n.restarts} restart(s)`;
        break;
      case "unsupported": text += "no query log (firmware from before it)"; cls = "warn"; break;
      case "error": text += "read failed"; cls = "bad"; c.title = String(n.error || ""); break;
      default: text += "not read yet";
    }
    c.textContent = text;
    if (cls) c.classList.add(cls);
    if (n.state === "ok") c.title = "Lost: entries the node overwrote before the controller read them. Restarts: boots, after which its log started over.";
    return c;
  }));
  const span = v.oldest && v.newest ? `, ${new Date(v.oldest).toLocaleTimeString()} to ${new Date(v.newest).toLocaleTimeString()}` : "";
  $("qlstate").textContent = `${(v.held || 0).toLocaleString()} of ${(v.cap || 0).toLocaleString()} queries held${span} · ` +
    `${Math.min(matched, v.held || 0).toLocaleString()} match, the newest ${Math.min(rows.length, SHOW)} shown · ` +
    (paused ? "paused" : "following");
}

function fail(e) {
  $("rows").replaceChildren(el("tr"));
  $("rows").firstChild.append(Object.assign(el("td", "empty bad", e.message), { colSpan: 7 }));
}

async function load() {
  const g = ++gen;
  try {
    const v = await getJSON(query(0));
    if (g !== gen) return; // the filters changed while it was read
    rows = arr(v.entries);
    last = v.last || 0;
    run = String(v.run || "");
    clients = clientsOf(v);
    matched = v.matched || 0;
    nodesState(v);
    render();
  } catch (e) { if (g === gen) fail(e); }
}

async function follow() {
  if (paused) return;
  const g = gen;
  try {
    const v = await getJSON(query(last));
    if (g !== gen || paused) return;
    // The controller restarted (its IDs started over), or a node's client setting changed
    // (the rows shown may hold more than it allows now): read again.
    if (String(v.run || "") !== run || clientsOf(v) !== clients) { load(); return; }
    last = Math.max(last, v.last || 0);
    const fresh = arr(v.entries);
    matched += v.matched || 0; // the new ones that match (the oldest leave the buffer as they come)
    if (fresh.length) {
      rows = fresh.concat(rows);
      rows.sort((a, b) => (new Date(b.at) - new Date(a.at)) || (b.id - a.id));
      rows = rows.slice(0, SHOW);
      render();
    }
    nodesState(v);
  } catch (e) { console.error(e); }
}

function schedule() {
  clearInterval(timer);
  timer = setInterval(follow, EVERY);
}

let typing = null;
for (const f of Object.values(fields)) {
  f.addEventListener(f.tagName === "SELECT" ? "change" : "input", () => {
    clearTimeout(typing);
    typing = setTimeout(load, f.tagName === "SELECT" ? 0 : 300);
  });
}
$("filters").addEventListener("submit", e => { e.preventDefault(); load(); });
$("filters").addEventListener("reset", () => setTimeout(load, 0));
$("pause").onclick = () => {
  paused = !paused;
  $("pause").textContent = paused ? "Resume" : "Pause";
  if (!paused) follow();
  $("qlstate").textContent = $("qlstate").textContent.replace(/(paused|following)$/, paused ? "paused" : "following");
};

load();
schedule();
