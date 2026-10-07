// Traffic (traffic.html, beside the query log): the fleet's rates now and over the hour from /api/dashboard
// (each node's /metrics, kept in the controller's memory), small charts drawn here in SVG,
// a tile per node, and the names asked most from /api/querylog/top. Every value may be
// missing (a node on firmware without /metrics, an hour not yet seen): shown as "–". Names
// are a node's, so hostile: text only.
import { header, el, session, getJSON, uptime, nodeLabel, stateWord, stateClass } from "./common.js";

header("traffic.html");

const SVG = "http://www.w3.org/2000/svg";
const num = v => typeof v === "number" && Number.isFinite(v);
const arr = v => (Array.isArray(v) ? v : []);
const obj = v => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
const qps = v => (num(v) ? v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0) : "–");
const ms = v => (num(v) ? `${v.toFixed(v < 1 ? 2 : v < 10 ? 1 : 0)} ms` : "–");
const pct = v => (num(v) ? `${(v * 100).toFixed(v < 0.1 && v > 0 ? 2 : 1)}%` : "–");
const count = v => (num(v) ? v.toLocaleString() : "–");
function bytes(n) {
  if (!num(n)) return "–";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}
const clock = t => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function svgEl(tag, attrs) {
  const e = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  return e;
}

// niceMax rounds a chart's top up to 1, 2 or 5 times a power of ten.
function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 5, 10].map(m => m * p).find(m => m >= v);
}

// path is a line through values (null breaks it), on a W×H box with top max.
function path(values, W, H, max) {
  const n = values.length;
  let d = "", pen = false;
  values.forEach((v, i) => {
    if (!num(v)) { pen = false; return; }
    const x = n > 1 ? (i / (n - 1)) * W : W / 2, y = H - (Math.min(v, max) / max) * H;
    d += `${pen ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`;
    if (!pen) d += "h0.01"; // a point on its own shows (round caps)
    pen = true;
  });
  return d;
}

// area is the first series' fill: each run of values down to the base.
function area(values, W, H, max) {
  const n = values.length;
  let d = "", run = [];
  const flush = () => {
    if (run.length > 1) {
      d += `M${run[0][0]} ${H}` + run.map(([x, y]) => `L${x} ${y}`).join("") + `L${run[run.length - 1][0]} ${H}Z`;
    }
    run = [];
  };
  values.forEach((v, i) => {
    if (!num(v)) { flush(); return; }
    run.push([((i / (n - 1)) * W).toFixed(2), (H - (Math.min(v, max) / max) * H).toFixed(2)]);
  });
  flush();
  return d;
}

// chart is a card with a title, the latest value, an SVG line chart of the series
// ([{values, label, cls}]) over the hour's bins, and a readout of the bin under the pointer.
function chart(title, series, fmt, d, opts = {}) {
  const card = el("div", "card chart");
  const W = 300, H = 90;
  const all = series.flatMap(s => arr(s.values)).filter(num);
  const head = el("div", "charthead");
  head.append(el("h3", "", title));
  const lastOf = s => [...arr(s.values)].reverse().find(num);
  const latest = el("span", "sub", series.map(s => `${s.label} ${fmt(lastOf(s))}`).join(" · "));
  head.append(latest);
  card.append(head);
  if (!all.length) {
    card.append(el("div", "chartempty sub", "Nothing yet: it fills in as the nodes are read."));
    return card;
  }
  const max = opts.max || niceMax(Math.max(...all));
  const box = el("div", "chartbox");
  const s = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img",
    "aria-label": `${title}: ${latest.textContent}` });
  for (const f of [0.5, 1]) s.append(svgEl("line", { x1: 0, x2: W, y1: H * (1 - f), y2: H * (1 - f), class: "grid" }));
  s.append(svgEl("line", { x1: 0, x2: W, y1: H, y2: H, class: "base" }));
  series.forEach((ser, i) => {
    if (i === 0) s.append(svgEl("path", { d: area(arr(ser.values), W, H, max), class: `area ${ser.cls}` }));
    s.append(svgEl("path", { d: path(arr(ser.values), W, H, max), class: `line ${ser.cls}` }));
  });
  const guide = svgEl("line", { x1: 0, x2: 0, y1: 0, y2: H, class: "guide", visibility: "hidden" });
  s.append(guide);
  box.append(s, el("span", "ymax sub", fmt(max)));
  card.append(box);
  const axis = el("div", "axis sub");
  axis.append(el("span", "", `${Math.round(d.window_s / 60)} min ago`), el("span", "", "now"));
  card.append(axis);
  // The readout: the bin under the pointer (or the finger), else the latest.
  const read = el("div", "readout sub", " ");
  card.append(read);
  const n = d.bins;
  const show = e => {
    const r = s.getBoundingClientRect();
    const i = Math.max(0, Math.min(n - 1, Math.round(((e.clientX - r.left) / r.width) * (n - 1))));
    const x = n > 1 ? (i / (n - 1)) * W : 0;
    guide.setAttribute("x1", x); guide.setAttribute("x2", x); guide.setAttribute("visibility", "visible");
    const end = new Date(new Date(d.now).getTime() - (n - 1 - i) * d.bin_s * 1000);
    read.textContent = `${clock(end)}: ` + series.map(ser => `${ser.label} ${fmt(arr(ser.values)[i])}`).join(" · ");
  };
  s.addEventListener("pointermove", show);
  s.addEventListener("pointerdown", show);
  s.addEventListener("pointerleave", () => { guide.setAttribute("visibility", "hidden"); read.textContent = " "; });
  return card;
}

function sparkline(values) {
  const W = 120, H = 28;
  const all = arr(values).filter(num);
  const s = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "spark", "aria-hidden": "true" });
  if (all.length) {
    const max = niceMax(Math.max(...all));
    s.append(svgEl("path", { d: area(values, W, H, max), class: "area s1" }), svgEl("path", { d: path(values, W, H, max), class: "line s1" }));
  }
  return s;
}

function kpi(label, value, sub, cls = "") {
  const k = el("div", `card kpi ${cls}`);
  k.append(el("div", "sub", label), el("div", "kv", value));
  if (sub) k.append(el("div", "sub", sub));
  return k;
}

// healthOf is a node's state and its class: normal states plain, degraded warn, the rest bad.
function healthOf(n) {
  const h = typeof n.health === "string" ? n.health : "";
  return [stateWord(n.online, h), stateClass(n.online, h)];
}

function kpis(d) {
  const f = obj(d.fleet), now = obj(f.now), hour = obj(f.hour);
  const fail = num(hour.upstream_failures) && hour.upstream_failures > 0;
  const bad = (hour.servfail || 0) + (hour.dropped || 0) > 0;
  return [
    kpi("Queries a second", qps(now.qps), `hour ${qps(hour.qps)} · ${count(hour.queries)} queries`),
    kpi("Cache hit rate", pct(hour.cache_hit_rate), `now ${pct(now.cache_hit_rate)}`),
    kpi("Blocked", pct(hour.blocked_share), `now ${pct(now.blocked_share)} · ${count(hour.blocked)} in the hour`),
    kpi("Answer time p50 / p95", `${ms(hour.p50_ms)} / ${ms(hour.p95_ms)}`, `now ${ms(now.p50_ms)} / ${ms(now.p95_ms)}`),
    kpi("Forwarders p50 / p95", `${ms(hour.upstream_p50_ms)} / ${ms(hour.upstream_p95_ms)}`,
      `${count(hour.upstream_failures)} failed of ${count(hour.upstream_queries)} (${pct(hour.upstream_failure_share)})`, fail ? "warn" : ""),
    kpi("SERVFAIL / dropped", `${count(hour.servfail)} / ${count(hour.dropped)}`,
      `in the hour · now ${count(now.servfail)} / ${count(now.dropped)}`, bad ? "warn" : ""),
  ];
}

// failCls marks a failures series only when it has failures: a line at 0 is normal.
const failCls = v => (arr(v).some(x => num(x) && x > 0) ? "s3" : "s2");

function charts(d) {
  const f = obj(d.fleet);
  return [
    chart("Queries a second", [{ values: f.qps, label: "all", cls: "s1" }, { values: f.blocked_qps, label: "blocked", cls: "s2" }], qps, d),
    chart("Answer time p95", [{ values: f.p95_ms, label: "answer", cls: "s1" }, { values: f.upstream_p95_ms, label: "forwarders", cls: "s2" }], ms, d),
    chart("Cache hit rate", [{ values: f.cache_hit_rate, label: "hits", cls: "s1" }], pct, d, { max: 1 }),
    chart("Failures a minute", [{ values: f.upstream_failures, label: "forwarders", cls: failCls(f.upstream_failures) },
      { values: f.servfail, label: "SERVFAIL", cls: failCls(f.servfail) }], count, d),
  ];
}

// bar is a plan against capacity: grey, however full; only more than there is is a warning.
function bar(used, total, label) {
  const out = el("div", "barwrap");
  const w = el("div", "bar"), fill = el("div", "fill");
  const p = num(used) && total > 0 ? Math.min(100, (used / total) * 100) : 0;
  fill.style.width = `${p}%`;
  if (num(used) && used > total) fill.classList.add("high");
  w.append(fill);
  out.append(w, el("div", "sub", label));
  return out;
}

function fact(rows) {
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

function tile(n) {
  const t = el("div", "card tile");
  const [h, cls] = healthOf(n);
  const head = el("div", "tilehead");
  const who = el("div", "who");
  who.append(nodeLabel(n.addr || n.id, n.name));
  head.append(who, el("span", `pill ${cls}`, h));
  t.append(head);
  if (arr(n.reasons).length) t.append(el("div", "sub reasons", arr(n.reasons).join(", ")));

  const m = obj(n.metrics), g = obj(n.gauges), now = n.now ? obj(n.now) : null, hour = obj(n.hour);
  const big = el("div", "tileqps");
  const q = el("div");
  const rate = now ? now.qps : m.state === "ok" ? null : n.status_qps;
  q.append(el("span", "kv", qps(rate)), el("span", "sub", " q/s"));
  big.append(q, sparkline(n.qps));
  t.append(big);

  if (m.state === "unsupported") {
    t.append(el("div", "sub warn", "No /metrics: firmware from before it (update it). Queries a second from /status."));
  } else if (m.state === "error") {
    t.append(el("div", "sub bad clip", `/metrics: ${m.error || "failed"}`));
  } else if (!m.state) {
    t.append(el("div", "sub", n.online ? "Not read yet." : "Not answering: not read."));
  }
  const rows = [];
  if (now || num(hour.secs) && hour.secs > 0) {
    rows.push(["Answer p95", `${ms(now && now.p95_ms)} now · ${ms(hour.p95_ms)} hour`]);
    rows.push(["Blocked", `${pct(now && now.blocked_share)} now · ${pct(hour.blocked_share)} hour`]);
  }
  if (num(g.fwd_slots)) {
    // The forward loop: upstream queries outstanding (the default forwarders' against their
    // cap, half the table), and what didn't go well over the hour.
    const busy = num(g.fwd_inflight) && num(g.fwd_group_cap) && g.fwd_inflight * 2 > g.fwd_group_cap;
    rows.push(["Upstream in flight", `${count(g.fwd_inflight)} of ${count(g.fwd_group_cap)}` +
      `${num(g.fwd_inflight_zones) && g.fwd_inflight_zones ? ` · zones ${count(g.fwd_inflight_zones)}` : ""}` +
      ` · peak ${count(g.fwd_inflight_peak)} of ${count(g.fwd_slots)}`, busy ? "warn" : ""]);
    const h = hour, shed = (now && now.fwd_shed) || hour.fwd_shed;
    rows.push(["Shed", `${count(now && now.fwd_shed)} now · ${count(h.fwd_shed)} hour`, shed ? "warn" : ""]);
    rows.push(["Forwarder timeouts", `${count(now && now.upstream_timeouts)} now · ${count(h.upstream_timeouts)} hour` +
      ` · answer p95 ${ms(h.upstream_p95_ms)}`]);
    const errs = h.select_errors ? ` · ${count(h.select_errors)} select errors` : "";
    rows.push(["Unanswered upstream", `${count(h.fwd_expired)} hour · ${count(h.tcp_retries)} TCP retries${errs}`,
      h.select_errors ? "bad" : ""]);
  }
  if (num(g.heap_free) || num(n.status_heap_free)) {
    const free = num(g.heap_free) ? g.heap_free : n.status_heap_free;
    rows.push(["Internal RAM", num(g.cap_internal) && num(g.plan_internal)
      ? bar(g.plan_internal, g.cap_internal, `planned ${bytes(g.plan_internal)} of ${bytes(g.cap_internal)} · ${bytes(free)} free`)
      : `${bytes(free)} free`, free < 16384 ? "bad" : ""]);
  }
  if (num(g.psram_free)) {
    rows.push(["PSRAM", num(g.cap_psram) && num(g.plan_psram) && g.cap_psram > 0
      ? bar(g.plan_psram, g.cap_psram, `planned ${bytes(g.plan_psram)} of ${bytes(g.cap_psram)} · ${bytes(g.psram_free)} free`)
      : `${bytes(g.psram_free)} free`]);
  }
  if (num(g.mhz_max)) {
    const busy = now && num(now.busy_share) ? ` · DNS ${pct(now.busy_share)} of the time` : "";
    rows.push(["CPU clock", `${g.mhz_max} MHz${num(g.mhz_idle) ? `, idle ${g.mhz_idle}` : ""}${busy}`]);
  }
  if (num(g.uptime_s)) rows.push(["Up", uptime(Math.round(g.uptime_s))]);
  const ql = obj(n.querylog);
  rows.push(["Query log", ql.state === "ok" ? (ql.enabled ? `on, clients ${ql.client || "–"}` : "off")
    : ql.state === "unsupported" ? "none (firmware from before it)" : ql.state === "error" ? "read failed" : "–",
    ql.state === "error" ? "bad" : ""]);
  if (rows.length) t.append(fact(rows));
  return t;
}

function topList(title, items, empty) {
  const c = el("div", "card toplist");
  c.append(el("h3", "", title));
  if (!items.length) { c.append(el("div", "sub", empty)); return c; }
  const max = items[0].count || 1;
  const ol = el("ol");
  for (const it of items) {
    const li = el("li");
    const a = el("a", "mono", String(it.name));
    a.href = `querylog.html?name=${encodeURIComponent(String(it.name))}`;
    const w = el("div", "bar"), f = el("div", "fill");
    f.style.width = `${(it.count / max) * 100}%`;
    w.append(f);
    const row = el("div", "toprow");
    row.append(a, el("span", "sub", count(it.count)));
    li.append(row, w);
    ol.append(li);
  }
  c.append(ol);
  return c;
}

async function tops() {
  const box = document.getElementById("tops");
  const s = await session;
  if (!s.logged_in) {
    box.replaceChildren(el("div", "card empty", s.password_set
      ? "Log in to see the names asked: they come from the query log."
      : "The names asked come from the query log, which needs a login: set a password (espdns passwd: docs/getting-started.md, step 6), then log in."));
    return;
  }
  try {
    const t = await getJSON("api/querylog/top");
    const span = t.oldest && t.newest ? `${count(t.entries)} queries from ${clock(t.oldest)} to ${clock(t.newest)}` : "no queries yet";
    const note = el("p", "sub topnote", `Over what the controller holds of the query log: ${span}.`);
    box.replaceChildren(topList("Asked most", arr(t.queried), "Nothing yet."),
      topList("Blocked most", arr(t.blocked), "Nothing blocked."), note);
  } catch (e) {
    box.replaceChildren(el("div", "card empty bad", e.message));
  }
}

let last = "";
async function refresh() {
  try {
    const d = await getJSON("api/dashboard");
    const key = JSON.stringify(d);
    if (key !== last) {
      last = key;
      document.getElementById("kpis").replaceChildren(...kpis(d));
      document.getElementById("charts").replaceChildren(...charts(d));
      const nodes = arr(d.nodes);
      document.getElementById("tiles").replaceChildren(...(nodes.length ? nodes.map(tile)
        : [el("div", "card empty", "No nodes yet: they are found over mDNS or listed in settings.json.")]));
    }
    const f = obj(d.fleet);
    document.getElementById("updated").textContent =
      `${f.reading || 0} of ${f.nodes || 0} node(s) report /metrics · updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    document.getElementById("updated").textContent = `Not updated: ${e.message}`;
  }
}

refresh();
tops();
setInterval(refresh, 10000);
setInterval(tops, 30000);
