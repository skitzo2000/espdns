// The node details (nodes.html, opened from a node on the Nodes page until the node page is
// built; #<node ID or address> opens that node's detail): the fleet line (how many nodes, how
// many need attention, queries a second, failures), one row per node from /api/nodes with its
// state and the reason when it isn't healthy, and a detail view per node from its last
// /status, with its actions (identify, flush, a pending reboot), each a job whose progress
// shows in the row.
// Every field may be missing on older firmware: shown as "–", never an error.
import { header, el, secs, uptime, ago, session, releaseKey, post, getJSON, confirmDialog, onNodes, nodeName, nodeLabel,
  ended, jobPill, jobParams, stateWord, stateClass, answering, events } from "./common.js";

header("nodes.html");

// What each health state and reason means (docs/design.md, Health and fault indication).
const STATES = {
  booting: "Before the listeners open. Not answering.",
  healthy: "Everything its config enables is running.",
  degraded: "Answering, but something enabled failed (see the reasons).",
  "no network": "Link down or no address. Not answering.",
  fault: "The listeners failed, or stalled and the node stopped rebooting for it. Not answering.",
  updating: "Receiving a release. Answering.",
};
// kind: fault and no network stop answering; warn degrades; info doesn't.
const REASONS = {
  "listeners failed": ["bad", "A DNS listener failed to open."],
  "listeners stalled": ["bad", "The listeners stalled after 3 stall reboots in a row: the node stays up for the controller rather than boot-loop."],
  "no link": ["bad", "No Ethernet link, or not associated with the Wi-Fi network."],
  "no address": ["bad", "The network interface has no IPv4 address."],
  "sd card": ["warn", "The board has a slot, but no card, or it failed or timed out mounting. Hosted zones and blocking are unavailable; secondary zones are kept in RAM only. Swap the card or the node."],
  blocking: ["warn", "An installed blocklist or the overrides failed to load, or a sector read failed."],
  "zone expired": ["warn", "A secondary zone passed its EXPIRE without a refresh from the primary."],
  "zone refresh failing": ["warn", "A secondary zone's SOA checks or transfers failed 3 times in a row."],
  "forwarders failing": ["warn", "5 upstream queries in a row went unanswered over at least 30 s (default forwarders only)."],
  "forwarder task stalled": ["warn", "The task that asks the forwarders missed its watchdog: forwarded queries go unanswered, cached and local ones are still answered. The node doesn't reboot for it."],
  "forwarders slow": ["warn", "The default forwarders are too slow for the queries the node is asked: a query to them was shed (SERVFAIL at once, past their cap of half the upstream query table) in the last 30 s, or they held over half that cap for 10 s, or of at least 5 upstream queries in the last 30 s most took longer than one try's timeout (upstream_timeout_ms) or went unanswered. Cached and local answers aren't affected. The node's tile on the Traffic page shows its forward loop; check the forwarders, or the timeout."],
  "low memory": ["warn", "Under 16 KB of internal RAM free."],
  "no board definition": ["warn", "No board definition: the node runs on its image's defaults."],
  config: ["warn", "The stored node config isn't in use (refused, unreadable, failed its trial, or its memory plan doesn't fit the board): the node runs on the older config or the firmware defaults. See the config error."],
  "hosted zones": ["warn", "The hosted zones bundle failed to load, or a zone in it isn't served because the node config names it too."],
  "service failed": ["warn", "A service's start failed 3 times in a row, or its task missed its watchdog."],
  "older copy": ["warn", "The newest blocklist, overrides or hosted zones bundle on the SD card is corrupt, unreadable or too big: the node runs the older copy it kept. See the fallback under Blocking or Zones; push it again."],
  "config on trial": ["info", "A new address waits to be reached; if it isn't, the node goes back to its previous config. Not degraded."],
  "reboot pending": ["info", "A release waits for a reboot, which the controller decides on. Not degraded."],
  "service restarting": ["info", "A service whose start failed is being started again (fewer than 3 times in a row). Not degraded."],
  degraded: ["warn", "Firmware from before health reasons: it says only that it is degraded."],
};
const REBOOT_REASONS = {
  "config: address": "The address, netmask or gateway changed.",
  "config: wifi": "The Wi-Fi network changed.",
  "config: zones": "Secondary zones, the primary or forward zones changed.",
  "blocklist: size": "A new blocklist whose two copies don't fit for a live swap.",
  firmware: "A staged firmware update.",
};

const COLS = 7;

// Actions: the job each node's last action is (by node key), the login and the release key.
const ACTIONS = { identify: "Identify", flush: "Flush cache", "reboot-pending": "Reboot (pending)" };
const acts = new Map();      // key -> { kind, job, line, error }
const identifySecs = new Map(); // key -> the seconds typed
let sess = {}, keyInfo = null;
const jobNode = j => jobParams(j).node;
const open = new Set();    // nodes whose detail is shown, by key
try { if (location.hash.length > 1) open.add(decodeURIComponent(location.hash.slice(1))); } catch { /* a bad hash: none */ }
const rawOpen = new Set(); // nodes whose raw /status is shown

const key = n => n.id || n.addr;
// lookup reads a meaning table by a node's string: only its own entries ("constructor" or
// "__proto__" from a node is unknown, not Object's).
const lookup = (table, k) => (typeof k === "string" && Object.hasOwn(table, k) ? table[k] : undefined);
const has = v => v !== undefined && v !== null && v !== "";
const dash = v => (has(v) ? String(v) : "–");
const num = v => (typeof v === "number" ? v.toLocaleString() : "–");
const yes = (v, t = "yes", f = "no") => (v === true ? t : v === false ? f : "–");
const obj = v => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
const arr = v => (Array.isArray(v) ? v : []);
function bytes(n) {
  if (typeof n !== "number") return "–";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}
const kb = v => (typeof v === "number" ? `${v.toLocaleString()} KB` : "–");
// Sequence numbers are milliseconds since 1970 (time-based, so a new controller's are newer).
function seq(v) {
  if (typeof v !== "number") return "–";
  if (v === 0) return "none";
  return v > 1e12 ? `${v} · ${new Date(v).toLocaleString()}` : String(v);
}
const sha = v => (has(v) ? String(v).slice(0, 16) : "–");

// stateOf is a node's health state as /status says it; cls is "" (normal), warn or bad.
function stateOf(n) {
  const s = n.status;
  if (!s) return { text: stateWord(false), cls: stateClass(false), reasons: [] };
  const h = s.health;
  let st;
  if (h && typeof h === "object" && h.state !== undefined && h.state !== null && h.state !== "") {
    st = { text: stateWord(true, h.state), cls: stateClass(true, h.state), reasons: arr(h.reasons), answering: h.answering };
  } else {
    // Firmware from before health states: the degraded flag and expired zones.
    const expired = arr(s.zones).filter(z => z && z.expired).length;
    st = s.degraded ? { text: "degraded", cls: "warn", reasons: ["degraded"] }
      : expired ? { text: "degraded", cls: "warn", reasons: ["zone expired"] }
      : { text: "answering", cls: "", reasons: [] };
    st.legacy = true;
  }
  if (!n.online) return { ...st, text: stateWord(false), cls: stateClass(false), was: st.text };
  return st;
}

function reasonChip(r) {
  const [kind, meaning] = lookup(REASONS, r) || ["warn", "A reason this controller doesn't know yet."];
  const c = el("span", `chip ${kind}`, r);
  c.title = meaning;
  return c;
}

// summary is the row's state and why: the state shown (a node found but not adopted says
// so), its class, and the reasons, each [text, class, meaning] (class "" is normal).
function summary(n) {
  const st = stateOf(n), s = obj(n.status), cfg = obj(s.config), reboot = obj(s.reboot);
  const out = { text: st.text, cls: st.cls, reasons: [] };
  const add = (text, cls, title) => out.reasons.push([text, cls, title]);
  if (!n.online) {
    add(n.status ? `last seen ${ago(n.last_seen)}` : "never answered", "", dash(n.error));
    return out;
  }
  if (n.error) add("last poll failed", "warn", n.error);
  for (const r of st.reasons) {
    if (st.legacy && r === "degraded") continue;
    const [kind, meaning] = lookup(REASONS, r) || ["warn", "A reason this controller doesn't know yet."];
    add(r, kind === "info" ? "" : kind, meaning);
  }
  if (reboot.pending === true && !st.reasons.includes("reboot pending")) add("reboot pending", "", lookup(REASONS, "reboot pending")[1]);
  if (st.legacy) add("old firmware", "warn", "Firmware from before health states: update it.");
  if (has(cfg.source) && cfg.source !== "node") {
    if (!st.cls && (st.text === "healthy" || st.text === "answering")) out.text = "not adopted";
    else add("not adopted", "", "");
    out.adopt = true;
  }
  if (n.source === "mdns") add("not in settings", "", "Found over mDNS only: rollouts don't count or change it; add it to settings.json.");
  return out;
}

function cell(tr, main, sub, cls) {
  const td = el("td", cls || "");
  const m = el("div");
  if (main instanceof Node) m.append(main); else m.textContent = main;
  td.append(m);
  if (sub) td.append(sub instanceof Node ? sub : el("div", "sub", sub));
  tr.append(td);
  return td;
}

function row(n) {
  const s = n.status || {};
  const sm = summary(n);
  const k = key(n), isOpen = open.has(k);
  const tr = el("tr", `node${n.online ? "" : " stale"}${isOpen ? " open" : ""}`);
  tr.tabIndex = 0;
  tr.dataset.key = k;
  tr.setAttribute("aria-expanded", isOpen);
  const toggle = () => { isOpen ? open.delete(k) : open.add(k); render(); };
  tr.addEventListener("click", e => { if (!e.target.closest("a, summary")) toggle(); });
  tr.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });

  tr.append(el("td", "tog", isOpen ? "▾" : "▸"));
  const nameTd = el("td", "namecell");
  nameTd.append(nodeLabel(n));
  tr.append(nameTd);
  cell(tr, dash(s.board), dash(s.image), "wide mid");

  const stTd = cell(tr, el("span", `pill ${sm.cls}`, sm.text), null, "stcell");
  if (sm.reasons.length) {
    const why = el("div", "why");
    sm.reasons.forEach(([text, cls, title], i) => {
      if (i) why.append(", ");
      const r = el("span", cls, text);
      if (title) r.title = title;
      why.append(r);
    });
    stTd.append(why);
  }
  if (sm.adopt) {
    const a = el("a", "act", "Adopt it");
    a.href = "adopt.html";
    stTd.append(a);
  }
  const act = actStatus(k, true);
  if (act) stTd.append(act);

  const fw = el("div", "sub", has(s.elf_sha256) ? `${String(s.elf_sha256).slice(0, 8)} · ${dash(s.slot)}` : "");
  if (has(s.ota_state) && s.ota_state !== "valid") fw.append(" · ", el("span", "warn", s.ota_state));
  cell(tr, has(s.version) ? `v${s.version}` : "–", fw, "wide wrap");
  const boot = el("div", "sub", has(s.boot_ms) ? `boot ${secs(s.boot_ms)}` : "");
  if (s.boot_ms > (s.boot_limit_ms || 15000)) boot.className = "sub bad";
  cell(tr, uptime(s.uptime_s), boot, "wide mid");
  cell(tr, n.online && typeof n.qps === "number" ? n.qps.toFixed(1) : "–", null, "num");
  return tr;
}

// facts is a two-column table: [label, value, class?]; a value may be a DOM node.
function facts(rows) {
  const t = el("table", "facts");
  for (const [label, value, cls] of rows) {
    const tr = el("tr");
    tr.append(el("th", "", label));
    const td = el("td", cls || "");
    if (value instanceof Node) td.append(value); else td.textContent = value;
    tr.append(td);
    t.append(tr);
  }
  return t;
}

// grid is a small table with a header row.
function grid(head, rows, empty) {
  if (!rows.length) return el("div", "sub", empty);
  const t = el("table", "mini");
  const hr = el("tr");
  hr.append(...head.map(h => el("th", "", h)));
  t.append(hr);
  for (const r of rows) {
    const tr = el("tr");
    for (const v of r) {
      const td = el("td");
      if (v instanceof Node) td.append(v); else td.textContent = v;
      tr.append(td);
    }
    t.append(tr);
  }
  const w = el("div", "scroll");
  w.append(t);
  return w;
}

// bar shows used of total; over 95% is shown as a warning, unless fullOK (a plan, or a share
// taken whole at the start, where full is normal: then only more than planned is).
function bar(used, total, label, fullOK = false) {
  const w = el("div", "bar");
  const f = el("div", "fill");
  const p = typeof used === "number" && total > 0 ? Math.min(100, (used / total) * 100) : 0;
  f.style.width = `${p}%`;
  if (fullOK ? used > total : p > 95) f.classList.add("high");
  w.append(f);
  const out = el("div", "barwrap");
  out.append(w, el("div", "sub", label));
  return out;
}

function section(title, ...children) {
  const s = el("section", "sect");
  s.append(el("h3", "", title), ...children.filter(Boolean));
  return s;
}

// stateText is a part's state: normal ones plain, off or none muted, a failure bad.
const stateText = (v, good = ["on", "running", "mounted"]) =>
  has(v) ? el("span", good.includes(v) ? "" : v === "failed" ? "bad" : v === "off" || v === "none" ? "muted" : "warn", v) : "–";

// configLink opens the config editor on the node's config (configs.html).
function configLink(n) {
  const d = el("div", "act");
  const a = el("a", "", "Edit or push its config");
  a.href = `configs.html#node=${encodeURIComponent(n.addr)}`;
  d.append(a);
  return d;
}

function detail(n) {
  const s = n.status;
  const wrap = el("div", "nodedetail");
  if (!n.online || n.error) {
    const b = el("div", `banner ${n.online ? "warn" : "bad"}`);
    b.textContent = !s ? `Never answered: ${dash(n.error)} (last tried ${ago(n.polled)}).`
      : !n.online ? `Not answering since ${new Date(n.last_seen).toLocaleString()} (${dash(n.error)}). What follows is its last /status, ${ago(n.last_seen)}.`
      : `The last poll failed (${n.error}); showing the /status from ${ago(n.last_seen)}.`;
    wrap.append(b);
  }
  if (!s) return wrap;

  const st = stateOf(n);
  const net = obj(s.net), cfg = obj(s.config), reboot = obj(s.reboot), mem = obj(s.memory), cpu = obj(s.cpu);
  const blk = obj(s.blocking), hosted = obj(s.hosted), time = obj(s.time), sd = obj(s.sd), led = obj(s.led);
  const q = obj(s.queries), seqs = obj(s.seq);
  const sects = el("div", "sects");
  sects.append(actionsSection(n));

  // Health
  const stateName = st.was || st.text;
  const reasons = st.reasons.length
    ? grid(["Reason", "What it means"], st.reasons.map(r => [reasonChip(r), (lookup(REASONS, r) || ["", "Unknown to this controller."])[1]]), "")
    : el("div", "sub", "No reasons.");
  sects.append(section("Health",
    facts([
      ["State", el("span", `pill ${n.online ? st.cls : "bad"}`, n.online ? st.text : `offline (was ${stateName})`)],
      ["Means", lookup(STATES, stateName) || (st.legacy ? "Firmware from before health states: answering, and its degraded flag." : "–")],
      ["Answering", n.online ? yes(st.answering ?? true) : "no (not reached)"],
      ["Last seen", `${ago(n.last_seen)}${n.online ? "" : " (offline)"}`],
    ]), reasons));

  // Network
  const netRows = [
    ["Kind", dash(net.kind)],
    ["Link", yes(net.link, "up", "down"), net.link === false ? "bad" : ""],
    ["Address", dash(s.ip)],
    ["Config", cfg.address ? `${cfg.address}${has(cfg.ip) ? ` ${cfg.ip}` : ""}` : "–"],
    ["From", dash(cfg.address_from)],
    ["Gateway", dash(cfg.gateway)],
    ["MAC", dash(net.mac)],
    ["Hostname", dash(net.hostname)],
    ["Polled at", `${n.addr} (${n.source === "mdns" ? "found by mDNS" : "listed in settings"})`],
  ];
  if (net.kind === "wifi") {
    const rssi = net.rssi;
    netRows.push(
      ["Signal", typeof rssi === "number" ? `${rssi} dBm` : "–", typeof rssi === "number" ? (rssi < -75 ? "bad" : rssi < -67 ? "warn" : "") : ""],
      ["Access point", dash(net.ap)],
      ["Channel", dash(net.channel)],
      ["Connects", num(net.connects)],
      ["Drops", num(net.drops), net.drops > 0 ? "warn" : ""],
      ["Failed joins", num(net.failed_attempts)],
      ["Last join", has(net.last_join_ms) ? secs(net.last_join_ms) : "–"],
      ["Last error", has(net.last_error) && net.last_error_code ? `${net.last_error} (${net.last_error_code})` : "none"],
    );
  }
  sects.append(section("Network", facts(netRows)));

  // Firmware
  sects.append(section("Firmware", facts([
    ["Version", has(s.version) ? `${dash(s.project)} v${s.version}` : "–"],
    ["ELF SHA-256", dash(s.elf_sha256), "mono"],
    ["Built", dash(s.built)],
    ["ESP-IDF", dash(s.idf)],
    ["Slot", dash(s.slot)],
    ["OTA state", dash(s.ota_state), has(s.ota_state) && s.ota_state !== "valid" ? "warn" : ""],
    ["Image", dash(s.image)],
    ["Board", has(s.board_source) ? `${dash(s.board)} (${s.board_source})` : dash(s.board)],
    ...(has(s.board_error) ? [["Board note", s.board_error, "warn"]] : []),
    ["Keys", arr(s.keys).join(", ") || "–", "mono"],
  ])));

  // Seqs, config and reboot pending
  const seqNames = ["firmware", "config", "zones", "blocklist", "overrides", "control"];
  const rbRows = arr(reboot.reasons).map(r => [el("span", "chip", r), lookup(REBOOT_REASONS, r) || "–"]);
  sects.append(section("Releases and config",
    facts(seqNames.map(k => [k, seq(seqs[k]), "mono"])),
    facts([
      ["Config", has(cfg.source) ? `${cfg.source}${has(cfg.name) ? ` (${cfg.name})` : ""}` : "–"],
      ["Config seq", seq(cfg.seq), "mono"],
      ["Slot / storage", has(cfg.storage) ? `${dash(cfg.slot)} · ${cfg.storage}` : "–"],
      ["On trial", yes(cfg.trial)],
      ["Config error", has(cfg.error) ? cfg.error : Object.keys(cfg).length ? "none" : "–", has(cfg.error) ? "bad" : ""],
      ["Reboot pending", reboot.pending === true ? `yes, for ${uptime(reboot.since_s)}` : yes(reboot.pending)],
    ]),
    rbRows.length ? grid(["Waits for a reboot", "Because"], rbRows, "") : null,
    configLink(n)));

  // Services
  const svc = arr(s.services).map(v => {
    const m = obj(v && v.memory);
    // The dns service takes its share whole at the start (the cache and the query buffers:
    // the query path allocates nothing), so 100% is its normal state, not a warning.
    const whole = v && v.name === "dns";
    const used = typeof m.planned === "number" && m.planned > 0 && typeof m.allocated === "number"
      ? bar(m.allocated, m.planned, `${bytes(m.allocated)} · ${Math.round((m.allocated / m.planned) * 100)}%${whole ? " (taken whole at start)" : ""}`, whole)
      : bytes(m.allocated);
    return [dash(v && v.name), stateText(v && v.state), bytes(m.planned), used];
  });
  sects.append(section("Services", grid(["Service", "State", "Planned", "Allocated"], svc,
    "Not reported (firmware from before services: it runs every service it has).")));

  // Memory plan
  const board = obj(mem.board), inn = obj(mem.internal), ps = obj(mem.psram);
  const pool = p => typeof p.capacity === "number"
    ? bar(p.planned, p.capacity, `${bytes(p.planned)} planned of ${bytes(p.capacity)}`, true) : "–";
  sects.append(section("Memory plan",
    Object.keys(board).length ? facts([
      ["PSRAM", kb(board.psram_kb)],
      ["Internal", kb(board.internal_kb)],
      ["Cache", `${kb(board.cache_kb)}, ${num(board.cache_entries)} entries`],
      ["Blocklist", `${kb(board.blocklist_kb)}, index ${kb(board.blocklist_index_kb)}`],
      ["Hosted zones", kb(board.hosted_zones_kb)],
      ["Secondary zones", kb(board.secondary_zones_kb)],
    ]) : el("div", "sub", "No memory plan (firmware from before it)."),
    facts([
      ["Internal plan", pool(inn)],
      ["PSRAM plan", pool(ps)],
      ["Heap free", bytes(s.heap_free), s.heap_free < 16384 ? "bad" : ""],
      ["PSRAM free", bytes(s.psram_free)],
    ])));

  // Clock
  const hold = h => { h = obj(h); return has(h.holds) ? `${num(h.holds)} holds, ${secs(h.busy_ms)}${s.uptime_s > 0 && typeof h.busy_ms === "number" ? ` (${((h.busy_ms / 10) / s.uptime_s).toFixed(2)}% of uptime)` : ""}` : "–"; };
  sects.append(section("Clock", Object.keys(cpu).length ? facts([
    ["Scaling (DFS)", yes(cpu.dfs, "on", "off")],
    ["From", dash(cpu.from)],
    ["Max / min / idle", has(cpu.max_mhz) ? `${cpu.max_mhz} / ${dash(cpu.min_mhz)} / ${dash(cpu.idle_mhz)} MHz` : "–"],
    ["Power management", yes(cpu.pm, "built in", "not built")],
    ["Error", has(cpu.error) ? cpu.error : "none", has(cpu.error) ? "bad" : ""],
    ["DNS hold", hold(cpu.dns)],
    ["Work hold", hold(cpu.work)],
  ]) : el("div", "sub", "Not reported (firmware from before clock scaling).")));

  // Blocking
  const list = l => {
    l = obj(l);
    return facts([
      ["State", stateText(l.state)],
      ["Entries", num(l.entries)],
      ["Tier", dash(l.tier)],
      ["Seq", seq(l.seq), "mono"],
      ["Size", has(l.bytes) ? `${bytes(l.bytes)}${has(l.data_bytes) ? ` (data ${bytes(l.data_bytes)}, index ${bytes(l.internal_bytes)})` : ""}` : "–"],
      ["SHA-256", sha(l.sha256), "mono"],
      ...(has(l.slot) ? [["Slot", l.slot >= 0 ? String(l.slot) : "none"]] : []),
      ...(l.reverted_from > 0 ? [["Reverted from", seq(l.reverted_from), "mono"]] : []),
      ...(has(l.fallback) ? [["Older copy", `the newest isn't used: ${l.fallback}`, "warn"]] : []),
      ...(has(l.error) ? [["Error", l.error, "bad"]] : []),
    ]);
  };
  const blocking = Object.keys(blk).length ? [
    el("h4", "", "List"), list(blk.list),
    el("h4", "", "Overrides"), list(blk.overrides),
    facts([
      ["Paused", blk.paused_s > 0 ? `yes, ${uptime(blk.paused_s)} left` : yes(blk.paused_s === undefined ? undefined : false)],
      ["Blocked", `${num(blk.blocked)} (CNAME ${num(blk.cname_blocked)}), allowed ${num(blk.allowed)}`],
      ["Sector reads", num(blk.sector_reads)],
      ["Errors", num(blk.errors), blk.errors > 0 ? "bad" : ""],
    ]),
  ] : [el("div", "sub", "Not reported (firmware from before blocking).")];
  sects.append(section("Blocking", ...blocking));

  // Zones: the serial under the name, so four columns fit a section's width.
  const zoneName = z => {
    const d = el("div", "", dash(z.name));
    d.append(el("div", "sub", `serial ${dash(z.serial)}`));
    return d;
  };
  const sec = arr(s.zones).map(z => {
    z = obj(z);
    const xf = el("span", "", `${num(z.transfers)} / `);
    xf.append(z.fails > 0 ? el("span", "warn", num(z.fails)) : num(z.fails));
    return [zoneName(z), num(z.records), xf, z.expired ? el("span", "bad", "yes") : yes(z.expired)];
  });
  const hz = arr(hosted.zones).map(z => { z = obj(z); return [zoneName(z), num(z.records)]; });
  const fz = arr(s.forward_zones).map(z => (typeof z === "string" ? [z, "–"] : (z = obj(z), [dash(z.name), dash(z.forwarder)])));
  sects.append(section("Zones",
    el("h4", "", "Secondary"),
    grid(["Zone and serial", "Records", "Transfers / fails", "Expired"], sec, "None."),
    el("h4", "", "Forward"),
    s.forward_zones !== undefined ? grid(["Zone", "Forwarder"], fz, "None.")
      : el("div", "sub", "Not reported (firmware from before forward zones in /status)."),
    el("h4", "", "Hosted"),
    Object.keys(hosted).length ? facts([
      ["State", stateText(hosted.state)],
      ["Seq", seq(hosted.seq), "mono"],
      ["Size", has(hosted.limit_bytes) ? `${bytes(hosted.bytes)} of ${bytes(hosted.limit_bytes)}` : bytes(hosted.bytes)],
      ["Slot", hosted.slot >= 0 ? String(hosted.slot) : "none"],
      ...(hosted.reverted_from > 0 ? [["Reverted from", seq(hosted.reverted_from), "mono"]] : []),
      ["SHA-256", sha(hosted.sha256), "mono"],
      ...(has(hosted.fallback) ? [["Older copy", `the newest isn't used: ${hosted.fallback}`, "warn"]] : []),
      ...(has(hosted.error) ? [["Error", hosted.error, "bad"]] : []),
    ]) : el("div", "sub", "Not reported (firmware from before hosted zones)."),
    hosted.zones ? grid(["Zone and serial", "Records"], hz, "No hosted zones in the bundle.") : null));

  // Time, boot and the rest
  sects.append(section("Time", Object.keys(time).length ? facts([
    ["Synced", yes(time.synced), time.synced === false ? "warn" : ""],
    ["Local", dash(time.local)],
    ["UTC", dash(time.utc)],
    ["Zone", dash(time.tz), "mono"],
    ["Since sync", has(time.since_sync_s) ? uptime(time.since_sync_s) : "–"],
    ["Servers", arr(time.servers).join(", ") || "–"],
  ]) : el("div", "sub", "Not reported (firmware from before the clock).")));

  const steps = obj(s.boot);
  sects.append(section("Boot and board", facts([
    ["Boot", has(s.boot_ms) ? `${secs(s.boot_ms)} of ${secs(s.boot_limit_ms || 15000)}` : "–", s.boot_ms > (s.boot_limit_ms || 15000) ? "bad" : ""],
    ["Steps", Object.keys(steps).length ? Object.entries(steps).map(([k, v]) => `${k} ${v == null ? "–" : secs(v)}`).join(", ") : "–"],
    ["Reset", dash(s.reset)],
    ["Uptime", uptime(s.uptime_s)],
    ["SD card", has(sd.state) ? `${sd.state}${sd.timed_out ? ", timed out" : ""}` : "–", sd.state === "failed" || sd.timed_out ? "bad" : ""],
    ["LED", has(led.kind) ? `${led.kind}${led.identify_s > 0 ? `, identifying (${led.identify_s} s left)` : ""}` : "–"],
  ])));

  sects.append(section("Queries", facts([
    ["Rate", n.online && typeof n.qps === "number" ? `${n.qps.toFixed(1)} a second (last two polls)` : "–"],
    ["Total", `${num(q.total)} (UDP ${num(q.udp)}, TCP ${num(q.tcp)})`],
    ["Answered here", `${num(q.auth)} authoritative, ${num(q.cache_hits)} from cache`],
    ["Forwarded", num(q.forwarded)],
    ["NXDOMAIN / SERVFAIL / REFUSED", `${num(q.nxdomain)} / ${num(q.servfail)} / ${num(q.refused)}`],
    ["NOTIFYs", num(q.notifies)],
    ["Dropped", num(q.dropped), q.dropped > 0 ? "warn" : ""],
  ])));

  wrap.append(sects);
  const raw = el("details");
  raw.open = rawOpen.has(key(n));
  raw.addEventListener("toggle", () => { raw.open ? rawOpen.add(key(n)) : rawOpen.delete(key(n)); });
  raw.append(el("summary", "", "Raw /status"), el("pre", "raw", JSON.stringify(s, null, 2)));
  wrap.append(raw);
  return wrap;
}

let nodes = null; // null until the first read
function render() {
  const body = document.getElementById("nodes");
  if (!nodes) return;
  if (!nodes.length) {
    const tr = el("tr"), td = el("td", "empty", "No nodes yet: a node shows here once it is found over mDNS or listed in settings.json. A new board is installed from the ");
    const a = el("a", "", "Builder");
    a.href = "builder.html";
    td.append(a, ".");
    td.colSpan = COLS;
    tr.append(td);
    body.replaceChildren(tr);
    return;
  }
  const rows = [];
  for (const n of nodes) {
    // A node's /status is the node's to send: one that breaks the page shows as an error
    // in its own row, and the others still show.
    try {
      rows.push(row(n));
    } catch (e) {
      console.error(e);
      const tr = el("tr", "node"), td = el("td", "bad", `${dash(n.addr)}: can't show this node's /status (${e.message}).`);
      td.colSpan = COLS;
      tr.append(td);
      rows.push(tr);
      continue;
    }
    if (open.has(key(n))) {
      const tr = el("tr", "detailrow"), td = el("td");
      tr.dataset.key = key(n);
      td.colSpan = COLS;
      try {
        td.append(detail(n));
      } catch (e) {
        console.error(e);
        td.append(el("div", "banner bad", `Can't show this node's /status: ${e.message}.`));
      }
      tr.append(td);
      rows.push(tr);
    }
  }
  // Every poll rebuilds the rows: keep the keyboard focus on the row (or the raw /status
  // toggle) it was on.
  const f = document.activeElement, at = f && f.closest && f.closest("tr[data-key]");
  const was = at && { key: at.dataset.key, summary: f.tagName === "SUMMARY", fid: f.dataset && f.dataset.fid };
  const sel = was && was.fid && f.tagName === "INPUT" ? [f.selectionStart, f.selectionEnd] : null;
  body.replaceChildren(...rows);
  const again = was && was.fid && body.querySelector(`[data-fid="${CSS.escape(was.fid)}"]`);
  if (again && !again.disabled) {
    again.focus({ preventScroll: true });
    if (sel) try { again.setSelectionRange(...sel); } catch { /* a number input */ }
  } else if (was) {
    const tr = rows.find(r => r.dataset.key === was.key && r.classList.contains(was.summary ? "detailrow" : "node"));
    const target = tr && (was.summary ? tr.querySelector("summary") : tr);
    if (target) target.focus({ preventScroll: true });
  }
}

// The header reads /api/nodes every 5 s; the page follows it.
function onPoll(ns, { changed, error }) {
  document.getElementById("updated").textContent = error
    ? `Can't reach the controller: ${error.message}` : `Updated ${new Date().toLocaleTimeString()}.`;
  if (!changed) return; // unchanged since the last poll: keep the page as it is
  if (!ns) return;
  nodes = ns;
  render();
  fleetLine();
}

// The fleet line: how many nodes answer, how many need attention, queries a second and failures
// in the last hour (SERVFAIL answers, failed forwards and dropped queries, from /metrics).
let dash1 = null;
function fleetLine() {
  const box = document.getElementById("fleet");
  if (!nodes) return;
  box.hidden = !nodes.length; // no nodes: the list says so, and there is nothing to count
  const attention = nodes.filter(n => { const sm = summary(n); return sm.cls || sm.reasons.length || sm.text !== "healthy"; }).length;
  const f = obj(dash1 && dash1.fleet), now = obj(f.now), hour = obj(f.hour);
  const sum = nodes.reduce((t, n) => t + (n.online && typeof n.qps === "number" ? n.qps : 0), 0);
  const qps = typeof now.qps === "number" ? now.qps : nodes.some(n => typeof n.qps === "number") ? sum : null;
  const fails = dash1 && f.reading ? (hour.servfail || 0) + (hour.upstream_failures || 0) + (hour.dropped || 0) : null;
  const part = (v, label, cls, title) => {
    const sp = el("span", cls || "");
    sp.append(el("strong", "", v), ` ${label}`);
    if (title) sp.title = title;
    return sp;
  };
  // The home page's two questions first: is every node answering, and does any need attention.
  const up = nodes.filter(answering).length;
  box.replaceChildren(
    part(`${up} of ${nodes.length}`, "answering",
      up < nodes.length ? "bad" : "", "Nodes that answer DNS queries now"),
    part(String(attention), attention === 1 ? "needs attention" : "need attention", attention ? "warn" : ""),
    part(qps === null ? "–" : qps.toFixed(qps < 10 ? 1 : 0), "queries a second"),
    part(fails === null ? "–" : fails.toLocaleString(), fails === 1 ? "failure in the hour" : "failures in the hour", fails ? "warn" : "",
      fails === null ? "No node's /metrics read yet." : `SERVFAIL ${num(hour.servfail)}, failed forwards ${num(hour.upstream_failures)}, dropped ${num(hour.dropped)}`),
  );
}
async function readDashboard() {
  try { dash1 = await getJSON("api/dashboard"); } catch (e) { dash1 = null; console.error(e); }
  fleetLine();
}

// actStatus is the node's last action as a line: what, its state, its latest progress, and
// a link to its whole log on the Jobs page. Updated in place as the job's events come.
function actStatus(k, short) {
  const a = acts.get(k);
  if (!a) return null;
  const d = el("div", short ? "act sub" : "act");
  d.dataset.act = k;
  d.dataset.short = short ? "1" : "";
  if (a.error) {
    d.append(el("span", "bad", `${ACTIONS[a.kind] || a.kind}: not started: ${a.error}`));
    return d;
  }
  const j = a.job || {};
  const state = j.stopping && !ended(j.state) ? "stopping" : j.state || "queued";
  d.append(el("span", `pill ${jobPill(j.state)}`, `${ACTIONS[j.kind] || j.kind} · ${state}`), " ");
  const text = ended(j.state) && j.error ? j.error : a.line || "";
  if (text) d.append(el("span", j.state === "failed" ? "bad" : "", text), " ");
  const link = el("a", "", "job record");
  link.href = `jobs.html#job=${encodeURIComponent(j.id)}`;
  d.append(link);
  return d;
}

// refreshAct puts the node's action line in again wherever it shows (the row, the detail).
function refreshAct(k) {
  for (const old of document.querySelectorAll(`[data-act="${CSS.escape(k)}"]`)) {
    const fresh = actStatus(k, old.dataset.short === "1");
    if (fresh) old.replaceWith(fresh);
  }
}

// follow keeps a node's action up to date from its job's events, to its end.
function follow(k, job) {
  const es = events(`api/jobs/${encodeURIComponent(job.id)}/events`);
  const set = j => {
    const a = acts.get(k);
    if (!a || !a.job || a.job.id !== j.id) { es.close(); return false; }
    const changed = a.job.state !== j.state || a.job.stopping !== j.stopping;
    a.job = j;
    return changed;
  };
  es.addEventListener("state", e => { if (set(JSON.parse(e.data))) render(); });
  es.addEventListener("log", e => {
    const a = acts.get(k);
    if (!a || !a.job || a.job.id !== job.id) { es.close(); return; }
    a.line = JSON.parse(e.data).text;
    refreshAct(k);
  });
  es.addEventListener("end", e => { set(JSON.parse(e.data)); es.close(); render(); });
}

async function start(n, kind, params) {
  const k = key(n);
  try {
    const job = await post("api/jobs", { kind, params: { node: n.addr, ...params } });
    acts.set(k, { kind, job, line: "" });
    follow(k, job);
  } catch (e) {
    acts.set(k, { kind, error: e.message });
  }
  render();
}

function actionsSection(n) {
  const k = key(n), s = obj(n.status), reboot = obj(s.reboot), cfg = obj(s.config);
  const a = acts.get(k);
  const busy = a && a.job && !ended(a.job.state);
  const name = nodeName(n).name;
  let why = "";
  if (!sess.logged_in) why = sess.password_set ? "Log in to act on nodes." : "No password is set: the controller is read-only (espdns passwd: docs/getting-started.md, step 6).";
  else if (keyInfo && !keyInfo.present) why = keyInfo.missing ? "No release key, so no actions: import one (espdns key import: docs/getting-started.md, step 7)." : `The release key can't be used: ${keyInfo.error}`;
  else if (!n.online) why = "Not answering: no actions until it is.";
  else if (busy) why = "An action is running on this node.";
  const off = Boolean(why);

  const secsIn = el("input", "secs");
  secsIn.type = "number";
  secsIn.min = "1";
  secsIn.max = "3600";
  secsIn.step = "1";
  secsIn.value = identifySecs.get(k) || "30";
  secsIn.dataset.fid = `secs-${k}`;
  secsIn.setAttribute("aria-label", "Identify for how many seconds");
  secsIn.disabled = off;
  secsIn.addEventListener("input", () => identifySecs.set(k, secsIn.value));
  const ident = el("button", "btn small", "Identify");
  ident.dataset.fid = `identify-${k}`;
  ident.title = "Flicker the node's LED, to tell it from the others";
  ident.onclick = () => {
    const v = Number(secsIn.value);
    if (!Number.isInteger(v) || v < 1 || v > 3600) { secsIn.setCustomValidity("1 to 3600 seconds"); secsIn.reportValidity(); return; }
    secsIn.setCustomValidity("");
    start(n, "identify", { seconds: v });
  };
  const flush = el("button", "btn small", "Flush cache");
  flush.dataset.fid = `flush-${k}`;
  flush.title = "Drop every answer in the node's cache";
  flush.onclick = () => start(n, "flush", {});
  const pending = reboot.pending === true;
  const rb = el("button", "btn small danger", "Reboot (pending)");
  rb.dataset.fid = `reboot-${k}`;
  rb.title = pending ? "A release waits for a reboot: reboot it, coordinated" : "No reboot pending";
  rb.onclick = async () => {
    const ok = await confirmDialog(`Reboot ${name}?`, [
      `${n.addr} waits for a reboot for: ${arr(reboot.reasons).join(", ") || "a release it took"}.`,
      "The controller reboots it only while another node or a DNS peer answers (never the last healthy node), then waits for it to come back in service. Clients asking this node get no answer while it reboots.",
    ], "Reboot");
    if (ok) start(n, "reboot-pending", {});
  };
  // Flush and the reboot only for a node in settings.json: a host that only advertises
  // itself over mDNS could replay a release signed for it to another node (the controller
  // refuses them too).
  const unlisted = n.source === "mdns";
  if (unlisted) flush.title = rb.title = "Only for a node in settings.json, not one only found over mDNS";
  ident.disabled = off;
  flush.disabled = off || unlisted;
  rb.disabled = off || unlisted || !pending;

  const row1 = el("div", "acts");
  const lab = el("label", "inline");
  lab.append(secsIn, " s");
  row1.append(ident, lab, flush, rb);
  const out = [row1];
  const cfgSrc = n.status && n.status.config && n.status.config.source;
  if (cfgSrc && cfgSrc !== "node") {
    const d = el("div", "sub act", "Not adopted: it runs on its board's settings. ");
    const a = el("a", "", "Adopt it");
    a.href = "adopt.html";
    d.append(a);
    out.push(d);
  }
  if (why) out.push(el("div", "sub", why));
  else if (unlisted) out.push(el("div", "sub", "Found over mDNS only: identify works; flush and the reboot are only for the nodes in settings.json."));
  else if (keyInfo && keyInfo.fingerprint) out.push(el("div", "sub", `Signed with the release key ${keyInfo.fingerprint}, as ${sess.user}; each runs as a job under the fleet lock.`));
  const st = actStatus(k, false);
  if (st) out.push(st);
  return section("Actions", ...out);
}

// Actions running when the page opened: followed as if started here.
async function resume() {
  try {
    for (const j of await getJSON("api/jobs")) {
      const node = jobNode(j);
      if (!ACTIONS[j.kind] || ended(j.state) || typeof node !== "string") continue;
      const n = nodes.find(x => x.addr === node);
      const k = n ? key(n) : node;
      if (acts.has(k)) continue;
      acts.set(k, { kind: j.kind, job: j, line: "" });
      follow(k, j);
    }
  } catch (e) { console.error(e); }
}

async function loadKey() {
  keyInfo = await releaseKey();
  render();
}

session.then(s => { sess = s; render(); });
let resumed = false;
onNodes((ns, st) => {
  onPoll(ns, st);
  if (!resumed && ns) { resumed = true; resume(); }
});
loadKey();
readDashboard();
setInterval(readDashboard, 10000);
setInterval(loadKey, 60000);
