// + Add node (docs/plan.md, The prototype): the button becomes an address box with what it
// finds right under it. Empty, it lists the nodes found on the network and not added yet
// (/api/nodes/found) and a new board over USB (the Builder page, until Add node installs
// one itself); an address typed is looked up there (POST /api/nodes/lookup: that address
// only, nothing resolved). A node chosen gets a name (a node config from <data>/configs, which
// carries the name) and an address, and is added by the adoption (adopt.go): its preview,
// the dry run, the zone primary's lists changed by hand if they must be, then the adoption,
// which adds it to settings.json. One adopted already is added by the settings-add job.
// Esc, or a click outside with nothing typed or chosen, closes it.
import { h, arr, obj, str, hostOnly, toast, getJSON, post, session, events, nodeText, mac, MACHINT } from "./shell.js";

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const linkWord = k => (k === "ethernet" ? "Wired" : k === "wifi" ? "Wi-Fi" : "");

// follow resolves with a job once it ends, calling onProgress with its progress meanwhile;
// a job the controller no longer has (it restarted) ends it as failed.
function follow(job, onProgress) {
  return new Promise(resolve => {
    const es = events(`api/jobs/${encodeURIComponent(job.id)}/events`);
    es.addEventListener("state", e => { const s = JSON.parse(e.data); if (s.progress) onProgress(s.progress); });
    es.addEventListener("progress", e => onProgress(JSON.parse(e.data)));
    es.addEventListener("end", e => { const s = JSON.parse(e.data); es.close(); if (s.progress) onProgress(s.progress); resolve(s); });
    es.addEventListener("gone", () => resolve({ ...job, state: "failed", error: "The controller no longer has this job: it may have restarted. Try again." }));
  });
}

// addNode draws + Add node into box. opts: found() the nodes found, nodes() the listed
// ones, boardName(b), nodeKey(n), done() after a node is added. It returns {open(found)}.
export function addNode(box, opts) {
  const st = { open: false, sel: null, q: "", look: null, src: null, form: null, flow: null, sess: {} };
  session.then(s => { st.sess = s; });
  let input = null, list = null, timer = null, seq = 0;

  const button = h("button", { class: "btn", type: "button", onclick: () => open(null) }, "+ Add node");
  box.append(button);

  function open(sel) {
    st.open = true;
    st.sel = null;
    st.q = "";
    st.look = null;
    st.flow = null;
    input = h("input", { class: "t mono", id: "nq", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "An address, or pick below",
      "aria-label": "Node to add", "aria-controls": "nqres" });
    list = h("div", { class: "combo-list zpanel", id: "nqres", role: "region", "aria-label": "Add a node" });
    input.addEventListener("input", typed);
    input.addEventListener("keydown", e => {
      if (e.key === "Escape") { e.preventDefault(); close(); }
      if (e.key === "Enter") { e.preventDefault(); clearTimeout(timer); lookup(true); }
    });
    box.replaceChildren(h("div", { class: "combo zcombo ncombo" }, input, list));
    if (sel) choose(sel); else render();
    input.focus();
  }

  function close() {
    if (st.flow && st.flow.busy) return;
    clearTimeout(timer);
    seq++;
    st.open = false;
    box.replaceChildren(button);
  }

  // A click outside closes it while nothing is typed or chosen.
  document.addEventListener("mousedown", e => {
    if (st.open && !e.target.closest(".ncombo") && !st.q.trim() && !st.sel) close();
  });
  document.addEventListener("keydown", e => {
    if (st.open && e.key === "Escape" && !e.target.closest(".ncombo") && !document.querySelector(".drawer")) close();
  });

  function typed() {
    st.q = input.value.trim();
    st.sel = null;
    st.flow = null;
    st.look = null;
    clearTimeout(timer);
    seq++; // a lookup still on its way is for text no longer typed
    if (IPV4.test(st.q) && !known(st.q)) {
      st.look = { addr: st.q, busy: true };
      timer = setTimeout(() => lookup(false), 600);
    }
    render();
  }

  // known is a listed node the text names (its address or its name).
  function known(q) {
    const t = q.toLowerCase();
    return opts.nodes().find(n => hostOnly(n.addr) === q || nodeText(n).toLowerCase() === t);
  }

  async function lookup(now) {
    const q = st.q;
    if (!q || known(q)) { render(); return; }
    if (!IPV4.test(q)) {
      if (now) { st.look = { addr: q, error: "Type its IPv4 address: four numbers with dots between them." }; render(); }
      return;
    }
    const my = ++seq;
    st.look = { addr: q, busy: true };
    render();
    try {
      const r = await post("api/nodes/lookup", { address: q });
      if (my !== seq || st.q !== q) return;
      st.look = { addr: q, reply: r };
      if (r.found && r.node && r.node.next) { choose(r.node); return; }
    } catch (e) {
      if (my !== seq || st.q !== q) return;
      st.look = { addr: q, error: e.message };
    }
    render();
  }

  async function choose(f) {
    st.sel = f;
    st.flow = null;
    st.form = null;
    render();
    if (f.next === "adopt") {
      let src;
      try { src = await getJSON("api/adopt"); } catch (e) { src = { error: e.message }; }
      if (st.sel !== f) return; // another node chosen meanwhile
      st.src = src;
      const cs = arr(st.src.configs);
      const c = cs.find(x => x.name === f.config && !x.error) || null;
      st.form = { config: c ? c.name : "", address: "", edited: false };
      st.form.address = defaultAddress();
      render();
    }
  }

  function config() { return arr(obj(st.src).configs).find(c => c.name === (st.form && st.form.config)); }
  // The address it gets unless another is typed: its config's, else the one it runs on.
  function defaultAddress() {
    const c = config();
    return (c && c.address) || str(st.sel && st.sel.address);
  }

  // ---- what the panel shows ------------------------------------------------------------

  function render() {
    if (!list) return;
    list.replaceChildren(...body());
  }

  function body() {
    if (!st.sess.logged_in) {
      return [h("p", { class: "hint" }, st.sess.password_set ? "Log in to add a node." : "Read-only: set a password, then log in, to add a node.")];
    }
    if (st.sel) return chosen(st.sel);
    if (st.q) {
      const k = known(st.q);
      if (k) {
        return [h("div", { class: "found" }, h("b", {}, nodeText(k)), h("span", { class: "small" }, "Already one of your nodes, at ", h("span", { class: "mono" }, hostOnly(k.addr)), ".")),
          h("div", { class: "actions" }, h("a", { class: "btn small", href: `nodes.html#${encodeURIComponent(opts.nodeKey(k))}` }, "Open it"))];
      }
      const l = st.look;
      if (!l) return [h("p", { class: "hint" }, "Type the node's whole address, like 192.0.2.10; Enter looks it up.")];
      if (l.busy) return [h("div", { class: "row small" }, h("span", { class: "spin", "aria-hidden": "true" }), "Looking for a node at ", h("span", { class: "mono" }, l.addr), "…")];
      if (l.error) return [h("div", { class: "found" }, h("b", { class: "mono" }, l.addr), h("span", { class: "small bad" }, l.error))];
      const r = obj(l.reply);
      if (r.listed) {
        return [h("div", { class: "found" }, h("b", {}, r.node ? nodeText(r.node.host) : l.addr), h("span", { class: "small" }, "Already one of your nodes, at ", h("span", { class: "mono" }, l.addr), "."))];
      }
      if (r.found && r.node) return chosen(r.node);
      return [h("div", { class: "found" }, h("b", { class: "mono" }, l.addr),
        h("span", { class: "small" }, r.answered ? "Something answers there, but it isn't an espDNS node."
          : "No espDNS node answers there. A board that has never run espDNS needs installing over USB first.")),
      h("div", { class: "actions" }, h("a", { class: "btn primary", href: "builder.html" }, "Install a board over USB"))];
    }
    const found = arr(opts.found());
    const rows = found.map(f => h("div", { class: "opt" },
      h("div", {}, h("b", {}, opts.boardName(f.board) || str(f.hostname) || f.host),
        h("div", { class: "tagline" }, h("span", { class: "mono" }, hostOnly(f.host)), [linkWord(f.net), f.version && `firmware ${f.version}`].filter(Boolean).map(x => ` · ${x}`).join("")),
        f.next ? null : h("div", { class: "tagline" }, `Can't be added yet: ${arr(f.refusals).join("; ") || "it is one of your nodes already"}`)),
      f.next ? h("button", { class: "btn small", type: "button", onclick: () => choose(f) }, "Add") : h("span", {})));
    return [h("div", { class: "stack nogap" },
      h("span", { class: "small muted" }, "Found on your network"),
      rows.length ? rows : h("p", { class: "hint" }, "Nothing new right now."),
      h("div", { class: "opt" }, h("div", {}, h("b", {}, "A new board over USB"), h("div", { class: "tagline" }, "Plug it into this computer and install espDNS")),
        h("a", { class: "btn small", href: "builder.html" }, "Start"))),
    h("span", { class: "hint" }, "Or type the address of a node that isn't listed.")];
  }

  const back = () => h("button", { class: "btn small link", type: "button", onclick: () => { st.sel = null; st.flow = null; st.q = ""; st.look = null; input.value = ""; render(); input.focus(); } }, "Back");

  // intro is the node chosen or looked up: what it is, where, and its MAC to copy (for a
  // DHCP reservation, or to set a static address).
  function intro(f) {
    const link = linkWord(f.net);
    const m = mac(f.mac);
    return h("div", { class: "found" }, h("b", {}, opts.boardName(f.board) || str(f.hostname) || "A node"),
      h("span", { class: "small" }, "Found at ", h("span", { class: "mono" }, hostOnly(f.host)), link ? ` over ${link}` : "", f.version ? `, firmware ${f.version}` : "", "."),
      m ? h("div", { class: "macl" }, m, h("span", { class: "hint" }, MACHINT)) : null);
  }

  function chosen(f) {
    if (st.flow) return flowView(f);
    const refusals = arr(f.refusals);
    if (refusals.length || !f.next) {
      return [intro(f), h("p", { class: "small bad" }, `It can't be added yet: ${refusals.join("; ") || "it is one of your nodes already"}.`),
        h("div", { class: "actions" }, back())];
    }
    if (f.next === "settings-add") {
      const go = h("button", { class: "btn primary", type: "button", onclick: () => settingsAdd(f) }, "Add node");
      return [intro(f), h("p", { class: "small" }, `It runs its own config already${f.name ? `, as ${f.name}` : ""}. Adding it makes it one of your nodes: changes and updates go to it too.`),
        h("div", { class: "actions" }, go, back())];
    }
    if (!st.form) return [intro(f), h("div", { class: "row small" }, h("span", { class: "spin", "aria-hidden": "true" }), "Reading the configs…")];
    if (st.src && st.src.error) return [intro(f), h("p", { class: "small bad" }, st.src.error), h("div", { class: "actions" }, back())];
    const cs = arr(st.src.configs);
    const sel = h("select", { class: "t", id: "nnname" },
      h("option", { value: "" }, cs.length ? "Choose…" : "No node config yet"),
      cs.map(c => h("option", { value: c.name, disabled: !!c.error, selected: c.name === st.form.config },
        `${str(c.config_name) || c.name}${c.error ? ` (${c.error})` : ""}`)));
    const ip = h("input", { class: "t mono", id: "nnip", type: "text", autocomplete: "off", spellcheck: "false", "aria-describedby": "nnip-hint" });
    ip.value = st.form.address;
    const hint = h("span", { class: "hint", id: "nnip-hint" }, st.form.config ? "A fixed address, with its prefix length." : "");
    const go = h("button", { class: "btn primary", type: "button" }, "Add node");
    const ok = () => { go.disabled = !st.form.config || !st.src.key; };
    sel.addEventListener("change", () => {
      st.form.config = sel.value;
      if (!st.form.edited) { st.form.address = defaultAddress(); ip.value = st.form.address; }
      hint.textContent = st.form.config ? "A fixed address, with its prefix length." : "";
      ok();
    });
    ip.addEventListener("input", () => { st.form.address = ip.value.trim(); st.form.edited = true; });
    go.addEventListener("click", () => adopt(f));
    ok();
    const out = [intro(f),
      h("div", { class: "grid2" }, h("label", { class: "f" }, h("span", {}, "Name"), sel), h("label", { class: "f" }, h("span", {}, "Address"), ip, hint)),
      h("p", { class: "small" }, "espDNS gives it this name and address, lets it copy your zones, then it starts serving like the others.")];
    if (!cs.length) out.push(h("p", { class: "hint" }, "A node's name comes with its node config: write one on the ", h("a", { href: "configs.html" }, "Configs"), " page first."));
    if (f.net === "wifi") out.push(h("span", { class: "hint" }, "A Wi-Fi board: fine as an extra node; your wired nodes keep DNS steady."));
    if (!st.src.key) out.push(h("p", { class: "hint bad" }, `No release key to sign its config with${st.src.key_error ? `: ${st.src.key_error}` : ""}.`));
    out.push(h("div", { class: "actions" }, go, back()));
    return out;
  }

  // ---- adding ---------------------------------------------------------------------------

  function params(f) {
    const p = { node: f.host, node_id: f.id, config: st.form.config };
    const a = st.form.address;
    if (a && a !== defaultAddress()) p.address = a;
    return p;
  }

  async function adopt(f) {
    const p = params(f);
    const flow = st.flow = { busy: true, what: "Checking its address and its config…", progress: null, error: "", hints: [] };
    const show = () => { if (st.flow === flow && st.sel === f) render(); };
    const fail = (msg, hints) => { flow.busy = false; flow.error = msg; flow.hints = arr(hints); show(); };
    show();
    let pv;
    try { pv = await post("api/adopt/preview", p); } catch (e) { fail(e.message); return; }
    const ck = obj(pv.check);
    if (pv.refusal) { fail(pv.refusal); return; }
    if (!ck.ok) { fail(str(ck.error) || str(obj(ck.node).refusal) || "Its config doesn't pass the check."); return; }
    flow.what = "Trying it first: nothing changes yet.";
    show();
    let dry;
    try { dry = await post("api/jobs", { kind: "adopt", params: { ...p, dry_run: true } }); } catch (e) { fail(e.message); return; }
    dry = await follow(dry, pr => { flow.progress = pr; show(); });
    const dp = obj(flow.progress);
    if (dry.state !== "done") { fail(str(dp.outcome) || str(dry.error) || `The check ${dry.state}.`, dp.hints); return; }
    const prim = obj(dp.primary);
    let primaryDone = false;
    if (arr(prim.manual).length && !prim.done) {
      // The zone primary isn't changed from here: the changes are made by hand, then go on.
      flow.busy = false;
      flow.manual = { why: str(prim.why), items: arr(prim.manual) };
      show();
      const go = await new Promise(resolve => { flow.resume = resolve; });
      if (!go) { st.flow = null; show(); render(); return; }
      flow.busy = true;
      flow.manual = null;
      primaryDone = true;
    }
    flow.what = `Adding it: ${pv.how === "new" ? "it moves to its new address with a restart" : "no restart"}.`;
    flow.progress = null;
    show();
    let job;
    try { job = await post("api/jobs", { kind: "adopt", params: { ...p, after: dry.id, add_to_settings: true, ...(primaryDone ? { primary_done: true } : {}) } }); }
    catch (e) { fail(e.message); return; }
    job = await follow(job, pr => { flow.progress = pr; show(); });
    const ap = obj(flow.progress);
    if (job.state !== "done") { fail(str(ap.outcome) || str(job.error) || `The adoption ${job.state}.`, ap.hints); return; }
    flow.busy = false;
    const name = str(obj(config()).config_name) || hostOnly(f.host);
    toast(`${name} is added: it serves like the others`);
    st.flow = null;
    close();
    opts.done();
  }

  async function settingsAdd(f) {
    const flow = st.flow = { busy: true, what: "Adding it to your nodes…", progress: null, error: "", hints: [] };
    render();
    try {
      let j = await post("api/jobs", { kind: "settings-add", params: { node: f.host } });
      j = await follow(j, () => {});
      if (j.state !== "done") throw new Error(str(j.error) || `It ${j.state}.`);
      flow.busy = false;
      toast(`${f.name || hostOnly(f.host)} is one of your nodes now`);
      st.flow = null;
      close();
      opts.done();
    } catch (e) {
      flow.busy = false;
      flow.error = e.message;
      render();
    }
  }

  function flowView(f) {
    const fl = st.flow;
    const out = [intro(f)];
    const pr = obj(fl.progress);
    if (fl.busy) out.push(h("div", { class: "row small" }, h("span", { class: "spin", "aria-hidden": "true" }), fl.what));
    const steps = arr(pr.steps);
    if (steps.length) {
      out.push(h("ol", { class: "steps" }, steps.map(s => h("li", { class: s.state === "done" ? "done" : s.state === "running" ? "now" : s.state === "failed" ? "failed" : "" },
        h("span", { class: "m" }), h("div", {}, h("b", {}, str(s.title)), s.detail ? h("div", { class: "hint" }, str(s.detail)) : null)))));
    }
    if (fl.manual) {
      const cb = h("input", { type: "checkbox" });
      const go = h("button", { class: "btn primary", type: "button", disabled: true, onclick: () => fl.resume(true) }, "Continue");
      cb.addEventListener("change", () => { go.disabled = !cb.checked; });
      out.push(h("div", { class: "alert-box" },
        h("b", {}, "Make these changes at your zone primary first"),
        fl.manual.why ? h("p", { class: "small" }, fl.manual.why) : null,
        h("ul", { class: "small" }, fl.manual.items.map(x => h("li", {}, str(x)))),
        h("label", { class: "check" }, cb, h("span", {}, "I made these changes"))),
      h("div", { class: "actions" }, go, h("button", { class: "btn small link", type: "button", onclick: () => fl.resume(false) }, "Cancel")));
    }
    if (fl.error) {
      out.push(h("p", { class: "small bad" }, fl.error));
      if (fl.hints.length) out.push(h("ul", { class: "hint" }, fl.hints.map(x => h("li", {}, str(x)))));
      out.push(h("div", { class: "actions" }, h("button", { class: "btn small", type: "button", onclick: () => { st.flow = null; render(); } }, "Try again"), back()));
    }
    return out;
  }

  return { open };
}

