// The zone primary (System, system.html; its facts on the Adopt page too): each secondary
// zone the configs carry, on the zone primary settings.json names, from /api/primary. Over
// its API: who may transfer the zone and who gets its NOTIFYs, and whether every node in
// settings.json that carries it is in them; a missing node is allowed in as a job (the
// "primary" job, the adoption's own edit), and an entry that is no node in settings.json is
// taken off only when asked. Changed by hand (the manual kind, any primary): what each node
// needs there. Everything from the primary or the nodes is shown as text.
import { el, post, getJSON, confirmDialog, waitJob, nodeLabel } from "./common.js";

const arr = v => (Array.isArray(v) ? v : []);

// The zone primary's kind, as settings.json names it, in its driver's words (the server
// sends its name and whether it has an API): no kind is known here, so a new driver needs
// nothing on this page.
const kindText = t => t.api ? `${t.kind}: ${t.name || t.kind}, over its API` : `${t.kind}: ${t.name || "any zone primary"}, its lists changed by hand`;

export function primaryFacts(t, facts) {
  const fact = (k, v, cls) => { const tr = el("tr"); tr.append(el("th", "", k), el("td", cls || "", v)); facts.append(tr); };
  fact("Kind", `${kindText(t)}${t.set ? "" : " (none in settings.json: \"primary\")"}`);
  if (t.api) {
    fact("API", t.url || "none in settings.json (\"primary\" \"url\")", t.url ? "mono" : "warn");
    if (t.url) fact("Certificate", t.cert_sha256 ? `pinned, SHA-256 ${t.cert_sha256}` : "verified by the system's roots (none pinned: POST /api/primary/certificate pins a self-signed one)", t.cert_sha256 ? "mono" : "");
    fact("Token", t.token ? `imported (${t.token_file || "keys/primary.token"})` : t.token_error ? `can't be used: ${t.token_error}` : "none: import it with espdns primary import (docs/reference/cli.md#primary)", t.token ? "" : "warn");
  }
  return facts;
}

function rowOf(cells) {
  const tr = el("tr");
  for (const c of cells) {
    const td = el("td");
    if (c instanceof Node) td.append(c); else td.textContent = c;
    tr.append(td);
  }
  return tr;
}

// loadPrimary reads the zone primary into box, with sub saying from where and when.
export async function loadPrimary(box, sub) {
  sub.textContent = "reading…";
  let r;
  try { r = await getJSON("api/primary"); } catch (e) { box.replaceChildren(el("div", "banner bad", e.message)); sub.textContent = ""; return; }
  const pk = r.primary || {};
  sub.textContent = r.api ? `from ${r.api}, ${new Date().toLocaleTimeString()}` : "";
  const out = [primaryFacts(pk, el("table", "facts"))];
  if (r.error) out.push(el("div", "banner warn", r.error));
  if (r.by_hand) {
    const d = el("div", "banner muted");
    d.append(el("strong", "", "Changed by hand: "), `${r.by_hand}. The controller can't read the primary's lists, so each node below is shown with what it needs there; make sure each is in place.`);
    out.push(d);
  }
  if (!arr(r.zones).length) out.push(el("p", "sub", "No config carries a secondary zone."));
  const again = () => loadPrimary(box, sub);
  for (const z of arr(r.zones)) {
    const s = el("div", "sect");
    s.append(el("h3", "mono", z.zone), el("div", "sub", `primary ${z.primary || "?"} · in ${arr(z.configs).join(", ")}`));
    if (z.error) s.append(el("div", "bad", z.error));
    const l = z.lists;
    if (l) {
      const f = el("table", "facts");
      const add = (k, v) => { const tr = el("tr"); tr.append(el("th", "", k), el("td", "mono", v)); f.append(tr); };
      add("Zone transfer", `${l.transfer}${l.transfer_acl ? " (network ACL)" : ""}: ${arr(l.transfer_list).join(", ") || "none listed"}`);
      add("Notify", `${l.notify}: ${arr(l.notify_list).join(", ") || "none listed"}`);
      s.append(f);
    }
    const t = el("table", "mini");
    t.append(rowOf(["Node in settings.json", "Transfer", "NOTIFY", ""]));
    t.firstChild.querySelectorAll("td").forEach(td => td.className = "sub");
    for (const n of arr(z.nodes)) {
      const yes = v => el("span", v ? "" : l ? "bad" : "sub", l ? (v ? "yes" : "missing") : "?");
      let act = "";
      if (l && (!n.transfer || !n.notify)) {
        act = el("button", "btn small", "Allow");
        act.type = "button";
        act.onclick = () => primaryJob(z.zone, n.host.replace(/:\d+$/, ""), "allow", undefined, again);
      }
      const who = nodeLabel(n.host);
      if (n.manual) who.append(el("div", "sub", `Needs: ${n.manual}`));
      t.append(rowOf([who, yes(n.transfer), yes(n.notify), act]));
    }
    if (!arr(z.nodes).length) t.append(rowOf(["No node in settings.json carries it.", "", "", ""]));
    s.append(t);
    if (arr(z.unread).length) s.append(el("div", "sub warn", `Not read yet (no /status): ${z.unread.join(", ")}`));
    if (arr(z.extra).length) {
      const x = el("table", "mini");
      x.append(rowOf(["Other entries", "Transfer", "NOTIFY", ""]));
      x.firstChild.querySelectorAll("td").forEach(td => td.className = "sub");
      for (const e of z.extra) {
        let rm = "";
        if (!e.in_use) {
          rm = el("button", "btn small", "Remove…");
          rm.type = "button";
          rm.onclick = () => primaryJob(z.zone, e.addr, "remove", e.former, again);
        }
        const who = el("div"); who.append(el("span", "mono", e.addr), el("div", "sub", e.in_use ? `${e.in_use}: kept` :
          e.former ? `was node ${e.former} (no longer in settings.json)` : "not a node in settings.json"));
        x.append(rowOf([who, e.transfer ? "listed" : "–", e.notify ? "listed" : "–", rm]));
      }
      s.append(x);
    }
    out.push(s);
  }
  box.replaceChildren(...out);
}

async function primaryJob(zone, addr, action, former, again) {
  const lines = action === "allow"
    ? [`On the zone primary: add ${addr} to ${zone}'s zone transfer and NOTIFY lists (and turn the specified lists on where the zone uses only its own name servers), as an adoption does.`]
    : [`On the zone primary: take ${addr} off ${zone}'s zone transfer and NOTIFY lists; the modes stay as they are.`,
      former ? `It was node ${former}, which settings.json no longer has.` : `${addr} is no node in settings.json, but it may be another secondary server than an espDNS node: it would no longer get the zone.`];
  if (!await confirmDialog(action === "allow" ? `Allow ${addr} in ${zone}?` : `Remove ${addr} from ${zone}?`, lines,
    action === "allow" ? "Allow" : "Remove", action === "allow" ? "btn primary" : "btn danger")) return;
  try {
    const j = await waitJob((await post("api/jobs", { kind: "primary", params: { zone, address: addr, action } })).id);
    if (j.state !== "done") throw new Error(j.error || j.state);
  } catch (e) { await confirmDialog("Not changed", [e.message], "OK", "btn primary"); }
  again();
}
