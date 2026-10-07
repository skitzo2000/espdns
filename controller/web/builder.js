// The builder (builder.html): the board list and a board's facts, the custom board form,
// preparing an image and the ESP Web Tools button that installs it over USB.
import { header, el, api } from "./common.js";
import { Improv, STATE } from "./improv.js";
header("builder.html");
if (!("serial" in navigator)) document.getElementById("unsupported").hidden = false;

// The builder's POSTs carry the session's token, as every API request must (internal/auth,
// common.js api); its errors are text, the login's JSON.
const post = async (url, body) => {
  const r = await api(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) {
    let msg = text.trim();
    try { msg = JSON.parse(text).error || msg; } catch { /* text */ }
    throw new Error(msg);
  }
  return JSON.parse(text);
};
const known = (await (await api("api/images")).json()).known;
let entries = [];

function summary(b) {
  const e = b.ethernet || { kind: "none" };
  const eth = e.kind === "emac" ? `${(e.phy || "ip101").toUpperCase()} on the built-in MAC` : e.kind === "w5500" ? "W5500" : "Wi-Fi only";
  const sd = !b.sd || b.sd.kind === "none" ? "no SD" : b.sd.kind === "sdmmc" ? "SDMMC" : "SD over SPI";
  return `${eth}${e.optional ? " (add-on)" : ""} · ${sd}`;
}

function problems(box, errors, warnings) {
  box.replaceChildren(...errors.map(t => el("div", "bad", "✕ " + t)), ...warnings.map(t => el("div", "warn", "! " + t)));
}

// The ESP Web Tools button for a prepared build.
function installButton(box, build) {
  const btn = document.createElement("esp-web-install-button");
  btn.setAttribute("manifest", `build/${build.id}/manifest.json`);
  const b = el("button", "btn", `Install ${build.board.name} over USB`);
  b.slot = "activate";
  btn.append(b);
  box.replaceChildren(btn, el("div", "sub", `${build.chip.image} v${build.chip.version}, built ${build.chip.built} · ${build.chip.elf_sha256} · image ${build.id}`));
}

// The node's address, which goes into its board partition: per node, not saved with a board.
// A node never asks DHCP on its own, so one is required ("dhcp" only where a DHCP server is).
function addressFields() {
  const addr = el("input"), gw = el("input");
  addr.placeholder = "192.0.2.52/24, or dhcp"; addr.required = true; addr.spellcheck = false;
  gw.placeholder = "192.0.2.1"; gw.spellcheck = false;
  const la = el("label", "", "Address, with prefix length "), lg = el("label", "", "Gateway ");
  la.append(addr); lg.append(gw);
  const network = () => {
    const a = addr.value.trim();
    if (!a) throw new Error("Give the node an address: it never asks DHCP for one on its own.");
    return a === "dhcp" ? { address: a } : { address: a, gateway: gw.value.trim() };
  };
  return { labels: [la, lg], network };
}

async function prepare(box, body) {
  box.replaceChildren(el("div", "sub", "Building the image…"));
  try { installButton(box, await post("api/build", body)); }
  catch (e) { box.replaceChildren(el("div", "bad", e.message)); }
}

function renderList(select) {
  const list = document.getElementById("boards");
  list.replaceChildren(...entries.map(e => {
    const b = e.board, row = el("button", "boardrow");
    const top = el("div", "top");
    top.append(el("strong", "", b.title || b.name), el("span", `pill ${b.tier === "tested" ? "ok" : b.tier === "community" ? "warn" : ""}`, b.tier || "untested"));
    row.append(top, el("div", "sub mono", `${b.name} · ${b.image} · ${b.flash_mb || 4} MB${e.source === "custom" ? " · yours" : ""}`),
               el("div", "sub", summary(b)));
    if (e.errors.length) row.append(el("div", "bad", `${e.errors.length} problem${e.errors.length > 1 ? "s" : ""}`));
    else if (!e.image_ready) row.append(el("div", "warn", `chip image ${b.image} not imported`));
    row.addEventListener("click", () => { for (const r of list.children) r.classList.remove("on"); row.classList.add("on"); showBoard(e); });
    if (select === b.name) { row.classList.add("on"); showBoard(e); }
    return row;
  }), (() => {
    const row = el("button", "boardrow new");
    row.append(el("strong", "", "+ Describe your own board"), el("div", "sub", "Any ESP32, S3, C3, C6 or P4 board, from its pinout"));
    row.addEventListener("click", () => { for (const r of list.children) r.classList.remove("on"); row.classList.add("on"); showForm(); });
    return row;
  })());
}

function showBoard(e) {
  const b = e.board, d = document.getElementById("detail");
  const t = el("table", "facts");
  const rowOf = (k, v) => { const tr = el("tr"); tr.append(el("th", "", k), el("td", "", v)); t.append(tr); };
  rowOf("Chip image", b.image);
  rowOf("Flash / PSRAM", `${b.flash_mb || 4} MB / ${b.psram_mb ? b.psram_mb + " MB" : "none"}`);
  rowOf("Network", summary(b));
  rowOf("LED", !b.led || b.led.kind === "none" ? "none (an add-on LED can be set per node)" : `${b.led.kind} on GPIO ${b.led.pin}`);
  rowOf("Wi-Fi transmit cap", b.wifi && b.wifi.tx_power_dbm ? `${b.wifi.tx_power_dbm} dBm` : "chip default (20 dBm)");
  const tx = el("input"); tx.type = "number"; tx.min = 2; tx.max = 20;
  tx.placeholder = b.wifi && b.wifi.tx_power_dbm ? `${b.wifi.tx_power_dbm} (board default)` : "20 (chip default)";
  const txLabel = el("label", "", "Wi-Fi transmit cap for this node, dBm "); txLabel.append(tx);
  const box = el("div", "install"), probs = el("div", "problems"), net = addressFields();
  problems(probs, e.errors, e.warnings);
  const go = el("button", "btn", "Prepare image"), copy = el("button", "btn quiet", "Copy as a custom board");
  go.disabled = e.errors.length > 0 || !e.image_ready;
  go.addEventListener("click", () => {
    let network;
    try { network = net.network(); } catch (err) { return box.replaceChildren(el("div", "bad", err.message)); }
    if (!tx.value) return prepare(box, { name: b.name, network });
    const changed = structuredClone(b);
    changed.wifi = { ...(b.wifi || {}), tx_power_dbm: parseInt(tx.value, 10) };
    prepare(box, { board: changed, network });
  });
  copy.addEventListener("click", () => showForm({ ...structuredClone(b), name: "", title: (b.title || b.name) + " (mine)", tier: "untested" }));
  const row = el("div", "row"); row.append(go, copy);
  d.replaceChildren(el("h2", "", b.title || b.name), el("div", "sub mono", `${b.name} · ${e.source === "custom" ? "your board" : "catalog"} · ${b.tier || "untested"}`),
                    b.notes ? el("p", "notes", b.notes) : "", t, probs, b.image && !e.image_ready ? el("div", "warn", `Chip image ${b.image} isn't imported: build it and load it with espdns release import (docs/getting-started.md, steps 4 and 8).`) : "",
                    el("h3", "", "For this node"), ...net.labels, txLabel, row, box);
}

// ---- custom board form ----
const num = v => v === "" || v === undefined ? undefined : parseInt(v, 10);
function formToBoard(f) {
  const v = n => f.elements[n].type === "checkbox" ? f.elements[n].checked : f.elements[n].value;
  const b = { name: v("name").trim(), title: v("title").trim() || undefined, image: v("image"), flash_mb: num(v("flash_mb")),
              psram_mb: num(v("psram_mb")), tier: "untested" };
  const spi = [0, 1].filter(i => v(`spi${i}_host`)).map(i => ({ host: num(v(`spi${i}_host`)), sclk: num(v(`spi${i}_sclk`)), mosi: num(v(`spi${i}_mosi`)), miso: num(v(`spi${i}_miso`)) }));
  if (spi.length) b.spi = spi;
  const ek = v("eth_kind");
  if (ek === "emac") {
    b.ethernet = { kind: ek, phy: v("eth_phy"), addr: num(v("eth_addr")), reset: num(v("eth_reset")), power: num(v("eth_power")),
                   mdc: num(v("eth_mdc")), mdio: num(v("eth_mdio")), optional: v("eth_optional") || undefined };
    if (v("eth_clock")) b.ethernet.rmii_clock = { mode: v("eth_clock"), gpio: num(v("eth_clock_gpio")) };
  } else if (ek === "w5500") {
    b.ethernet = { kind: ek, spi_host: num(v("eth_spi")), cs: num(v("eth_cs")), int: num(v("eth_int")), rst: num(v("eth_rst")),
                   mhz: num(v("eth_mhz")), optional: v("eth_optional") || undefined };
  }
  const sk = v("sd_kind");
  if (sk === "sdmmc") b.sd = { kind: sk, slot: num(v("sd_slot")), width: num(v("sd_width")), ldo: num(v("sd_ldo")) };
  else if (sk === "spi") b.sd = { kind: sk, spi_host: num(v("sd_spi")), cs: num(v("sd_cs")) };
  const lk = v("led_kind");
  if (lk !== "none") b.led = { kind: lk, pin: num(v("led_pin")), active_low: (lk === "gpio" && v("led_low")) || undefined };
  if (v("wifi_tx")) b.wifi = { tx_power_dbm: num(v("wifi_tx")) };
  return JSON.parse(JSON.stringify(b)); // drops undefined
}
function boardToForm(f, b) {
  const set = (n, val) => { if (val === undefined || val === null) return; const e = f.elements[n]; if (e.type === "checkbox") e.checked = !!val; else e.value = val; };
  set("name", b.name); set("title", b.title); set("image", b.image); set("flash_mb", b.flash_mb); set("psram_mb", b.psram_mb);
  (b.spi || []).forEach((s, i) => { set(`spi${i}_host`, s.host); set(`spi${i}_sclk`, s.sclk); set(`spi${i}_mosi`, s.mosi); set(`spi${i}_miso`, s.miso); });
  const e = b.ethernet || { kind: "none" };
  set("eth_kind", e.kind); set("eth_phy", e.phy); set("eth_addr", e.addr); set("eth_reset", e.reset); set("eth_power", e.power);
  set("eth_mdc", e.mdc); set("eth_mdio", e.mdio); set("eth_spi", e.spi_host); set("eth_cs", e.cs); set("eth_int", e.int);
  set("eth_rst", e.rst); set("eth_mhz", e.mhz); set("eth_optional", e.optional);
  if (e.rmii_clock) { set("eth_clock", e.rmii_clock.mode); set("eth_clock_gpio", e.rmii_clock.gpio); }
  const s = b.sd || { kind: "none" };
  set("sd_kind", s.kind); set("sd_slot", s.slot); set("sd_width", s.width); set("sd_ldo", s.ldo); set("sd_spi", s.spi_host); set("sd_cs", s.cs);
  const l = b.led || { kind: "none" };
  set("led_kind", l.kind); set("led_pin", l.pin); set("led_low", l.active_low);
  if (b.wifi) set("wifi_tx", b.wifi.tx_power_dbm);
}
function showForm(from) {
  const d = document.getElementById("detail");
  const f = document.getElementById("form-tpl").content.firstElementChild.cloneNode(true);
  f.elements.image.replaceChildren(...Object.keys(known).sort().map(k => el("option", "", k)));
  f.elements.image.value = "esp32s3-octal";
  if (from) boardToForm(f, from);
  const probs = f.querySelector(".problems"), box = f.querySelector(".install"), net = addressFields();
  f.querySelector(".node-net .grid").append(...net.labels);
  // A field with data-for shows when its section's first choice (the kind) is one of those.
  const showFor = () => {
    for (const l of f.querySelectorAll("[data-for]"))
      l.hidden = !l.dataset.for.split(" ").includes(l.closest("fieldset").querySelector("select").value);
  };
  let timer;
  const check = () => {
    showFor();
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try { const r = await post("api/boards/check", formToBoard(f)); problems(probs, r.errors, r.warnings); }
      catch (e) { problems(probs, [e.message], []); }
    }, 250);
  };
  f.addEventListener("input", check);
  f.addEventListener("change", check);
  f.querySelector('[data-act="prepare"]').addEventListener("click", () => {
    try { prepare(box, { board: formToBoard(f), network: net.network() }); }
    catch (err) { box.replaceChildren(el("div", "bad", err.message)); }
  });
  f.querySelector('[data-act="save"]').addEventListener("click", async () => {
    try {
      const b = await post("api/boards", formToBoard(f));
      entries = await (await api("api/boards")).json();
      renderList(b.name);
    } catch (e) { problems(probs, [e.message], []); }
  });
  d.replaceChildren(f);
  check();
}

entries = await (await api("api/boards")).json();
renderList();
