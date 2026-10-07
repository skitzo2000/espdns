// Improv Wi-Fi over Web Serial (https://www.improv-wifi.com/serial/): set up a node's Wi-Fi
// over USB. The board's log shares the port; bytes outside packets are passed on as log lines.
//
// Packet: "IMPROV", version 1, type, length, data, checksum (sum of the bytes before it).

const MAGIC = [0x49, 0x4d, 0x50, 0x52, 0x4f, 0x56]; // "IMPROV"
const T = { STATE: 1, ERROR: 2, RPC: 3, RESULT: 4 };
const CMD = { WIFI: 1, STATE: 2, INFO: 3, SCAN: 4 };
export const STATE = { READY: 2, PROVISIONING: 3, PROVISIONED: 4 };
const ERRORS = { 1: "invalid request", 2: "unknown request", 3: "could not join the network", 255: "unknown error" };

export class Improv {
  constructor(port, onLog = () => {}) {
    this.port = port;
    this.onLog = onLog;
    this.buf = [];
    this.waiters = new Set();
    this.state = undefined;
  }

  async open() {
    await this.port.open({ baudRate: 115200 });
    this.reader = this.port.readable.getReader();
    this.loop = this._read();
  }

  // Always leaves the port closed, whatever state it was in.
  async close() {
    try { await this.reader?.cancel(); } catch {}
    try { await this.loop; } catch {}
    try { this.reader?.releaseLock(); } catch {}
    try { await this.port.close(); } catch {}
  }

  async _read() {
    for (;;) {
      const { value, done } = await this.reader.read();
      if (done) return;
      this.buf.push(...value);
      this._parse();
    }
  }

  _parse() {
    for (;;) {
      const at = this._find();
      if (at < 0) {
        // No packet start: hand over complete log lines, keep a possible partial "IMPROV".
        const nl = this.buf.lastIndexOf(10);
        if (nl >= 0) this._log(this.buf.splice(0, nl + 1));
        return;
      }
      if (at > 0) this._log(this.buf.splice(0, at));
      if (this.buf.length < 9) return;
      const len = this.buf[8];
      if (this.buf.length < 10 + len) return;
      const pkt = this.buf.splice(0, 10 + len);
      if (this.buf[0] === 10) this.buf.shift();
      const sum = pkt.slice(0, 9 + len).reduce((a, b) => a + b, 0) & 0xff;
      if (pkt[6] !== 1 || sum !== pkt[9 + len]) continue;
      this._packet(pkt[7], pkt.slice(9, 9 + len));
    }
  }

  _find() {
    outer: for (let i = 0; i + MAGIC.length <= this.buf.length; i++) {
      for (let j = 0; j < MAGIC.length; j++) if (this.buf[i + j] !== MAGIC[j]) continue outer;
      return i;
    }
    return -1;
  }

  _log(bytes) {
    const text = new TextDecoder().decode(new Uint8Array(bytes));
    for (const line of text.split(/\r?\n/)) if (line.trim()) this.onLog(line.replace(/\x1b\[[0-9;]*m/g, ""));
  }

  _packet(type, data) {
    let ev;
    if (type === T.STATE) { this.state = data[0]; ev = { type: "state", state: data[0] }; }
    else if (type === T.ERROR) ev = { type: "error", code: data[0] };
    else if (type === T.RESULT) {
      const strings = [];
      for (let i = 2; i < data.length; i += 1 + data[i]) strings.push(new TextDecoder().decode(new Uint8Array(data.slice(i + 1, i + 1 + data[i]))));
      ev = { type: "result", cmd: data[0], strings };
    } else return;
    for (const w of [...this.waiters]) w(ev);
  }

  // Sends a request and waits until done(event) returns a value, or the timeout passes.
  _rpc(cmd, data, done, timeoutMs, what) {
    return new Promise(async (resolve, reject) => {
      const w = ev => {
        try {
          const r = done(ev);
          if (r !== undefined) { cleanup(); resolve(r); }
        } catch (e) { cleanup(); reject(e); }
      };
      const timer = setTimeout(() => { cleanup(); reject(new Error(`${what}: no answer from the board`)); }, timeoutMs);
      const cleanup = () => { clearTimeout(timer); this.waiters.delete(w); };
      this.waiters.add(w);
      const body = [cmd, data.length, ...data];
      const pkt = [...MAGIC, 1, T.RPC, body.length, ...body];
      pkt.push(pkt.reduce((a, b) => a + b, 0) & 0xff, 10);
      const writer = this.port.writable.getWriter();
      try { await writer.write(new Uint8Array(pkt)); } catch (e) { cleanup(); reject(e); } finally { writer.releaseLock(); }
    });
  }

  info() {
    return this._rpc(CMD.INFO, [], ev => ev.type === "result" && ev.cmd === CMD.INFO
      ? { firmware: ev.strings[0], version: ev.strings[1], chip: ev.strings[2], name: ev.strings[3] } : undefined, 3000, "device info");
  }

  // The current state, and the node's address if it is on a network.
  // The board answers with its state and, when it is on a network, then its address.
  currentState() {
    let state;
    return this._rpc(CMD.STATE, [], ev => {
      if (ev.type === "state") {
        state = ev.state;
        if (state !== STATE.PROVISIONED) return { state };
      }
      if (ev.type === "result" && ev.cmd === CMD.STATE) return { state: STATE.PROVISIONED, url: ev.strings[0] };
    }, 3000, "state");
  }

  scan() {
    const nets = [];
    return this._rpc(CMD.SCAN, [], ev => {
      if (ev.type !== "result" || ev.cmd !== CMD.SCAN) return;
      if (!ev.strings.length) return nets;
      nets.push({ ssid: ev.strings[0], rssi: parseInt(ev.strings[1], 10), secure: ev.strings[2] === "YES" });
    }, 15000, "network scan");
  }

  // Joins a network; resolves with the node's address, or rejects with why it couldn't.
  join(ssid, password) {
    const enc = new TextEncoder();
    const s = [...enc.encode(ssid)], p = [...enc.encode(password)];
    return this._rpc(CMD.WIFI, [s.length, ...s, p.length, ...p], ev => {
      if (ev.type === "error" && ev.code !== 0) throw new Error(ERRORS[ev.code] || `error ${ev.code}`);
      if (ev.type === "result" && ev.cmd === CMD.WIFI) return ev.strings[0];
    }, 45000, "joining");
  }
}
