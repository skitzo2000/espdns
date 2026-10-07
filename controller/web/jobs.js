// Jobs (jobs.html): the jobs and the action log, a job's live log, Run check and Stop.
import { header, el, post, getJSON, jobWhat, jobPill, ended, events } from "./common.js";
header("jobs.html");

const pillClass = jobPill;
const time = t => t && !t.startsWith("0001") ? new Date(t).toLocaleString() : "–";
const took = j => j.started && j.ended ? `${((new Date(j.ended) - new Date(j.started)) / 1000).toFixed(1)} s` : "–";

const what = jobWhat;

let source = null, shown = null;
function showJob(job) {
  shown = job.id;
  document.getElementById("job").hidden = false;
  document.getElementById("job-title").textContent = `${what(job)} · ${job.id}`;
  history.replaceState(null, "", `#job=${encodeURIComponent(job.id)}`);
  document.getElementById("log").textContent = "";
  if (source) source.close();
  // The stream replays the log, then follows it live, and ends with "end".
  source = events(`api/jobs/${job.id}/events`);
  source.addEventListener("state", e => setState(JSON.parse(e.data)));
  source.addEventListener("log", e => {
    const l = JSON.parse(e.data);
    const pre = document.getElementById("log");
    const atEnd = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
    pre.textContent += `${new Date(l.time).toLocaleTimeString()}  ${l.text}\n`;
    if (atEnd) pre.scrollTop = pre.scrollHeight;
  });
  source.addEventListener("end", e => { setState(JSON.parse(e.data)); source.close(); source = null; refresh(); });
}

function setState(job) {
  const st = document.getElementById("job-state");
  st.textContent = job.stopping && !ended(job.state) ? "stopping" : job.state;
  st.className = `pill ${pillClass(job.state)}`;
  document.getElementById("stop").hidden = !["queued", "running"].includes(job.state) || job.stopping;
  document.getElementById("job-sub").textContent =
    `started by ${job.who}, ${time(job.started || job.created)}` + (job.error ? ` — ${job.error}` : "");
}

document.getElementById("check").onclick = async () => {
  try { showJob(await post("api/jobs", { kind: "check" })); refresh(); }
  catch (e) { alert(e.message); }
};
document.getElementById("stop").onclick = async () => {
  try { setState(await post(`api/jobs/${shown}/stop`)); } catch (e) { alert(e.message); }
};

function cells(tr, values) { for (const v of values) tr.append(el("td", "", v)); return tr; }
function rows(id, items, make) {
  const body = document.getElementById(id);
  if (!Array.isArray(items) || !items.length) return;
  body.replaceChildren(...items.map(make));
}

async function refresh() {
  try {
    const lock = await getJSON("api/lock");
    document.getElementById("lock").textContent = lock.held ? `Fleet locked by ${lock.text}` : "Fleet lock free.";
    const jobs = await getJSON("api/jobs");
    rows("jobs", jobs, j => {
      const tr = cells(el("tr"), [time(j.started || j.created), what(j), j.who]);
      const td = el("td"); td.append(el("span", `pill ${pillClass(j.state)}`, j.state)); tr.append(td);
      cells(tr, [took(j), j.error || ""]);
      tr.style.cursor = "pointer";
      tr.onclick = () => showJob(j);
      return tr;
    });
    const actions = await getJSON("api/actions?n=30");
    rows("actions", actions, a => cells(el("tr"), [time(a.time), a.event, a.source, a.who,
      [a.action, ...(a.args || [])].join(" "), [a.result, a.error].filter(Boolean).join(": ")]));
  } catch (e) { console.error(e); }
}
// A job named in the address (#job=<id>, as the header and the node list link them):
// shown at once, and again when the header's link changes it on this page.
function fromHash() {
  const want = new URLSearchParams(location.hash.slice(1)).get("job");
  if (want && want !== shown) getJSON(`api/jobs/${encodeURIComponent(want)}`).then(showJob).catch(e => console.error(e));
}
window.addEventListener("hashchange", fromHash);
fromHash();
refresh();
setInterval(refresh, 5000);
