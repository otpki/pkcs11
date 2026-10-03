"use strict";

const HISTORY = 120;                       // samples kept per target
const history = new Map();                 // id -> [{t, active, opened}]
const sparkCtx = new Map();                // id -> canvas 2d context
const rateHist = [];                       // [{t, req, err}] -> rates on draw

// Expanded cards survive reloads so the dev loop's page refresh doesn't
// collapse a card the operator opened.
const openCards = new Set();
try { JSON.parse(localStorage.getItem("devui-open") || "[]").forEach(id => openCards.add(id)); } catch (e) {}
const saveOpen = () => { try { localStorage.setItem("devui-open", JSON.stringify([...openCards])); } catch (e) {} };

const el = id => document.getElementById(id);
const fmtBytes = n => n < 1024 ? n + " B"
  : n < 1048576 ? (n/1024).toFixed(1) + " KiB"
  : (n/1048576).toFixed(1) + " MiB";
const fmtAgo = iso => {
  if (!iso || iso.startsWith("0001-")) return "—";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s/60) + "m ago";
  return Math.floor(s/3600) + "h ago";
};
const fmtUntil = iso => {
  if (!iso || iso.startsWith("0001-")) return "";
  const s = (Date.parse(iso) - Date.now()) / 1000;
  return s > 0 ? " · retry in " + Math.ceil(s) + "s" : "";
};

function meter(name, used, max) {
  const capped = max > 0;
  const pct = capped ? Math.min(100, 100 * used / max) : 0;
  const cls = capped && used >= max ? "max" : capped && used >= 0.8 * max ? "hot" : "";
  return `<div class="meter ${cls}">
    <span class="name">${name}</span>
    <span class="bar"><span class="fill" style="width:${pct}%"></span></span>
    <span class="val">${used}${capped ? " / " + max : ""}</span>
  </div>`;
}

function activationLine(a) {
  let parts = [`gen <b>${a.generation}</b>`];
  if (a.activated_by) parts.push(`by <b>${a.activated_by.slice(0, 24)}${a.activated_by.length > 24 ? "…" : ""}</b>`);
  if (a.activated_at && !a.activated_at.startsWith("0001-")) parts.push(fmtAgo(a.activated_at));
  if (a.failed_at && !a.failed_at.startsWith("0001-")) parts.push(`last failure ${fmtAgo(a.failed_at)}`);
  parts.push(fmtUntil(a.retry_after));
  return parts.filter(Boolean).join(" · ");
}

function drawSpark(id) {
  const ctx = sparkCtx.get(id), h = history.get(id);
  if (!ctx || !h || h.length < 2) return;
  const {canvas} = ctx, w = canvas.width, hh = canvas.height;
  ctx.clearRect(0, 0, w, hh);
  const max = Math.max(1, ...h.map(p => p.opened));
  const step = w / (HISTORY - 1), x0 = w - step * (h.length - 1);
  ctx.strokeStyle = "#58a6ff"; ctx.lineWidth = 1.5; ctx.beginPath();
  h.forEach((p, i) => {
    const x = x0 + i * step, y = hh - 2 - (p.active / max) * (hh - 4);
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
}

function drawRate() {
  const canvas = el("rate-spark");
  if (!canvas || rateHist.length < 2) return;
  const ctx = canvas.getContext("2d"), w = canvas.width, hh = canvas.height;
  ctx.clearRect(0, 0, w, hh);
  const rates = [];
  for (let i = 1; i < rateHist.length; i++) {
    const dt = (rateHist[i].t - rateHist[i-1].t) / 1000;
    if (dt <= 0) continue;
    rates.push({
      req: (rateHist[i].req - rateHist[i-1].req) / dt,
      err: (rateHist[i].err - rateHist[i-1].err) / dt,
    });
  }
  if (!rates.length) return;
  const max = Math.max(1, ...rates.map(r => r.req));
  const step = w / (HISTORY - 1), x0 = w - step * (rates.length - 1);
  const plot = (get, color) => {
    ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.beginPath();
    rates.forEach((r, i) => {
      const x = x0 + i * step, y = hh - 2 - (get(r) / max) * (hh - 4);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  };
  plot(r => r.req, "#58a6ff");
  plot(r => r.err, "#f85149");
}

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => "&#" + c.charCodeAt(0) + ";");

// renderClients fills the per-logical-client table: which workload holds
// which route, how it established, and its live resource use.
function renderClients(clients) {
  const rows = clients.map(cl =>
    `<tr><td title="${esc(cl.id)}">${esc(cl.id.slice(0, 12))}…</td>` +
    `<td>${esc(cl.target)}</td>` +
    `<td title="${esc(cl.principal)}">${esc((cl.principal || "—").slice(0, 28))}${cl.principal && cl.principal.length > 28 ? "…" : ""}</td>` +
    `<td>${esc(cl.via || "?")} · ${fmtAgo(cl.since)}</td>` +
    `<td>${fmtAgo(cl.last_used)}</td>` +
    `<td class="${cl.authenticated ? "okc" : ""}">${cl.authenticated ? "yes" : "—"}</td>` +
    `<td>${cl.virtual_sessions ?? 0}</td><td>${cl.objects ?? 0}</td><td>${cl.active_requests ?? 0}</td></tr>`);
  el("client-table").querySelector("tbody").innerHTML =
    rows.join("") || `<tr><td colspan="9" style="color:var(--dim)">no logical clients</td></tr>`;
}

function render(data) {
  el("server-meta").innerHTML =
    `<b>${data.server.address}</b> · up <b>${data.server.uptime_seconds}s</b> · ` +
    `${data.server.go_version} · pid ${data.server.pid} · ` +
    `id <b>${(data.server.server_id || "").slice(0, 12)}</b> · ` +
    `${data.server.state} · tls <b>${data.server.tls_mode || "?"}</b> · ` +
    `${data.server.logical_clients} logical clients`;
  const c = data.server.counters || {}, o = data.server.observability || {};
  const obs = [
    `requests <b>${c.requests_total ?? 0}</b>`,
    `transport errors <b>${c.transport_errors_total ?? 0}</b>`,
    `auth failures <b>${c.auth_failures_total ?? 0}</b>`,
    `fence rejections <b>${c.fence_rejections_total ?? 0}</b>`,
    `drain rejections <b>${c.drain_rejections_total ?? 0}</b>`,
    `stale generations <b>${c.stale_generations_total ?? 0}</b>`,
    `otel <b>${o.otel_enabled ? "on" : "off"}</b>`,
    `log queue <b>${o.log_queue_depth ?? 0}/${o.log_queue_cap ?? 0}</b> dropped <b>${o.log_dropped ?? 0}</b>`,
  ];
  if (o.health_listen) obs.push(`health listener <b>${o.health_listen}</b>`);
  obs.push(o.audit_enabled
    ? `audit <b>${o.audit_sealed ?? 0}/${o.audit_written ?? 0} sealed</b> in <b>${o.audit_checkpoints ?? 0}</b> checkpoints · pending <b>${o.audit_pending ?? 0}</b> · key <b>${o.audit_key_id || "?"}</b> dropped <b>${o.audit_dropped ?? 0}</b> failed <b>${o.audit_failed ?? 0}</b>`
    : `audit <b>off</b>`);
  el("obs-meta").innerHTML = obs.join(" · ");
  el("audit").style.display = o.audit_enabled ? "block" : "none";

  const errTotal = (c.transport_errors_total ?? 0) + (c.auth_failures_total ?? 0) +
    (c.fence_rejections_total ?? 0) + (c.drain_rejections_total ?? 0) +
    (c.stale_generations_total ?? 0);
  rateHist.push({t: Date.now(), req: c.requests_total ?? 0, err: errTotal});
  if (rateHist.length > HISTORY) rateHist.shift();
  drawRate();
  renderClients(data.server.clients || []);
  const root = el("targets");
  const seen = new Set();

  for (const t of data.targets) {
    seen.add(t.id);
    const s = t.stats, a = s.activation;
    let h = history.get(t.id);
    if (!h) history.set(t.id, h = []);
    h.push({t: Date.now(), active: s.physical_active, opened: s.physical_opened});
    if (h.length > HISTORY) h.shift();

    let card = document.getElementById("card-" + t.id);
    if (!card) {
      card = document.createElement("section");
      card.className = "card"; card.id = "card-" + t.id;
      card.innerHTML = `
        <h2><span class="chev">▸</span><span class="tid"></span><span class="rev"></span><span class="sum"></span><span class="hbadge"></span><span class="badge"></span></h2>
        <div class="detail">
          <div class="tok"></div>
          <div class="act"></div>
          <div class="health"></div>
          <div class="meters"></div>
          <div class="subgrid"></div>
          <div class="spark-label">physical sessions in use</div>
          <canvas class="spark" width="660" height="36"></canvas>
        </div>`;
      root.appendChild(card);
      sparkCtx.set(t.id, card.querySelector("canvas").getContext("2d"));
      if (openCards.has(t.id)) card.classList.add("open");
      card.querySelector("h2").addEventListener("click", () => {
        if (card.classList.toggle("open")) openCards.add(t.id);
        else openCards.delete(t.id);
        saveOpen();
      });
    }
    const tid = card.querySelector(".tid");
    tid.textContent = t.id;
    tid.title = t.id;
    card.querySelector(".rev").textContent = "rev " + t.revision;
    card.querySelector(".sum").textContent =
      `phys ${s.physical_active}${s.max_physical ? "/" + s.max_physical : ""} · ` +
      `virt ${s.virtual_sessions} · queued ${s.queued_requests}`;
    const bits = [];
    if (t.token_label) bits.push(`token <b>${t.token_label}</b>`);
    if (t.token_serial) bits.push(`serial <b>${t.token_serial}</b>`);
    if (t.model) bits.push(t.model);
    if (t.manufacturer_id) bits.push(t.manufacturer_id);
    bits.push(`physical slot ${t.slot_id}`);
    card.querySelector(".tok").innerHTML = bits.join(" · ");
    const badge = card.querySelector(".badge");
    badge.className = "badge " + a.state;
    badge.textContent = a.state;
    card.querySelector(".act").innerHTML = activationLine(a);
    // The health badge reports the same per-route probe /readyz serves:
    // healthy/degraded/unhealthy, with failing checks named underneath.
    const hbadge = card.querySelector(".hbadge");
    const health = t.health;
    if (health) {
      hbadge.className = "hbadge " + health.status;
      hbadge.textContent = health.status;
      hbadge.title = "probe " + fmtAgo(health.checked_at);
    } else {
      hbadge.className = "hbadge unknown";
      hbadge.textContent = "?";
      hbadge.title = "no probe result yet";
    }
    const failed = health ? (health.checks || []).filter(c => c.error) : [];
    card.querySelector(".health").innerHTML = failed.length
      ? `failed checks: ` + failed.map(c => `<b>${esc(c.name)}</b>: ${esc(c.error)}`).join(" · ")
      : "";
    card.querySelector(".meters").innerHTML =
      meter("physical opened", s.physical_opened, s.max_physical) +
      meter("physical in use",  s.physical_active, s.max_physical) +
      meter("pinned",           s.pinned_sessions, s.max_pinned) +
      meter("queued requests",  s.queued_requests, s.max_queued) +
      meter("virtual sessions", s.virtual_sessions, s.max_virtual);
    card.querySelector(".subgrid").innerHTML = `
      <div class="stat"><div class="k">clients</div><div class="v">${s.authenticated_clients} authed / ${s.clients}</div></div>
      <div class="stat"><div class="k">dedup ledger</div><div class="v">${fmtBytes(s.dedup_bytes)}${s.max_dedup_bytes ? " / " + fmtBytes(s.max_dedup_bytes) : ""} · ${s.dedup_entries} ops</div></div>`;
    drawSpark(t.id);
  }
  for (const card of [...root.children]) {
    const id = card.id.replace("card-", "");
    if (!seen.has(id)) { card.remove(); history.delete(id); sparkCtx.delete(id); }
  }
  if (!data.targets.length) root.innerHTML = `<div class="empty">no targets configured</div>`;
}

function auditDetail(e) {
  const parts = [];
  if (e.target) parts.push("target=" + e.target);
  if (e.method) parts.push("method=" + e.method);
  if (e.client_id) parts.push("client=" + e.client_id.slice(0, 16) + "…");
  if (e.principal) parts.push("principal=" + e.principal.slice(0, 32) + (e.principal.length > 32 ? "…" : ""));
  if (e.code) parts.push("code=" + e.code);
  if (e.dropped) parts.push("dropped=" + e.dropped);
  return parts.join(" ");
}

let auditTimer = 0;
async function pollAudit() {
  const panel = el("audit");
  if (panel.style.display === "none") return;
  try {
    const r = await fetch("/dev/api/audit/events?tail=12", {cache: "no-store"});
    if (!r.ok) return;
    const a = await r.json();
    el("audit-meta").innerHTML =
      `key <b>${a.key_id || "?"}</b> · <b>${a.sealed ?? 0}</b> records sealed · ` +
      `<b>${a.pending ?? 0}</b> pending next checkpoint`;
    const rows = (a.events || []).slice().reverse().map(e =>
      `<tr><td>${e.seq}</td><td>${esc((e.ts || "").slice(11, 19))}Z</td><td>${esc(e.type)}</td><td>${esc(auditDetail(e))}</td></tr>`);
    el("audit-events").querySelector("tbody").innerHTML =
      rows.join("") || `<tr><td colspan="4" style="color:var(--dim)">no audit events yet</td></tr>`;
  } catch (e) { /* leave stale view */ }
}

el("audit-verify-btn").addEventListener("click", async () => {
  const out = el("audit-verify-result");
  out.className = ""; out.textContent = "verifying…";
  try {
    const r = await fetch("/dev/api/audit/verify", {cache: "no-store"});
    const v = await r.json();
    if (!r.ok || !v.ok) {
      out.className = "bad";
      out.textContent = "failed: " + (v.error || "http " + r.status);
      return;
    }
    const rep = v.report || {};
    out.className = "ok";
    out.textContent = `verified ${rep.records ?? 0} records · ${rep.checkpoints ?? 0} checkpoints` +
      (rep.unsealed ? ` · ${rep.unsealed} unsealed` : "") +
      (rep.partial_tail ? " · torn tail" : "");
  } catch (e) {
    out.className = "bad"; out.textContent = "unreachable";
  }
});
setInterval(pollAudit, 5000);

// Dev PKI tool: POSTs the form, receives a {files: {path: pem}} bundle, and
// renders per-file download links via blob URLs.
el("pki-generate").addEventListener("click", async () => {
  const out = el("pki-result");
  out.className = ""; out.textContent = "generating…";
  const csv = id => el(id).value.split(",").map(s => s.trim()).filter(Boolean);
  try {
    const r = await fetch("/dev/api/pki", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        ca_cn:     el("pki-ca-cn").value,
        server_cn: el("pki-server-cn").value,
        hosts:     csv("pki-hosts"),
        clients:   csv("pki-clients"),
        leaf_days: parseInt(el("pki-days").value, 10) || 0,
      }),
    });
    if (!r.ok) throw new Error((await r.text()).trim() || "http " + r.status);
    const body = await r.json();
    const files = el("pki-files");
    files.style.display = "block";
    files.innerHTML = "";
    const names = Object.keys(body.files).sort();
    const all = document.createElement("div");
    all.className = "file";
    const allLink = document.createElement("a");
    allLink.href = URL.createObjectURL(new Blob([names.map(n => body.files[n]).join("\n")], {type: "application/x-pem-file"}));
    allLink.download = "pki-bundle.pem";
    allLink.textContent = "download all → pki-bundle.pem";
    all.appendChild(allLink);
    files.appendChild(all);
    for (const name of names) {
      const row = document.createElement("div");
      row.className = "file";
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([body.files[name]], {type: "application/x-pem-file"}));
      link.download = name.split("/").pop();
      link.textContent = name;
      row.appendChild(link);
      row.appendChild(document.createTextNode(` ${body.files[name].length} B`));
      files.appendChild(row);
    }
    out.className = "ok";
    out.textContent = `${Object.keys(body.files).length} files ready`;
  } catch (e) {
    out.className = "bad"; out.textContent = "failed: " + e.message;
  }
});

let timer;
async function poll() {
  try {
    const r = await fetch("/dev/api/status", {cache: "no-store"});
    if (!r.ok) throw new Error("http " + r.status);
    render(await r.json());
    el("poll").className = ""; el("poll-label").textContent = "live";
  } catch (e) {
    el("poll").className = "stale"; el("poll-label").textContent = "disconnected";
  }
}
function schedule() { clearTimeout(timer); if (!document.hidden) { poll(); timer = setTimeout(schedule, 1000); } }
document.addEventListener("visibilitychange", () => {
  el("poll").className = document.hidden ? "paused" : "";
  el("poll-label").textContent = document.hidden ? "paused" : "live";
  schedule();
});
schedule();
