"use strict";
// PactMesh 控制台 M2：纯原生 JS（无 htmx/SPA/构建步骤）。
// 读面板每 2 秒轮询；会话条解锁/锁定 + TTL；成员/待批治理写操作经 JSON fetch。

const READ_TABS = {
  overview: { url: "/api/node", render: renderObject },
  peers: { url: "/api/peers", render: renderFirstArray },
  routes: { url: "/api/routes", render: renderFirstArray },
  stats: { url: "/api/stats", render: renderFirstArray },
};

let active = "overview";
let readTimer = null;

// ---------- 通用 ----------

function setStatus(cls, text) {
  const el = document.getElementById("status");
  el.className = "status " + cls;
  el.textContent = text;
}
function isScalar(v) {
  return v === null || ["string", "number", "boolean"].includes(typeof v);
}
function fmt(v) {
  if (v === null) return "null";
  if (isScalar(v)) return String(v);
  return JSON.stringify(v);
}
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function flash(msg, isErr) {
  const el = document.getElementById("flash");
  el.textContent = msg;
  el.className = "flash " + (isErr ? "err" : "ok");
  if (msg) setTimeout(() => { if (el.textContent === msg) el.textContent = ""; }, 6000);
}

async function getJson(url) {
  const resp = await fetch(url, { headers: { Accept: "application/json" } });
  const data = await resp.json().catch(() => null);
  return { ok: resp.ok, status: resp.status, data };
}
async function postJson(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await resp.json().catch(() => null);
  return { ok: resp.ok, status: resp.status, data };
}
function errText(r) {
  return (r.data && r.data.error) || ("HTTP " + r.status);
}

// ---------- 只读渲染 ----------

function renderObject(obj) {
  if (!obj || typeof obj !== "object") return `<div class="empty">无数据</div>`;
  const rows = Object.entries(obj)
    .map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(fmt(v))}</div>`)
    .join("");
  return `<div class="kv">${rows}</div>`;
}
function renderArray(arr) {
  if (!arr.length) return `<div class="empty">空</div>`;
  const cols = [];
  for (const row of arr) {
    if (row && typeof row === "object" && !Array.isArray(row)) {
      for (const k of Object.keys(row)) if (!cols.includes(k)) cols.push(k);
    }
  }
  if (!cols.length) {
    return `<table><tbody>${arr.map((r) => `<tr><td>${esc(fmt(r))}</td></tr>`).join("")}</tbody></table>`;
  }
  const head = cols.map((c) => `<th>${esc(c)}</th>`).join("");
  const body = arr
    .map((row) => {
      const cells = cols
        .map((c) => {
          const v = row ? row[c] : undefined;
          if (v === undefined) return `<td></td>`;
          return isScalar(v) ? `<td>${esc(fmt(v))}</td>` : `<td class="nested">${esc(fmt(v))}</td>`;
        })
        .join("");
      return `<tr>${cells}</tr>`;
    })
    .join("");
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}
function renderFirstArray(obj) {
  if (Array.isArray(obj)) return renderArray(obj);
  if (obj && typeof obj === "object") {
    for (const v of Object.values(obj)) if (Array.isArray(v)) return renderArray(v);
    return renderObject(obj);
  }
  return `<div class="empty">无数据</div>`;
}

async function refreshRead() {
  const tab = READ_TABS[active];
  if (!tab) return;
  const body = document.getElementById("body-" + active);
  const r = await getJson(tab.url);
  if (!r.ok) {
    setStatus("err", "HTTP " + r.status);
    body.innerHTML = `<div class="empty">请求失败：${r.status}</div>`;
    return;
  }
  setStatus("ok", "已连接");
  body.innerHTML = tab.render(r.data);
}

// ---------- 会话条 ----------

function selectedNet() {
  const sel = document.getElementById("net-select");
  if (!sel.value) return null;
  try {
    const [td, nid] = JSON.parse(sel.value);
    return { td, nid };
  } catch (e) {
    return null;
  }
}

async function loadDomains() {
  const sel = document.getElementById("net-select");
  const r = await getJson("/api/domains");
  if (!r.ok || !Array.isArray(r.data)) return;
  const opts = [];
  for (const d of r.data) {
    const lbl = d.label || d.trust_domain_id.slice(0, 10);
    const tag = d.is_root_holder ? "" : "（无 root）";
    for (const nid of d.networks || []) {
      const val = esc(JSON.stringify([d.trust_domain_id, nid]));
      opts.push(`<option value="${val}">${esc(lbl)} / ${esc(nid)} ${tag}</option>`);
    }
  }
  sel.innerHTML = opts.length ? opts.join("") : `<option value="">（无可治理网络）</option>`;
}

async function refreshSession() {
  const r = await getJson("/api/session");
  const el = document.getElementById("sess-state");
  const d = r.data || {};
  if (d.unlocked) {
    el.className = "status ok";
    el.textContent = `已解锁 ${d.ttl_secs}s`;
  } else {
    el.className = "status warn";
    el.textContent = "未解锁";
  }
}

async function doUnlock() {
  const net = selectedNet();
  if (!net) { flash("请选择网络", true); return; }
  const pass = document.getElementById("pass").value;
  if (!pass) { flash("请输入 root 口令", true); return; }
  const r = await postJson("/api/unlock", {
    trust_domain_id: net.td,
    network_local_id: net.nid,
    passphrase: pass,
  });
  document.getElementById("pass").value = "";
  if (r.ok) { flash("已解锁", false); refreshSession(); }
  else flash("解锁失败：" + errText(r), true);
}

async function doLock() {
  await postJson("/api/lock", {});
  flash("已锁定", false);
  refreshSession();
}

// ---------- 成员 ----------

function capCompact(c) {
  if (!c || typeof c !== "object") return "";
  const f = [];
  if (c.can_relay_data) f.push("relay-data");
  if (c.can_relay_control) f.push("relay-ctrl");
  if (c.can_be_exit_node) f.push("exit");
  if (Array.isArray(c.can_proxy_subnet) && c.can_proxy_subnet.length) f.push("proxy:" + c.can_proxy_subnet.length);
  return f.join(" ");
}

function actBtn(action, fp, label, danger) {
  return `<button class="act${danger ? " danger" : ""}" data-act="${action}" data-fp="${esc(fp)}">${label}</button>`;
}

async function loadMembers() {
  const body = document.getElementById("body-members");
  const net = selectedNet();
  if (!net) { body.innerHTML = `<div class="empty">请在上方选择网络</div>`; return; }
  const url = `/api/members?trust_domain_id=${encodeURIComponent(net.td)}&network_local_id=${encodeURIComponent(net.nid)}`;
  const r = await getJson(url);
  if (!r.ok || !Array.isArray(r.data)) { body.innerHTML = `<div class="empty">加载失败：${esc(errText(r))}</div>`; return; }
  if (!r.data.length) { body.innerHTML = `<div class="bar"><button id="m-refresh">刷新</button></div><div class="empty">无成员</div>`; }
  else {
    const rows = r.data.map((m) => {
      const fp = m.fingerprint || "";
      const act = [
        actBtn("disable", fp, "禁用"),
        actBtn("enable", fp, "启用"),
        actBtn("rename", fp, "改名"),
        actBtn("hostname", fp, "主机名"),
        actBtn("capability", fp, "能力"),
        actBtn("revoke", fp, "吊销", true),
      ].join(" ");
      return `<tr>
        <td>${esc(m.device_label || "")}</td>
        <td class="mono">${esc(fp.slice(0, 10))}</td>
        <td>${esc(m.role || "")}</td>
        <td>${esc(m.status || "")}</td>
        <td>${esc(m.hostname || "")}</td>
        <td>${esc(capCompact(m.capabilities))}</td>
        <td class="actions">${act}</td>
      </tr>`;
    }).join("");
    body.innerHTML = `<div class="bar"><button id="m-refresh">刷新</button></div>
      <table><thead><tr><th>设备</th><th>指纹</th><th>角色</th><th>状态</th><th>主机名</th><th>能力</th><th>操作</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
  document.getElementById("m-refresh").onclick = loadMembers;
}

async function memberAction(action, fp) {
  const body = { fingerprint: fp };
  if (action === "rename") {
    const label = prompt("新设备名：");
    if (label === null || label.trim() === "") return;
    body.label = label.trim();
  } else if (action === "hostname") {
    const h = prompt("主机名（留空=清除）：", "");
    if (h === null) return;
    body.hostname = h.trim();
  } else if (action === "capability") {
    const rd = prompt("can_relay_data (y/n，留空不改)：", "");
    if (rd === null) return;
    if (rd.trim() !== "") body.relay_data = /^y/i.test(rd);
    const rc = prompt("can_relay_control (y/n，留空不改)：", "");
    if (rc === null) return;
    if (rc.trim() !== "") body.relay_control = /^y/i.test(rc);
    const ps = prompt("proxy_subnet CIDR（逗号分隔；留空不改；输入 - 清空）：", "");
    if (ps === null) return;
    if (ps.trim() === "-") body.clear_proxy_subnet = true;
    else if (ps.trim() !== "") body.proxy_subnet = ps.split(",").map((x) => x.trim()).filter(Boolean);
  } else if (action === "revoke") {
    if (!confirm("吊销不可逆，确认吊销 " + fp.slice(0, 10) + " ？")) return;
    const reason = prompt("原因 (unspecified/key-compromise/device-lost/removed/superseded)：", "removed");
    if (reason === null) return;
    if (reason.trim()) body.reason = reason.trim();
  } else if (action === "disable") {
    if (!confirm("禁用 " + fp.slice(0, 10) + " ？")) return;
  }
  const r = await postJson("/api/" + action, body);
  if (r.ok) {
    const v = r.data || {};
    flash(`${action} 成功 v${v.previous_version}→${v.version}`, false);
    loadMembers();
    refreshSession();
  } else {
    flash(`${action} 失败：${errText(r)}`, true);
  }
}

// ---------- 待批入网 ----------

async function loadPending() {
  const body = document.getElementById("body-pending");
  const net = selectedNet();
  if (!net) { body.innerHTML = `<div class="empty">请在上方选择网络</div>`; return; }
  const url = `/api/pending?trust_domain_id=${encodeURIComponent(net.td)}&network_local_id=${encodeURIComponent(net.nid)}`;
  const r = await getJson(url);
  if (!r.ok || !Array.isArray(r.data)) { body.innerHTML = `<div class="empty">加载失败：${esc(errText(r))}</div>`; return; }
  let table;
  if (!r.data.length) {
    table = `<div class="empty">无待批申请</div>`;
  } else {
    const rows = r.data.map((p) => {
      const pk = p.applicant_pk || "";
      return `<tr>
        <td>${esc(p.device_label || "")}</td>
        <td class="mono">${esc(pk.slice(0, 12))}</td>
        <td>${esc(p.hint || "")}</td>
        <td class="actions">
          <button class="pact" data-do="approve" data-pk="${esc(pk)}" data-label="${esc(p.device_label || "")}">批准</button>
          <button class="pact danger" data-do="reject" data-pk="${esc(pk)}">拒绝</button>
        </td></tr>`;
    }).join("");
    table = `<table><thead><tr><th>申请设备</th><th>公钥</th><th>提示</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  body.innerHTML = `<div class="bar"><button id="p-refresh">刷新</button></div>${table}`;
  document.getElementById("p-refresh").onclick = loadPending;
}

async function pendingAction(action, pk, label) {
  const net = selectedNet();
  if (!net) return;
  let r;
  if (action === "approve") {
    if (!confirm(`批准 ${label || pk.slice(0, 10)} 入网？`)) return;
    r = await postJson("/api/approve", { applicant_pk: pk, device_label: label || "device" });
  } else {
    if (!confirm(`拒绝 ${pk.slice(0, 10)}？`)) return;
    r = await postJson("/api/reject", {
      trust_domain_id: net.td,
      network_local_id: net.nid,
      applicant_pk: pk,
    });
  }
  if (r.ok) { flash(action + " 成功", false); loadPending(); refreshSession(); }
  else flash(action + " 失败：" + errText(r), true);
}

// ---------- 配置下发（daemon RPC，无需解锁，作用于控制器绑定的实例） ----------

const CFG_FORMS = [
  { ep: "connector", title: "连接器", action: true, fields: [["url", "tcp://host:port"]] },
  { ep: "mapped-listener", title: "映射监听", action: true, fields: [["url", "tcp://0.0.0.0:port"]] },
  { ep: "port-forward", title: "端口转发", action: true, fields: [["protocol", "tcp|udp"], ["bind_addr", "127.0.0.1:8080"], ["dst_addr", "10.0.0.2:80(可空)"]] },
  { ep: "route", title: "手动路由", action: true, fields: [["cidr", "10.0.0.0/24"]] },
  { ep: "proxy-network", title: "子网代理", action: true, fields: [["cidr", "10.0.0.0/24"], ["mapped_cidr", "映射(可空)"]] },
  { ep: "exit-node", title: "出口节点", action: true, fields: [["node", "10.0.0.2"]] },
  { ep: "relay-serving", title: "跨域中继授权", action: true, fields: [["foreign_root_pk_hex", "root pk hex"], ["can_relay_data", "@check 中继数据"], ["can_assist_holepunch", "@check 协助打洞"], ["ttl_secs", "@num ttl秒"]] },
  { ep: "hostname", title: "主机名", fields: [["hostname", "my-host"]] },
  { ep: "ipv4", title: "IPv4", fields: [["ipv4", "10.0.0.5/24"]] },
  { ep: "whitelist", title: "白名单", fields: [["kind", "tcp|udp"], ["ports", "80,443,8000-9000"], ["clear", "@check 清空"]] },
];

function fieldInput(ep, name, ph) {
  if (ph.startsWith("@check")) {
    const lbl = ph.replace("@check", "").trim() || name;
    return `<label class="ck"><input type="checkbox" data-f="${name}"> ${esc(lbl)}</label>`;
  }
  if (ph.startsWith("@num")) {
    return `<input type="number" data-f="${name}" placeholder="${esc(ph.replace("@num", "").trim())}">`;
  }
  return `<input data-f="${name}" placeholder="${esc(ph)}">`;
}

function cfgForm(f) {
  const action = f.action
    ? `<select data-f="action"><option value="add">add</option><option value="remove">remove</option></select>`
    : "";
  const inputs = f.fields.map(([n, ph]) => fieldInput(f.ep, n, ph)).join(" ");
  return `<form class="cfgform" data-ep="/api/config/${f.ep}">
    <span class="cfgtitle">${esc(f.title)}</span>${action}${inputs}
    <button type="submit">下发</button></form>`;
}

async function loadConfig() {
  const body = document.getElementById("body-config");
  const r = await getJson("/api/config");
  const cfg = (r.ok && r.data && r.data.config) || {};
  body.innerHTML = `<div class="bar"><button id="c-refresh">刷新</button></div>
    <h3>下发配置补丁</h3>
    <div class="cfgforms">${CFG_FORMS.map(cfgForm).join("")}</div>
    <h3>当前实例配置</h3>
    <div>${renderObject(cfg)}</div>`;
  document.getElementById("c-refresh").onclick = loadConfig;
}

async function submitCfgForm(form) {
  const body = {};
  for (const el of form.querySelectorAll("[data-f]")) {
    const k = el.dataset.f;
    if (el.type === "checkbox") body[k] = el.checked;
    else if (el.type === "number") { if (el.value !== "") body[k] = Number(el.value); }
    else { const v = el.value.trim(); if (v !== "") body[k] = v; }
  }
  const r = await postJson(form.dataset.ep, body);
  if (r.ok) { flash("下发成功", false); loadConfig(); }
  else flash("下发失败：" + errText(r), true);
}

// ---------- ACL 编辑器（数据面 acl.proto，daemon RPC，无需解锁） ----------

const PROTO_OPTS = [[0, "Unspecified"], [1, "TCP"], [2, "UDP"], [3, "ICMP"], [4, "ICMPv6"], [5, "Any"]];
const ACTION_OPTS = [[0, "Noop"], [1, "Allow"], [2, "Drop"]];
const CHAINTYPE_OPTS = [[1, "Inbound"], [2, "Outbound"], [3, "Forward"], [0, "Unspecified"]];

let aclState = null;

function emptyAcl() { return { acl_v1: { chains: [], group: { declares: [], members: [] } } }; }
function newRule() {
  return { name: "", description: "", priority: 0, enabled: true, protocol: 5, ports: [],
    source_ips: [], destination_ips: [], source_ports: [], action: 1, rate_limit: 0,
    burst_limit: 0, stateful: false, source_groups: [], destination_groups: [] };
}
function newChain() {
  return { name: "new-chain", chain_type: 1, description: "", enabled: true, rules: [], default_action: 2 };
}
function selOpts(opts, val) {
  return opts.map(([v, t]) => `<option value="${v}"${v === val ? " selected" : ""}>${t}</option>`).join("");
}
function csv(arr) { return Array.isArray(arr) ? arr.join(",") : ""; }

function ruleRow(ci, ri, r) {
  const d = `data-ci="${ci}" data-ri="${ri}"`;
  return `<tr>
    <td><input type="checkbox" ${d} data-rf="enabled"${r.enabled ? " checked" : ""}></td>
    <td><input ${d} data-rf="name" value="${esc(r.name)}" size="8"></td>
    <td><input type="number" ${d} data-rf="priority" value="${r.priority}" size="3"></td>
    <td><select ${d} data-rf="protocol">${selOpts(PROTO_OPTS, r.protocol)}</select></td>
    <td><input ${d} data-rf="ports" value="${esc(csv(r.ports))}" size="7"></td>
    <td><input ${d} data-rf="source_ips" value="${esc(csv(r.source_ips))}" size="10"></td>
    <td><input ${d} data-rf="destination_ips" value="${esc(csv(r.destination_ips))}" size="10"></td>
    <td><select ${d} data-rf="action">${selOpts(ACTION_OPTS, r.action)}</select></td>
    <td><input type="number" ${d} data-rf="rate_limit" value="${r.rate_limit}" size="4"></td>
    <td><button class="act danger" data-aclop="del-rule" ${d}>×</button></td></tr>`;
}

function chainBlock(ci, c) {
  const rules = (c.rules || []).map((r, ri) => ruleRow(ci, ri, r)).join("");
  return `<div class="chain"><div class="bar">
      <input data-ci="${ci}" data-cf="name" value="${esc(c.name)}" placeholder="链名" size="10">
      类型 <select data-ci="${ci}" data-cf="chain_type">${selOpts(CHAINTYPE_OPTS, c.chain_type)}</select>
      默认 <select data-ci="${ci}" data-cf="default_action">${selOpts(ACTION_OPTS, c.default_action)}</select>
      <label class="ck"><input type="checkbox" data-ci="${ci}" data-cf="enabled"${c.enabled ? " checked" : ""}> 启用</label>
      <button class="act" data-aclop="add-rule" data-ci="${ci}">+规则</button>
      <button class="act danger" data-aclop="del-chain" data-ci="${ci}">删链</button></div>
    <table><thead><tr><th>启用</th><th>名称</th><th>优先级</th><th>协议</th><th>端口</th><th>源IP</th><th>目的IP</th><th>动作</th><th>限速</th><th></th></tr></thead>
    <tbody>${rules}</tbody></table></div>`;
}

function renderAcl() {
  const body = document.getElementById("body-acl");
  const chains = (aclState.acl_v1 && aclState.acl_v1.chains) || [];
  const blocks = chains.length ? chains.map((c, ci) => chainBlock(ci, c)).join("") : `<div class="empty">无链</div>`;
  body.innerHTML = `<div class="bar">
      <button id="acl-reload">重载</button>
      <button id="acl-addchain" class="act">+链</button>
      <button id="acl-save">保存 ACL</button>
      <button id="acl-statbtn">刷新统计</button></div>
    <div id="acl-chains">${blocks}</div>
    <h3>ACL 统计 / 连接跟踪</h3>
    <div id="acl-statbox" class="empty">点“刷新统计”加载</div>`;
  document.getElementById("acl-reload").onclick = loadAcl;
  document.getElementById("acl-addchain").onclick = () => { aclSyncFromDom(); aclState.acl_v1.chains.push(newChain()); renderAcl(); };
  document.getElementById("acl-save").onclick = saveAcl;
  document.getElementById("acl-statbtn").onclick = loadAclStats;
}

function aclSyncFromDom() {
  const chains = aclState.acl_v1.chains;
  for (const el of document.querySelectorAll("#acl-chains [data-cf]")) {
    const c = chains[+el.dataset.ci]; if (!c) continue;
    const f = el.dataset.cf;
    if (el.type === "checkbox") c[f] = el.checked;
    else if (el.tagName === "SELECT") c[f] = Number(el.value);
    else c[f] = el.value;
  }
  for (const el of document.querySelectorAll("#acl-chains [data-rf]")) {
    const c = chains[+el.dataset.ci]; if (!c || !c.rules) continue;
    const r = c.rules[+el.dataset.ri]; if (!r) continue;
    const f = el.dataset.rf;
    if (el.type === "checkbox") r[f] = el.checked;
    else if (el.type === "number" || el.tagName === "SELECT") r[f] = Number(el.value);
    else if (f === "ports" || f === "source_ips" || f === "destination_ips")
      r[f] = el.value.split(",").map((x) => x.trim()).filter(Boolean);
    else r[f] = el.value;
  }
}

async function loadAcl() {
  const body = document.getElementById("body-acl");
  const r = await getJson("/api/config");
  if (!r.ok) { body.innerHTML = `<div class="empty">加载失败：${esc(errText(r))}</div>`; return; }
  const acl = r.data && r.data.config && r.data.config.acl;
  aclState = acl && acl.acl_v1 ? acl : emptyAcl();
  aclState.acl_v1 = aclState.acl_v1 || { chains: [], group: { declares: [], members: [] } };
  aclState.acl_v1.chains = aclState.acl_v1.chains || [];
  aclState.acl_v1.group = aclState.acl_v1.group || { declares: [], members: [] };
  renderAcl();
}

async function saveAcl() {
  aclSyncFromDom();
  if (!confirm("保存并下发 ACL 配置？")) return;
  const r = await postJson("/api/config/acl", aclState);
  if (r.ok) { flash("ACL 已下发", false); loadAcl(); }
  else flash("ACL 下发失败：" + errText(r), true);
}

async function loadAclStats() {
  const box = document.getElementById("acl-statbox");
  const r = await getJson("/api/acl-stats");
  if (!r.ok) { box.innerHTML = `<div class="empty">加载失败：${esc(errText(r))}</div>`; return; }
  const stats = (r.data && r.data.acl_stats) || {};
  const rules = (stats.rules || []).map((x) => ({
    rule: x.rule && x.rule.name, packets: x.stat && x.stat.packet_count, bytes: x.stat && x.stat.byte_count,
  }));
  const ct = stats.conn_track || [];
  box.innerHTML = `<h4>规则命中</h4>${rules.length ? renderArray(rules) : `<div class="empty">无</div>`}
    <h4>连接跟踪</h4>${ct.length ? renderArray(ct) : `<div class="empty">无</div>`}`;
}

// ---------- 凭据（daemon RPC，无需解锁） ----------

function credRow(c) {
  const id = c.credential_id || "";
  return `<tr>
    <td class="mono">${esc(id)}</td>
    <td>${esc(csv(c.groups))}</td>
    <td>${c.allow_relay ? "是" : ""}</td>
    <td>${esc(c.expiry_unix || "")}</td>
    <td>${esc(csv(c.allowed_proxy_cidrs))}</td>
    <td class="actions"><button class="act danger" data-revoke="${esc(id)}">吊销</button></td></tr>`;
}

async function loadCredentials() {
  const body = document.getElementById("body-credentials");
  const r = await getJson("/api/credentials");
  const creds = (r.ok && r.data && r.data.credentials) || [];
  const list = creds.length
    ? `<table><thead><tr><th>ID</th><th>组</th><th>中继</th><th>到期</th><th>代理CIDR</th><th></th></tr></thead><tbody>${creds.map(credRow).join("")}</tbody></table>`
    : `<div class="empty">无凭据</div>`;
  body.innerHTML = `<div class="bar"><button id="cr-refresh">刷新</button></div>
    <h3>签发凭据</h3>
    <form id="cr-gen" class="cfgform">
      <input data-f="ttl_seconds" type="number" placeholder="TTL秒(必填>0)">
      <input data-f="groups" placeholder="组(逗号,可空)">
      <input data-f="allowed_proxy_cidrs" placeholder="代理CIDR(逗号,可空)">
      <input data-f="credential_id" placeholder="ID(可空)">
      <label class="ck"><input type="checkbox" data-f="allow_relay"> 允许中继</label>
      <label class="ck"><input type="checkbox" data-f="reusable" checked> 可复用</label>
      <button type="submit">签发</button></form>
    <div id="cr-result"></div>
    <h3>现有凭据</h3>${list}`;
  document.getElementById("cr-refresh").onclick = loadCredentials;
  document.getElementById("cr-gen").addEventListener("submit", genCredential);
}

async function genCredential(e) {
  e.preventDefault();
  const form = e.target;
  const g = (n) => form.querySelector(`[data-f="${n}"]`);
  const ttl = Number(g("ttl_seconds").value);
  if (!ttl || ttl <= 0) { flash("TTL 必须 > 0", true); return; }
  const csvVal = (n) => g(n).value.split(",").map((x) => x.trim()).filter(Boolean);
  const body = {
    ttl_seconds: ttl, groups: csvVal("groups"), allowed_proxy_cidrs: csvVal("allowed_proxy_cidrs"),
    allow_relay: g("allow_relay").checked, reusable: g("reusable").checked,
  };
  const cid = g("credential_id").value.trim();
  if (cid) body.credential_id = cid;
  const r = await postJson("/api/credentials/generate", body);
  if (r.ok) {
    const d = r.data || {};
    document.getElementById("cr-result").innerHTML =
      `<div class="flash ok">已签发 id=<span class="mono">${esc(d.credential_id)}</span> · secret=<span class="mono">${esc(d.credential_secret)}</span>（仅此一次）</div>`;
    flash("凭据已签发", false);
  } else flash("签发失败：" + errText(r), true);
}

async function revokeCredential(id) {
  if (!confirm("吊销凭据 " + id + "？")) return;
  const r = await postJson("/api/credentials/revoke", { credential_id: id });
  if (r.ok) { flash("已吊销", false); loadCredentials(); }
  else flash("吊销失败：" + errText(r), true);
}

// ---------- M4：引导 / 高危治理（建域/建网/升根/tags/peer-hints/invite） ----------

function netQS() {
  const net = selectedNet();
  if (!net) return null;
  return `trust_domain_id=${encodeURIComponent(net.td)}&network_local_id=${encodeURIComponent(net.nid)}`;
}

async function loadTrust() {
  const body = document.getElementById("body-trust");
  const r = await getJson("/api/domains");
  const domains = r.ok && Array.isArray(r.data) ? r.data : [];
  const domOpts =
    domains
      .filter((d) => d.is_root_holder)
      .map((d) => {
        const lbl = d.label || d.trust_domain_id.slice(0, 10);
        return `<option value="${esc(d.trust_domain_id)}">${esc(lbl)} (${esc(d.trust_domain_id.slice(0, 10))})</option>`;
      })
      .join("") || `<option value="">（无持 root 的域）</option>`;
  body.innerHTML = `
    <div class="warnbar">⚠ 高危治理：建域生成新管理口令、升根授予对方完整 root 权限，均不可逆。口令即用即清、绝不缓存。</div>
    <h3>建域（生成新信任域 + 新管理口令）</h3>
    <form class="cfgform" id="t-create-domain">
      <input data-f="label" placeholder="域标签">
      <input data-f="passphrase" type="password" placeholder="新管理口令(≥8)" autocomplete="new-password">
      <button type="submit">建域</button></form>
    <div id="t-domain-result"></div>
    <h3>建网（在既有域下新建网络）</h3>
    <form class="cfgform" id="t-create-network">
      <select data-f="trust_domain_id">${domOpts}</select>
      <input data-f="network_local_id" placeholder="network_local_id">
      <select data-f="default_action"><option value="accept">accept</option><option value="drop">drop</option></select>
      <input data-f="passphrase" type="password" placeholder="域管理口令" autocomplete="off">
      <button type="submit">建网</button></form>
    <h3>升级 peer 为 root（需先在顶部解锁本网络）</h3>
    <form class="cfgform" id="t-upgrade-root">
      <input data-f="peer_id" type="number" placeholder="peer_id">
      <button type="submit" class="danger">升根</button></form>
    <h3>本机预授权 root 升级（武装限时一次性接受令牌）</h3>
    <form class="cfgform" id="t-arm-root">
      <input data-f="passphrase" type="password" placeholder="升级后管理口令(≥8)" autocomplete="off">
      <input data-f="ttl_secs" type="number" placeholder="ttl秒(默认300)">
      <button type="submit">武装</button></form>
    <h3>ACL Tags（需解锁；作用于顶部所选网络）</h3>
    <div class="bar"><button id="t-tags-refresh">刷新 tags</button></div>
    <div id="t-tags-box" class="empty">点“刷新 tags”</div>
    <form class="cfgform" id="t-tag">
      <input data-f="fingerprint" placeholder="成员指纹">
      <input data-f="tag" placeholder="tag 名">
      <select data-f="add"><option value="true">add</option><option value="false">remove</option></select>
      <button type="submit">应用</button></form>
    <h3>Peer Hints（需解锁；作用于顶部所选网络）</h3>
    <div class="bar"><button id="t-hints-refresh">刷新 hints</button></div>
    <div id="t-hints-box" class="empty">点“刷新 hints”</div>
    <form class="cfgform" id="t-peer-hint">
      <input data-f="url" placeholder="tcp://host:port">
      <input data-f="label" placeholder="标签(可空)">
      <input data-f="capabilities" placeholder="能力(逗号,可空)">
      <input data-f="expires_at" type="number" placeholder="到期unix(可空)">
      <select data-f="add"><option value="true">add</option><option value="false">remove</option></select>
      <button type="submit">应用</button></form>
    <h3>导出 invite（供他机加入；作用于顶部所选网络）</h3>
    <form class="cfgform" id="t-invite">
      <label class="chk"><input type="checkbox" data-f="include_peer_hints" checked> 自动包含 peer-hints</label>
      <label class="chk"><input type="checkbox" data-f="include_local_listeners" checked> 自动包含本机监听地址</label>
      <input data-f="seeds" placeholder="额外 seed url(可选，逗号分隔)">
      <select data-f="format"><option value="url">url</option><option value="file">file</option></select>
      <button type="submit">导出</button></form>
    <div id="t-invite-result"></div>`;
  document.getElementById("t-tags-refresh").onclick = loadTags;
  document.getElementById("t-hints-refresh").onclick = loadPeerHints;
}

async function loadTags() {
  const box = document.getElementById("t-tags-box");
  const qs = netQS();
  if (!qs) { box.innerHTML = `<div class="empty">请在顶部选择网络</div>`; return; }
  const r = await getJson("/api/trust/tags?" + qs);
  if (!r.ok || !Array.isArray(r.data)) { box.innerHTML = `<div class="empty">加载失败：${esc(errText(r))}</div>`; return; }
  box.innerHTML = r.data.length
    ? renderArray(r.data.map((t) => ({ tag: t.tag, members: csv(t.members) })))
    : `<div class="empty">无 tags</div>`;
}

async function loadPeerHints() {
  const box = document.getElementById("t-hints-box");
  const qs = netQS();
  if (!qs) { box.innerHTML = `<div class="empty">请在顶部选择网络</div>`; return; }
  const r = await getJson("/api/trust/peer-hints?" + qs);
  if (!r.ok || !Array.isArray(r.data)) { box.innerHTML = `<div class="empty">加载失败：${esc(errText(r))}</div>`; return; }
  box.innerHTML = r.data.length ? renderArray(r.data) : `<div class="empty">无 peer hints</div>`;
}

async function trustSubmit(form) {
  const g = (n) => form.querySelector(`[data-f="${n}"]`);
  const val = (n) => { const el = g(n); return el ? el.value.trim() : ""; };
  const clearPass = () => { const p = g("passphrase"); if (p) p.value = ""; };

  switch (form.id) {
    case "t-create-domain": {
      const label = val("label"), pass = val("passphrase");
      if (!label || pass.length < 8) { flash("标签必填、口令≥8", true); return; }
      if (!confirm("建域将生成新 root 与新管理口令，确认？")) return;
      const r = await postJson("/api/trust/create-domain", { label, passphrase: pass });
      clearPass();
      if (r.ok) {
        const d = r.data || {};
        document.getElementById("t-domain-result").innerHTML =
          `<div class="flash ok">已建域 td=<span class="mono">${esc(d.trust_domain_id)}</span> · 务必牢记管理口令并备份 sk_root.age</div>`;
        flash("建域成功", false); loadDomains(); loadTrust();
      } else flash("建域失败：" + errText(r), true);
      break;
    }
    case "t-create-network": {
      const td = val("trust_domain_id"), nid = val("network_local_id"), pass = val("passphrase"), da = val("default_action");
      if (!td || !nid || !pass) { flash("域/网络名/口令必填", true); return; }
      if (!confirm(`在域 ${td.slice(0, 10)} 下建网 ${nid}？`)) return;
      const r = await postJson("/api/trust/create-network", { trust_domain_id: td, network_local_id: nid, passphrase: pass, default_action: da });
      clearPass();
      if (r.ok) { flash("建网成功 v" + (r.data && r.data.version), false); loadDomains(); }
      else flash("建网失败：" + errText(r), true);
      break;
    }
    case "t-upgrade-root": {
      const pid = Number(val("peer_id"));
      if (!pid) { flash("peer_id 必填", true); return; }
      if (!confirm(`升级 peer_id=${pid} 为 root 持有者？此举授予对方完整治理权，不可撤销！`)) return;
      const r = await postJson("/api/trust/upgrade-peer-to-root", { peer_id: pid });
      if (r.ok) { flash("升根成功 ack=" + (r.data && r.data.ack), false); refreshSession(); }
      else flash("升根失败：" + errText(r), true);
      break;
    }
    case "t-arm-root": {
      const pass = val("passphrase"), ttl = Number(val("ttl_secs")) || 300;
      if (pass.length < 8) { flash("口令≥8", true); return; }
      if (!confirm("武装本机接受一次性 root 升级令牌？")) return;
      const r = await postJson("/api/trust/arm-root-upgrade", { passphrase: pass, ttl_secs: ttl });
      clearPass();
      if (r.ok) { flash("已武装 " + (r.data && r.data.armed_ttl_secs) + "s", false); }
      else flash("武装失败：" + errText(r), true);
      break;
    }
    case "t-tag": {
      const fp = val("fingerprint"), tag = val("tag"), add = val("add") === "true";
      if (!fp || !tag) { flash("指纹/tag 必填", true); return; }
      const r = await postJson("/api/trust/tag", { fingerprint: fp, tag, add });
      if (r.ok) { flash(`tag ${add ? "added" : "removed"} v${r.data.previous_version}→${r.data.version}`, false); loadTags(); refreshSession(); }
      else flash("tag 失败：" + errText(r), true);
      break;
    }
    case "t-peer-hint": {
      const url = val("url");
      if (!url) { flash("url 必填", true); return; }
      const body = { url, add: val("add") === "true" };
      const lbl = val("label"); if (lbl) body.label = lbl;
      const caps = val("capabilities"); if (caps) body.capabilities = caps.split(",").map((x) => x.trim()).filter(Boolean);
      const exp = val("expires_at"); if (exp) body.expires_at = Number(exp);
      const r = await postJson("/api/trust/peer-hint", body);
      if (r.ok) { flash(`peer-hint v${r.data.previous_version}→${r.data.version}`, false); loadPeerHints(); refreshSession(); }
      else flash("peer-hint 失败：" + errText(r), true);
      break;
    }
    case "t-invite": {
      const net = selectedNet();
      if (!net) { flash("请在顶部选择网络", true); return; }
      const seeds = val("seeds").split(",").map((x) => x.trim()).filter(Boolean);
      const peerHints = g("include_peer_hints").checked, localL = g("include_local_listeners").checked;
      if (!seeds.length && !peerHints && !localL) { flash("至少勾选一个来源或手填 seed", true); return; }
      const r = await postJson("/api/trust/invite", {
        trust_domain_id: net.td, network_local_id: net.nid, seeds,
        include_peer_hints: peerHints, include_local_listeners: localL, format: val("format"),
      });
      if (r.ok) {
        const d = r.data || {};
        const note = `${d.seed_count} 个落脚点` + (d.omitted ? `（URL 超长，省略 ${d.omitted} 个低优先级）` : "");
        document.getElementById("t-invite-result").innerHTML =
          `<div class="muted">${note}</div><textarea class="invite" readonly rows="4">${esc(d.invite)}</textarea>`;
        flash("invite 已导出", false);
      } else flash("导出失败：" + errText(r), true);
      break;
    }
  }
}

// ---------- 标签调度 ----------

function stopReadTimer() { if (readTimer) { clearInterval(readTimer); readTimer = null; } }
function startReadTimer() { stopReadTimer(); readTimer = setInterval(refreshRead, 2000); }

function selectTab(name) {
  active = name;
  for (const b of document.querySelectorAll("#tabs button"))
    b.classList.toggle("active", b.dataset.tab === name);
  for (const s of document.querySelectorAll(".tab"))
    s.classList.toggle("active", s.id === "tab-" + name);
  if (name === "members") { stopReadTimer(); loadMembers(); }
  else if (name === "pending") { stopReadTimer(); loadPending(); }
  else if (name === "config") { stopReadTimer(); loadConfig(); }
  else if (name === "acl") { stopReadTimer(); loadAcl(); }
  else if (name === "credentials") { stopReadTimer(); loadCredentials(); }
  else if (name === "trust") { stopReadTimer(); loadTrust(); }
  else { startReadTimer(); refreshRead(); }
}

function init() {
  for (const b of document.querySelectorAll("#tabs button"))
    b.addEventListener("click", () => selectTab(b.dataset.tab));
  document.getElementById("btn-unlock").addEventListener("click", doUnlock);
  document.getElementById("btn-lock").addEventListener("click", doLock);
  document.getElementById("pass").addEventListener("keydown", (e) => { if (e.key === "Enter") doUnlock(); });
  document.getElementById("net-select").addEventListener("change", () => {
    if (active === "members") loadMembers();
    else if (active === "pending") loadPending();
    else if (active === "trust") { loadTags(); loadPeerHints(); }
  });
  document.getElementById("body-members").addEventListener("click", (e) => {
    const b = e.target.closest("button.act");
    if (b) memberAction(b.dataset.act, b.dataset.fp);
  });
  document.getElementById("body-pending").addEventListener("click", (e) => {
    const b = e.target.closest("button.pact");
    if (b) pendingAction(b.dataset.do, b.dataset.pk, b.dataset.label);
  });
  document.getElementById("body-config").addEventListener("submit", (e) => {
    if (e.target.classList.contains("cfgform")) { e.preventDefault(); submitCfgForm(e.target); }
  });
  document.getElementById("body-acl").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-aclop]");
    if (!b) return;
    aclSyncFromDom();
    const ci = +b.dataset.ci, op = b.dataset.aclop;
    if (op === "add-rule") aclState.acl_v1.chains[ci].rules.push(newRule());
    else if (op === "del-rule") aclState.acl_v1.chains[ci].rules.splice(+b.dataset.ri, 1);
    else if (op === "del-chain") aclState.acl_v1.chains.splice(ci, 1);
    renderAcl();
  });
  document.getElementById("body-credentials").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-revoke]");
    if (b) revokeCredential(b.dataset.revoke);
  });
  document.getElementById("body-trust").addEventListener("submit", (e) => {
    if (e.target.classList.contains("cfgform")) { e.preventDefault(); trustSubmit(e.target); }
  });

  loadDomains();
  refreshSession();
  setInterval(refreshSession, 1000);
  startReadTimer();
  refreshRead();
}

document.addEventListener("DOMContentLoaded", init);
