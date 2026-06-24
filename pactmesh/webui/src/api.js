// 与后端 36 个 /api/* JSON 端点交互的统一封装。
// 同源请求，鉴权由 pm_token cookie 自动携带（SameSite=Strict）。

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

async function parse(res) {
  const text = await res.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }
  if (!res.ok) {
    const msg = (data && data.error) || (typeof data === 'string' && data) || `HTTP ${res.status}`
    throw new ApiError(res.status, msg)
  }
  return data
}

export async function getJson(path) {
  return parse(await fetch(path, { headers: { Accept: 'application/json' } }))
}

export async function postJson(path, body) {
  return parse(
    await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    }),
  )
}

export async function delJson(path) {
  return parse(await fetch(path, { method: 'DELETE' }))
}

const netQS = (td, nid) =>
  `trust_domain_id=${encodeURIComponent(td)}&network_local_id=${encodeURIComponent(nid)}`

// ---- 具名端点（D1 会话/网络；D2 邀请；D3 成员/待批） ----
export const api = {
  domains: () => getJson('/api/domains'),
  session: () => getJson('/api/session'),
  unlock: (trust_domain_id, network_local_id, passphrase) =>
    postJson('/api/unlock', { trust_domain_id, network_local_id, passphrase }),
  lock: () => postJson('/api/lock'),

  // 成员（读不需解锁，写需会话）
  members: (td, nid) => getJson(`/api/members?${netQS(td, nid)}`),
  rename: (fingerprint, label, note) => postJson('/api/rename', { fingerprint, label, note }),
  hostname: (fingerprint, hostname, note) => postJson('/api/hostname', { fingerprint, hostname, note }),
  capability: (fingerprint, body) => postJson('/api/capability', { fingerprint, ...body }),
  disable: (fingerprint, note) => postJson('/api/disable', { fingerprint, note }),
  enable: (fingerprint) => postJson('/api/enable', { fingerprint }),
  revoke: (fingerprint, reason, note) => postJson('/api/revoke', { fingerprint, reason, note }),

  // 待批（列出/拒绝走 daemon RPC；批准需会话签名）
  pending: (td, nid) => getJson(`/api/pending?${netQS(td, nid)}`),
  approve: (applicant_pk, device_label) => postJson('/api/approve', { applicant_pk, device_label }),
  reject: (td, nid, applicant_pk) =>
    postJson('/api/reject', { trust_domain_id: td, network_local_id: nid, applicant_pk }),

  // 连通 / 诊断（均为 daemon RPC 透传，无 daemon → 502）
  node: () => getJson('/api/node'),
  peers: () => getJson('/api/peers'),
  routes: () => getJson('/api/routes'),
  stats: () => getJson('/api/stats'),
  aclStats: () => getJson('/api/acl-stats'),

  // 访问控制（D5）：ACL 编辑（daemon RPC，无需解锁）/ 分组（会话签名）/ 凭据（daemon RPC）
  config: () => getJson('/api/config'),
  aclSet: (acl) => postJson('/api/config/acl', acl),
  tags: (td, nid) => getJson(`/api/trust/tags?${netQS(td, nid)}`),
  tagSet: (fingerprint, tag, add) => postJson('/api/trust/tag', { fingerprint, tag, add }),
  credentials: () => getJson('/api/credentials'),
  credGenerate: (body) => postJson('/api/credentials/generate', body),
  credRevoke: (credential_id) => postJson('/api/credentials/revoke', { credential_id }),

  // 本机配置下发（D6）：均 daemon RPC 热重载，无需解锁，作用于控制器绑定实例
  cfgConnector: (body) => postJson('/api/config/connector', body),
  cfgMappedListener: (body) => postJson('/api/config/mapped-listener', body),
  cfgPortForward: (body) => postJson('/api/config/port-forward', body),
  cfgRoute: (body) => postJson('/api/config/route', body),
  cfgProxyNetwork: (body) => postJson('/api/config/proxy-network', body),
  cfgExitNode: (body) => postJson('/api/config/exit-node', body),
  cfgRelayServing: (body) => postJson('/api/config/relay-serving', body),
  cfgHostname: (hostname) => postJson('/api/config/hostname', { hostname }),
  cfgIpv4: (ipv4) => postJson('/api/config/ipv4', { ipv4 }),
  cfgWhitelist: (body) => postJson('/api/config/whitelist', body),

  // 高危治理（D6 危险区）
  createDomain: (label, passphrase) => postJson('/api/trust/create-domain', { label, passphrase }),
  createNetwork: (body) => postJson('/api/trust/create-network', body),
  upgradeRoot: (peer_id) => postJson('/api/trust/upgrade-peer-to-root', { peer_id }),
  armRootUpgrade: (passphrase, ttl_secs) =>
    postJson('/api/trust/arm-root-upgrade', { passphrase, ttl_secs }),
}
