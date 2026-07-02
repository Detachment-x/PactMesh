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
  // 主控指派固定虚拟 IP（network_state.ip_assignments，不重签证书）；ipv4 省略/空 = 清除回 DHCP
  assignedIpv4: (fingerprint, ipv4) => postJson('/api/assigned-ipv4', { fingerprint, ipv4: ipv4 || null }),

  // 待批（列出/拒绝走 daemon RPC；批准需会话签名）
  pending: (td, nid) => getJson(`/api/pending?${netQS(td, nid)}`),
  approve: (applicant_pk, device_label) => postJson('/api/approve', { applicant_pk, device_label }),
  reject: (td, nid, applicant_pk) =>
    postJson('/api/reject', { trust_domain_id: td, network_local_id: nid, applicant_pk }),

  // 已挂载实例（空载 daemon → {inst_ids:[]} 200；daemon 不可达 → 502）
  instances: () => getJson('/api/instances'),
  // 一站式建网+运行时加网：建域(可选)→建网→自举→封存口令→对运行中空载 daemon 挂实例，不重启
  networkRun: (body) => postJson('/api/network/run', body),

  // 网络级 IP 池（控制器元数据 controller_meta.json，非签名态）：读/写网段 + 自动分配开关
  ipPool: (td, nid) => getJson(`/api/network/ip-pool?${netQS(td, nid)}`),
  ipPoolSet: (body) => postJson('/api/network/ip-pool', body),
  // 从池自动为某设备选一个空闲 IP 并指派（走 assigned-ipv4 签名路径，需会话）
  autoAssign: (fingerprint) => postJson('/api/network/auto-assign', { fingerprint }),
  // 成员离开网络：停本机实例（DeleteNetworkInstance）+ 可选清本机封存口令；本机 daemon 操作，不需签名
  leave: (td, nid) => postJson('/api/network/leave', { trust_domain_id: td, network_local_id: nid }),

  // 经邀请加入既有网络（异步：预览→提交(非阻塞)→轮询状态，批准后服务端自动挂载）
  invitePreview: (invite_url) => postJson('/api/network/invite-preview', { invite_url }),
  join: (body) => postJson('/api/network/join', body),
  joinStatus: () => getJson('/api/network/join-status'),

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
