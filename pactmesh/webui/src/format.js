// 把 proto 原始值（u32 IP / 微秒 / 字节 / i32 枚举 / unix 秒）格式化为人话。
// 仅 D4 连通/诊断两页共用；防御式取值，缺字段一律回退 '—'。

export function ipv4(inet) {
  const a = inet?.address?.addr
  if (a == null) return '—'
  const n = a >>> 0
  const s = `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`
  return inet.network_length != null ? `${s}/${inet.network_length}` : s
}

// common.Ipv4Addr = { addr: u32 }（裸地址，无掩码）— 用于 ip_list。
export function ipv4Addr(a) {
  const n = a?.addr
  if (n == null) return null
  const u = n >>> 0
  return `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`
}

// common.Ipv6Addr = { part1..part4: u32 }（每段 2 个 hextet）→ 标准 :: 压缩。
export function ipv6Addr(a) {
  if (!a) return null
  const parts = [a.part1, a.part2, a.part3, a.part4]
  if (parts.every((p) => p == null)) return null
  const h = []
  for (const p of parts) {
    const n = (p ?? 0) >>> 0
    h.push((n >>> 16) & 0xffff, n & 0xffff)
  }
  let best = -1, bestLen = 0, cur = -1, curLen = 0
  for (let i = 0; i < 8; i++) {
    if (h[i] === 0) {
      if (cur < 0) cur = i
      curLen++
      if (curLen > bestLen) { bestLen = curLen; best = cur }
    } else { cur = -1; curLen = 0 }
  }
  const seg = h.map((x) => x.toString(16))
  if (bestLen < 2) return seg.join(':')
  return `${seg.slice(0, best).join(':')}::${seg.slice(best + bestLen).join(':')}`
}

// common.Ipv6Inet = { address: Ipv6Addr, network_length }（Route.ipv6_addr）。
export function ipv6(inet) {
  const s = ipv6Addr(inet?.address)
  if (!s) return '—'
  return inet.network_length != null ? `${s}/${inet.network_length}` : s
}

// GetIpListResponse → 结构化物理地址（仅本机 my_info/node 有）。
export function ipList(il) {
  if (!il) return null
  const v4 = []
  const p4 = ipv4Addr(il.public_ipv4)
  if (p4) v4.push({ ip: p4, pub: true })
  for (const a of il.interface_ipv4s || []) { const s = ipv4Addr(a); if (s) v4.push({ ip: s }) }
  const v6 = []
  const p6 = ipv6Addr(il.public_ipv6)
  if (p6) v6.push({ ip: p6, pub: true })
  for (const a of il.interface_ipv6s || []) { const s = ipv6Addr(a); if (s) v6.push({ ip: s }) }
  const listeners = (il.listeners || []).map((u) => u?.url).filter(Boolean)
  if (!v4.length && !v6.length && !listeners.length) return null
  return { v4, v6, listeners }
}

// MagicDNS 网络域：从 NodeInfo.config（TOML 串）提取 tld_dns_zone（网络级常量，只读）。
export function dnsZone(configStr) {
  if (!configStr || typeof configStr !== 'string') return null
  const m = configStr.match(/tld_dns_zone\s*=\s*"([^"]*)"/)
  return (m && m[1].trim()) || null
}

export function sockAddr(sa) {
  if (!sa) return '—'
  const ip = sa.ipv4 != null ? ipv4({ address: sa.ipv4 }) : sa.ipv6 ? ipv6Addr(sa.ipv6) || '—' : '—'
  return sa.port ? `${ip}:${sa.port}` : ip
}

export function bytes(v) {
  let n = Number(v) || 0
  if (n < 1024) return `${n} B`
  const u = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  do {
    n /= 1024
    i++
  } while (n >= 1024 && i < u.length - 1)
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${u[i]}`
}

export function latencyUs(us) {
  if (us == null) return '—'
  const ms = us / 1000
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`
}

export function latencyMs(ms) {
  if (ms == null) return '—'
  return ms < 10 ? `${(+ms).toFixed(1)} ms` : `${Math.round(ms)} ms`
}

export function ago(unixSecs) {
  if (!unixSecs) return '—'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSecs))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

export const PROTOCOL = { 0: '任意', 1: 'TCP', 2: 'UDP', 3: 'ICMP', 4: 'ICMPv6', 5: '任意' }
export const CONN_STATE = {
  0: { t: '新建', kind: 'info' },
  1: { t: '已建立', kind: 'ok' },
  2: { t: '关联', kind: 'info' },
  3: { t: '无效', kind: 'err' },
}
export const ACL_ACTION = { 0: '空操作', 1: '放行', 2: '丢弃' }
export const CHAIN_TYPE = { 0: '未指定', 1: '入站', 2: '出站', 3: '转发' }

// ACL 编辑器下拉项（人话标签 → i32 枚举值）。
export const PROTO_OPTS = [[5, '任意'], [1, 'TCP'], [2, 'UDP'], [3, 'ICMP'], [4, 'ICMPv6']]
export const ACTION_OPTS = [[1, '放行'], [2, '丢弃'], [0, '空操作']]
export const CHAINTYPE_OPTS = [[1, '入站'], [2, '出站'], [3, '转发']]
export const IDENTITY = { 0: '主控', 1: '临时设备', 2: '共享节点' }
export const NAT_TYPE = {
  0: '未知',
  1: '开放网络',
  2: '无端口转换',
  3: '全锥型',
  4: '受限锥型',
  5: '端口受限',
  6: '对称型',
  7: '对称防火墙',
  8: '对称(易增)',
  9: '对称(易减)',
}
