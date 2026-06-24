// 把 proto 原始值（u32 IP / 微秒 / 字节 / i32 枚举 / unix 秒）格式化为人话。
// 仅 D4 连通/诊断两页共用；防御式取值，缺字段一律回退 '—'。

export function ipv4(inet) {
  const a = inet?.address?.addr
  if (a == null) return '—'
  const n = a >>> 0
  const s = `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`
  return inet.network_length != null ? `${s}/${inet.network_length}` : s
}

export function sockAddr(sa) {
  if (!sa) return '—'
  const ip = sa.ipv4 != null ? ipv4({ address: sa.ipv4 }) : sa.ipv6 ? '[v6]' : '—'
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
