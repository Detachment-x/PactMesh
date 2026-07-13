import { Fragment } from 'preact'
import { useState, useCallback } from 'preact/hooks'
import { api } from '../api.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, ErrorState, CopyId, Dot, Drawer, Toggle, Modal, InlineEdit, useToast } from '../ui.jsx'
import { ipv4, ipv6, bytes, latencyUs, ipList as fmtIpList, dnsZone, NAT_TYPE, IDENTITY } from '../format.js'

const ROLE = {
  root: { label: '主控', cls: 'role-root' },
  member: { label: '设备', cls: 'role-member' },
  external: { label: '外部', cls: 'role-ext' },
}
const STATUS = {
  active: { label: '正常', kind: 'ok' },
  disabled: { label: '已禁用', kind: 'warn' },
  revoked: { label: '已吊销', kind: 'err' },
  expired: { label: '已过期', kind: 'muted' },
}
const REASONS = [
  { v: 'unspecified', t: '未指定' },
  { v: 'removed', t: '移除设备' },
  { v: 'device-lost', t: '设备遗失' },
  { v: 'key-compromise', t: '密钥泄露' },
  { v: 'superseded', t: '证书更替' },
]

function capChips(c) {
  const out = []
  if (c.relay_data) out.push('中继数据')
  if (c.relay_control) out.push('中继控制')
  if (c.proxy_subnets?.length) out.push(`代理 ${c.proxy_subnets.length} 段`)
  return out
}

// 从一个节点的连接集合提炼摘要：是否在线、隧道类型、最佳延迟、丢包、是否临时设备。
function connSummary(conns) {
  const live = (conns || []).filter((c) => !c.is_closed)
  if (!live.length) return { online: false }
  const best = live.reduce((a, b) => ((a.stats?.latency_us ?? 9e9) <= (b.stats?.latency_us ?? 9e9) ? a : b))
  return {
    online: true,
    tunnel: best.tunnel?.tunnel_type || '—',
    latencyUs: best.stats?.latency_us,
    loss: Math.max(...live.map((c) => c.loss_rate || 0)),
    credential: live.some((c) => c.peer_identity_type === 1),
    count: live.length,
  }
}

// 把 peers(my_info + conns) 与 routes 归一为「运行时条目」，同时按指纹与 hostname 建索引。
// 指纹是唯一可靠的 join 键（hostname 可重名、可改名，会把同一台设备拆成成员行 + 临时设备行两条）。
// 本机运行时优先取 peers.my_info；孤立节点（无对端）时 daemon 返回 my_info=null，回退到 /api/node 的 node_info。
function runtimeIndex(peers, routes, peerIds, selfNode) {
  const connByPeer = {}
  for (const p of peers?.peer_infos || []) connByPeer[p.peer_id] = p.conns
  const fpByPeer = {}
  for (const p of peerIds || []) if (p.fingerprint) fpByPeer[p.peer_id] = p.fingerprint

  const byHost = {}
  const byFp = {}
  const entries = []
  const add = (e) => {
    entries.push(e)
    if (e.hostname) byHost[e.hostname] = e
    if (e.fingerprint) byFp[e.fingerprint] = e
  }

  const my = peers?.my_info || selfNode || null
  if (my) {
    add({
      peer_id: my.peer_id, hostname: my.hostname || '', fingerprint: fpByPeer[my.peer_id] || '', isSelf: true,
      overlayV4: my.ipv4_addr || '—', overlayV6: '—',
      ipList: my.ip_list, version: my.version, instId: my.inst_id,
      proxyCidrs: my.proxy_cidrs || [], nat: my.stun_info?.udp_nat_type,
      nextHop: my.peer_id, cost: 0, conns: [], sum: { online: true, self: true },
    })
  }
  for (const r of routes?.routes || []) {
    const conns = connByPeer[r.peer_id]
    add({
      peer_id: r.peer_id, hostname: r.hostname || '', fingerprint: fpByPeer[r.peer_id] || '', isSelf: false,
      overlayV4: ipv4(r.ipv4_addr), overlayV6: ipv6(r.ipv6_addr),
      ipList: null, version: r.version, instId: r.inst_id,
      proxyCidrs: r.proxy_cidrs || [], nat: r.stun_info?.udp_nat_type,
      nextHop: r.next_hop_peer_id, cost: r.cost, conns: conns || [], sum: connSummary(conns),
    })
  }
  return { byHost, byFp, entries, my }
}

// 指派/虚拟 IP 单元格显示：已指派 → 绿色 chip；否则运行时自分配地址（灰）或「自分配」。
function ipCellDisplay(assigned, r) {
  if (assigned) return <span class="chip chip-ok"><code>{assigned}</code></span>
  if (r && r.overlayV4 && r.overlayV4 !== '—') return <span class="mono muted" title="动态 IP（节点自行获取）">{r.overlayV4}</span>
  return <span class="muted">动态</span>
}

// 网络中心页内嵌的治理名册：轮询与地址池由父页 `network.jsx` 统一持有并下传，
// 避免双重轮询。onAutoAssign(fp) 走地址池签名分配；pool 提供「是否已设池」判断。
export function DeviceRoster({ members, peers, routes, peerIds, node, pool, onAutoAssign }) {
  const { network, requireUnlock } = useApp()
  const toast = useToast()
  const isRoot = !!network?.isRoot
  const [sel, setSel] = useState(null) // { kind:'member', id:device_id } | { kind:'temp', id:peer_id }
  const [revoking, setRevoking] = useState(null) // 待吊销设备
  const poolReady = !!pool?.data?.ip_pool_cidr

  // 单项治理提交：JIT 解锁 → 调用 → 刷新。返回 true/false（false=未解锁/失败，供 InlineEdit 保持编辑）。
  const gov = useCallback(async (fn, okMsg) => {
    const ok = await requireUnlock()
    if (!ok) return false
    try {
      await fn()
      toast.ok(okMsg)
      await members.refresh()
      return true
    } catch (e) {
      toast.err(e.message)
      return false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requireUnlock])

  if (!network) {
    return <EmptyState icon="◍" title="尚未选择网络" hint="在顶栏选择一个网络后查看其设备。" />
  }
  if (members.error) return <ErrorState error={members.error} onRetry={members.refresh} />

  const list = Array.isArray(members.data) ? members.data : []
  const runtimeDown = !!peers.error && !!routes.error && !!node.error
  const rt = runtimeIndex(
    runtimeDown ? null : peers.data,
    runtimeDown ? null : routes.data,
    runtimeDown ? null : peerIds?.data,
    runtimeDown ? null : node.data?.node_info,
  )
  const zone = dnsZone(rt.my?.config)

  // 名册行：每台成员先按指纹左连运行时，指纹缺失才回退 hostname（未上线 → rt=null）。
  const usedPeers = new Set()
  const memberRows = list.map((d) => {
    const r = (d.fingerprint && rt.byFp[d.fingerprint]) || (d.hostname && rt.byHost[d.hostname]) || null
    if (r) usedPeers.add(r.peer_id)
    return { dev: d, rt: r }
  })
  // 在线但不在名册（临时设备）：非本机、且未被任何成员行认领。
  const tempRows = rt.entries
    .filter((e) => !e.isSelf && !usedPeers.has(e.peer_id))
    .map((e) => ({ rt: e }))

  const hasRows = memberRows.length || tempRows.length
  const current =
    sel?.kind === 'member' ? memberRows.find((r) => r.dev.device_id === sel.id) :
    sel?.kind === 'temp' ? tempRows.find((r) => r.rt.peer_id === sel.id) : null

  const refreshAll = () => { members.refresh(); peers.refresh(); routes.refresh(); peerIds?.refresh(); node.refresh() }

  return (
    <>
      <div class="toolbar">
        <span class="muted">
          {members.loading ? '加载中…' : `${list.length} 台设备`}
          {!members.loading && tempRows.length > 0 && ` · ${tempRows.length} 台临时设备在线`}
          {!isRoot && ' · 成员视图（只读）'}
          {runtimeDown && ' · daemon 未连接，运行时信息不可用'}
        </span>
        <button class="btn btn-ghost" onClick={refreshAll}>刷新</button>
      </div>

      {members.loading && !list.length ? (
        <Skeleton rows={4} />
      ) : !hasRows ? (
        <EmptyState
          icon="✦"
          title="还没有设备"
          hint="在「概览」点击「邀请设备」生成邀请，对方接受后到「待批」审批即可加入。"
        />
      ) : (
        <div class="table-wrap">
          <table class="dtable">
            <thead>
              <tr>
                <th>设备</th>
                <th>{isRoot ? '启用' : '状态'}</th>
                <th>hostname</th>
                <th>指派 / 虚拟 IP</th>
                <th>连接</th>
                <th>延迟</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {memberRows.map(({ dev: d, rt: r }) => {
                const st = STATUS[d.status] || STATUS.active
                const chips = capChips(d.capabilities)
                const isSelf = !!r?.isSelf
                const fp = d.fingerprint
                const canGov = isRoot && d.role !== 'root'
                return (
                  <tr key={d.device_id}>
                    <td>
                      <div class="dev-name">
                        {isRoot ? (
                          <InlineEdit
                            value={d.device_label || ''}
                            placeholder="未命名设备"
                            onCommit={(v) => (v ? gov(() => api.rename(fp, v), '已重命名') : false)}
                          />
                        ) : (
                          <span>{d.device_label || '未命名设备'}</span>
                        )}
                        {isSelf && <span class="badge-role role-root">本机</span>}
                        {d.role === 'root' && <span class="badge-role role-root">主控</span>}
                        {chips.length > 0 && (
                          <span class="chips chips-inline">{chips.map((c) => <span key={c} class="chip">{c}</span>)}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      {canGov && (d.status === 'active' || d.status === 'disabled') ? (
                        <Toggle
                          checked={d.status === 'active'}
                          onChange={(next) => gov(next ? () => api.enable(fp) : () => api.disable(fp), next ? '已启用' : '已禁用')}
                        />
                      ) : (
                        <Dot kind={st.kind} label={st.label} />
                      )}
                    </td>
                    <td class="mono-cell">
                      {isRoot ? (
                        <InlineEdit
                          value={d.hostname || ''}
                          mono
                          title={d.hostname ? '点击编辑（留空清除）' : '点击设置 hostname'}
                          onCommit={(v) => gov(() => api.hostname(fp, v || undefined), v ? 'hostname 已更新' : 'hostname 已清除')}
                          render={(v) => v ? <span class="mono">{v}</span> : <span class="muted" title="设 hostname 后可显示在线状态与虚拟 IP">—</span>}
                        />
                      ) : (d.hostname || <span class="muted">—</span>)}
                    </td>
                    <td class="mono-cell">
                      {isRoot ? (
                        <span class="ip-cell">
                          <InlineEdit
                            value={d.assigned_ipv4 || ''}
                            placeholder="10.10.0.2/24"
                            mono
                            title={d.assigned_ipv4 ? '点击改派（留空清除回退动态 IP）' : '点击指派固定 IP'}
                            onCommit={(v) => gov(() => api.assignedIpv4(fp, v || null), v ? '已指派 IP' : '已清除指派')}
                            render={(v) => ipCellDisplay(v, r)}
                          />
                          {!d.assigned_ipv4 && poolReady && canGov && (
                            <button class="btn btn-ghost btn-sm" title="从地址池分配一个空闲 IP" onClick={() => onAutoAssign?.(fp)}>自动分配</button>
                          )}
                        </span>
                      ) : ipCellDisplay(d.assigned_ipv4, r)}
                    </td>
                    <td>{connCell(r, d.hostname)}</td>
                    <td class="mono-cell">{r?.sum?.online && !r.isSelf ? latencyUs(r.sum.latencyUs) : r?.isSelf ? '本机' : '—'}</td>
                    <td class="ta-right">
                      <div class="row-ops">
                        <button class="btn btn-ghost btn-sm" onClick={() => setSel({ kind: 'member', id: d.device_id })}>
                          {isRoot ? '管理' : '详情'}
                        </button>
                        {canGov && d.status !== 'revoked' && (
                          <button class="icon-btn danger" title="吊销设备" onClick={() => setRevoking(d)}>🗑</button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
              {tempRows.map(({ rt: r }) => (
                <tr key={'t' + r.peer_id} class="row-temp">
                  <td>
                    <div class="dev-name">
                      <span>{r.hostname || <span class="muted">节点 {r.peer_id}</span>}</span>
                      <span class="badge-role role-cred">临时设备</span>
                    </div>
                  </td>
                  <td><Dot kind={r.sum.online ? 'ok' : 'muted'} label={r.sum.online ? '在线' : '离线'} /></td>
                  <td class="mono-cell">{r.hostname || <span class="muted">—</span>}</td>
                  <td class="mono-cell">{r.overlayV4}</td>
                  <td>{connCell(r, r.hostname)}</td>
                  <td class="mono-cell">{r.sum.online ? latencyUs(r.sum.latencyUs) : '—'}</td>
                  <td class="ta-right">
                    <button class="btn btn-ghost btn-sm" onClick={() => setSel({ kind: 'temp', id: r.peer_id })}>详情</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {current && sel.kind === 'member' && (
        <DeviceDrawer
          key={current.dev.device_id}
          device={current.dev}
          rt={current.rt}
          zone={zone}
          canEdit={isRoot}
          onClose={() => setSel(null)}
          onChanged={members.refresh}
        />
      )}
      {current && sel.kind === 'temp' && (
        <TempDrawer rt={current.rt} zone={zone} onClose={() => setSel(null)} />
      )}
      {revoking && (
        <RevokeDialog
          device={revoking}
          onCancel={() => setRevoking(null)}
          onConfirm={async (reason, note) => {
            const ok = await gov(() => api.revoke(revoking.fingerprint, reason, note), '设备已吊销')
            if (ok) setRevoking(null)
            return ok
          }}
        />
      )}
    </>
  )
}

// 吊销确认对话框（不可逆，需二次确认 + 原因）。
function RevokeDialog({ device, onCancel, onConfirm }) {
  const [reason, setReason] = useState('removed')
  const [note, setNote] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const go = async () => {
    if (!confirm || busy) return
    setBusy(true)
    const ok = await onConfirm(reason, note || undefined)
    if (!ok) setBusy(false)
  }
  return (
    <Modal
      title={`吊销「${device.device_label || '设备'}」`}
      onClose={onCancel}
      footer={
        <>
          <button class="btn" onClick={onCancel}>取消</button>
          <button class="btn btn-danger" disabled={!confirm || busy} onClick={go}>
            {busy ? '吊销中…' : '吊销设备'}
          </button>
        </>
      }
    >
      <p class="modal-note">吊销不可恢复：该设备证书将被永久作废、立即失去网络访问。</p>
      <div class="form-row">
        <label class="field-label">原因</label>
        <select class="field" value={reason} onChange={(e) => setReason(e.currentTarget.value)}>
          {REASONS.map((r) => <option key={r.v} value={r.v}>{r.t}</option>)}
        </select>
      </div>
      <div class="form-row">
        <label class="field-label">备注<small>（可选，记入证书审计）</small></label>
        <input class="field" value={note} placeholder="吊销原因…" onInput={(e) => setNote(e.currentTarget.value)} />
      </div>
      <label class="check-row">
        <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.currentTarget.checked)} />
        <span>我确认永久吊销此设备，吊销后无法恢复。</span>
      </label>
    </Modal>
  )
}

// 连接列：无主机名 → —（带提示）；有主机名未上线 → 离线；在线 → 直连/中继 + 隧道；本机 → 本机。
function connCell(r, hostname) {
  if (!r) {
    if (!hostname) return <span class="muted" title="设 hostname 后可显示在线/IP">—</span>
    return <Dot kind="muted" label="离线" />
  }
  if (r.isSelf) return <span class="chip chip-ok">本机</span>
  if (!r.sum.online) {
    const direct = r.nextHop === r.peer_id
    return <span class={'chip ' + (direct ? 'chip-ok' : 'chip-warn')}>{direct ? '直连·离线' : '中继·离线'}</span>
  }
  const direct = r.nextHop === r.peer_id
  return (
    <span class="chips">
      <span class={'chip ' + (direct ? 'chip-ok' : 'chip-warn')}>{direct ? '直连' : '中继'}</span>
      <span class="chip">{r.sum.tunnel}</span>
    </span>
  )
}

// 运行时区块（设备抽屉与临时设备抽屉共用）：虚拟 IP / 下一跳 / NAT / 物理 IP / 逐连接。
function RuntimeSection({ rt }) {
  const live = (rt.conns || []).filter((c) => !c.is_closed)
  const il = rt.isSelf ? fmtIpList(rt.ipList) : null
  return (
    <section class="drawer-sec">
      <div class="sec-title">运行时{rt.isSelf && <small>（本机）</small>}</div>
      <dl class="kv">
        <dt>虚拟 IPv4</dt><dd class="mono">{rt.overlayV4 || '—'}</dd>
        {rt.overlayV6 && rt.overlayV6 !== '—' && (<Fragment><dt>虚拟 IPv6</dt><dd class="mono">{rt.overlayV6}</dd></Fragment>)}
        {!rt.isSelf && (<Fragment><dt>下一跳</dt><dd class="mono">{rt.nextHop === rt.peer_id ? '直连' : `经节点 ${rt.nextHop}`}</dd></Fragment>)}
        {!rt.isSelf && rt.cost != null && (<Fragment><dt>路径成本</dt><dd class="mono">{rt.cost}</dd></Fragment>)}
        <dt>NAT 类型</dt><dd>{rt.nat != null ? NAT_TYPE[rt.nat] || rt.nat : '—'}</dd>
        <dt>版本</dt><dd>{rt.version || '—'}</dd>
        {rt.instId && (<Fragment><dt>实例 ID</dt><dd><CopyId value={rt.instId} chars={14} /></dd></Fragment>)}
      </dl>
      {rt.proxyCidrs?.length > 0 && (
        <div class="form-row">
          <label class="field-label">代理网段</label>
          <div class="chips">{rt.proxyCidrs.map((c) => <span key={c} class="chip"><code>{c}</code></span>)}</div>
        </div>
      )}
      {il && (
        <div class="form-row">
          <label class="field-label">物理 IP</label>
          <dl class="kv">
            {il.v4.map((x, i) => <Fragment key={'4' + i}><dt>{x.pub ? '公网 IPv4' : '本地 IPv4'}</dt><dd class="mono">{x.ip}</dd></Fragment>)}
            {il.v6.map((x, i) => <Fragment key={'6' + i}><dt>{x.pub ? '公网 IPv6' : '本地 IPv6'}</dt><dd class="mono">{x.ip}</dd></Fragment>)}
            {il.listeners.length > 0 && (<Fragment><dt>监听</dt><dd class="mono">{il.listeners.join('  ')}</dd></Fragment>)}
          </dl>
        </div>
      )}
      {!rt.isSelf && (
        <div class="form-row">
          <label class="field-label">物理连接 <small>（{live.length} 条活跃）</small></label>
          {!live.length ? (
            <span class="muted">无活跃连接</span>
          ) : (
            live.map((c) => (
              <div key={c.conn_id} class="conn-card">
                <div class="conn-head">
                  <span class="chip">{c.tunnel?.tunnel_type || '—'}</span>
                  <span class="badge-role role-cred-soft">{IDENTITY[c.peer_identity_type] ?? '?'}</span>
                  <span class="conn-lat mono">{latencyUs(c.stats?.latency_us)}</span>
                </div>
                <div class="conn-meta muted">
                  ↓ {bytes(c.stats?.rx_bytes)} · ↑ {bytes(c.stats?.tx_bytes)} · 丢包 {((c.loss_rate || 0) * 100).toFixed(0)}%
                </div>
                {c.tunnel?.remote_addr?.url && <div class="conn-addr mono muted">{c.tunnel.remote_addr.url}</div>}
              </div>
            ))
          )}
        </div>
      )}
    </section>
  )
}

function TempDrawer({ rt, zone, onClose }) {
  return (
    <Drawer
      title={rt.hostname || `节点 ${rt.peer_id}`}
      subtitle={<><span class="badge-role role-cred">临时设备</span> · 节点 {rt.peer_id}</>}
      onClose={onClose}
      footer={<button class="btn" onClick={onClose}>关闭</button>}
    >
      {zone && rt.hostname && (
        <section class="drawer-sec">
          <div class="form-row"><label class="field-label">网络域名</label><div class="mono">{rt.hostname}.{zone}</div></div>
        </section>
      )}
      <RuntimeSection rt={rt} />
      <div class="muted drawer-note">临时设备凭密钥接入、不在名册中，无法在此进行治理操作。</div>
    </Drawer>
  )
}

// 设备详情/管理抽屉：常用编辑（名/主机名/启用/指派IP/吊销）已内联到表格；
// 此处承载复合项 —— 运行时详情、能力（开关 + 代理网段）、指纹审计。canEdit=false（成员）时降级只读。
function DeviceDrawer({ device, rt, zone, canEdit, onClose, onChanged }) {
  const { requireUnlock } = useApp()
  const toast = useToast()
  const fp = device.fingerprint
  const caps = device.capabilities

  const [relayData, setRelayData] = useState(!!caps.relay_data)
  const [relayControl, setRelayControl] = useState(!!caps.relay_control)
  const [cidrs, setCidrs] = useState(caps.proxy_subnets || [])
  const [newCidr, setNewCidr] = useState('')
  const [busy, setBusy] = useState(false)

  const addCidr = () => {
    const v = newCidr.trim()
    if (!v || cidrs.includes(v)) return
    setCidrs([...cidrs, v])
    setNewCidr('')
  }

  const saveCaps = async () => {
    if (busy) return
    const ok = await requireUnlock()
    if (!ok) return
    const body = { relay_data: relayData, relay_control: relayControl }
    const orig = caps.proxy_subnets || []
    if (cidrs.join(',') !== orig.join(',')) {
      if (cidrs.length === 0) body.clear_proxy_subnet = true
      else body.proxy_subnet = cidrs
    }
    setBusy(true)
    try {
      await api.capability(fp, body)
      toast.ok('能力已更新，实时生效')
      await onChanged?.() // 能力写入签名网络状态，证书指纹不变、设备不掉线；刷新以取最新 effective 视图
    } catch (e) {
      toast.err(e.message)
    } finally {
      setBusy(false)
    }
  }

  const st = STATUS[device.status] || STATUS.active

  return (
    <Drawer
      title={device.device_label || '未命名设备'}
      subtitle={<><Dot kind={st.kind} label={st.label} /> · {(ROLE[device.role] || ROLE.member).label}{rt?.isSelf && ' · 本机'}</>}
      onClose={onClose}
      footer={<button class="btn" onClick={onClose}>关闭</button>}
    >
      {zone && device.hostname && (
        <section class="drawer-sec">
          <div class="form-row">
            <label class="field-label">网络域名<small>（MagicDNS）</small></label>
            <div class="mono">{device.hostname}.{zone}</div>
          </div>
        </section>
      )}

      {/* 运行时（在线时并入连通信息） */}
      {rt && <RuntimeSection rt={rt} />}

      {/* 能力 */}
      <section class="drawer-sec">
        <div class="sec-title">能力</div>
        {canEdit ? (
          <>
            <Toggle label="中继数据" hint="允许为他人转发数据流量" checked={relayData} onChange={setRelayData} />
            <Toggle label="中继控制" hint="允许参与控制面中继" checked={relayControl} onChange={setRelayControl} />
            <div class="form-row">
              <label class="field-label">代理网段<small>（CIDR，可访问的子网）</small></label>
              {cidrs.length > 0 && (
                <div class="chips editable">
                  {cidrs.map((c) => (
                    <span key={c} class="chip">
                      <code>{c}</code>
                      <button class="chip-x" onClick={() => setCidrs(cidrs.filter((x) => x !== c))}>✕</button>
                    </span>
                  ))}
                </div>
              )}
              <div class="inline-field">
                <input
                  class="field mono"
                  value={newCidr}
                  placeholder="10.0.0.0/24"
                  onInput={(e) => setNewCidr(e.currentTarget.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addCidr())}
                />
                <button class="btn btn-sm" onClick={addCidr}>添加</button>
              </div>
            </div>
            <p class="muted cap-hint">保存后立即生效：设备无需重新入网，也不会掉线。</p>
            <button class="btn btn-primary btn-sm" disabled={busy} onClick={saveCaps}>
              {busy ? '保存中…' : '保存能力'}
            </button>
          </>
        ) : (
          <>
            <dl class="kv">
              <dt>中继数据</dt><dd>{caps.relay_data ? '允许' : '否'}</dd>
              <dt>中继控制</dt><dd>{caps.relay_control ? '允许' : '否'}</dd>
            </dl>
            {caps.proxy_subnets?.length > 0 && (
              <div class="form-row">
                <label class="field-label">代理网段</label>
                <div class="chips">{caps.proxy_subnets.map((c) => <span key={c} class="chip"><code>{c}</code></span>)}</div>
              </div>
            )}
          </>
        )}
      </section>

      {/* 高级 / 审计（内部标识，默认折叠） */}
      <section class="drawer-sec">
        <details class="adv-fold">
          <summary>高级 / 审计</summary>
          <div class="form-row"><label class="field-label">证书指纹</label><CopyId value={fp} chars={20} /></div>
          <div class="form-row"><label class="field-label">设备 ID</label><CopyId value={device.device_id} chars={20} /></div>
        </details>
      </section>
    </Drawer>
  )
}
