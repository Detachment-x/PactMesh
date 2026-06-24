import { Fragment } from 'preact'
import { useState, useCallback } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, ErrorState, CopyId, Dot, Drawer, Toggle, useToast } from '../ui.jsx'
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

// 把 peers(my_info + conns) 与 routes 归一为「运行时条目」，按 hostname 建索引（唯一 join 键）。
function runtimeIndex(peers, routes) {
  const connByPeer = {}
  for (const p of peers?.peer_infos || []) connByPeer[p.peer_id] = p.conns
  const byHost = {}
  const entries = []
  const my = peers?.my_info
  if (my) {
    const e = {
      peer_id: my.peer_id, hostname: my.hostname || '', isSelf: true,
      overlayV4: my.ipv4_addr || '—', overlayV6: '—',
      ipList: my.ip_list, version: my.version, instId: my.inst_id,
      proxyCidrs: my.proxy_cidrs || [], nat: my.stun_info?.udp_nat_type,
      nextHop: my.peer_id, cost: 0, conns: [], sum: { online: true, self: true },
    }
    entries.push(e)
    if (e.hostname) byHost[e.hostname] = e
  }
  for (const r of routes?.routes || []) {
    const conns = connByPeer[r.peer_id]
    const e = {
      peer_id: r.peer_id, hostname: r.hostname || '', isSelf: false,
      overlayV4: ipv4(r.ipv4_addr), overlayV6: ipv6(r.ipv6_addr),
      ipList: null, version: r.version, instId: r.inst_id,
      proxyCidrs: r.proxy_cidrs || [], nat: r.stun_info?.udp_nat_type,
      nextHop: r.next_hop_peer_id, cost: r.cost, conns: conns || [], sum: connSummary(conns),
    }
    entries.push(e)
    if (e.hostname) byHost[e.hostname] = e
  }
  return { byHost, entries, my }
}

export function Devices() {
  const { network } = useApp()
  const td = network?.td
  const nid = network?.nid
  const [sel, setSel] = useState(null) // { kind:'member', id:device_id } | { kind:'temp', id:peer_id }

  const members = usePoll(
    useCallback(() => (td ? api.members(td, nid) : Promise.resolve([])), [td, nid]),
    [td, nid],
    8000,
  )
  const peers = usePoll(api.peers, [], 4000)
  const routes = usePoll(api.routes, [], 4000)

  if (!network) {
    return <EmptyState icon="◍" title="尚未选择网络" hint="在顶栏选择一个网络后查看其设备。" />
  }
  if (members.error) return <ErrorState error={members.error} onRetry={members.refresh} />

  const list = Array.isArray(members.data) ? members.data : []
  const runtimeDown = !!peers.error || !!routes.error
  const rt = runtimeIndex(runtimeDown ? null : peers.data, runtimeDown ? null : routes.data)
  const zone = dnsZone(rt.my?.config)

  // 名册行：每台成员按 hostname 左连运行时（无主机名/未上线 → rt=null）。
  const usedHosts = new Set()
  const memberRows = list.map((d) => {
    const r = d.hostname ? rt.byHost[d.hostname] : null
    if (r) usedHosts.add(d.hostname)
    return { dev: d, rt: r }
  })
  // 在线但不在名册（临时设备）：非本机、且 hostname 不匹配任何成员。
  const tempRows = rt.entries
    .filter((e) => !e.isSelf && (!e.hostname || !usedHosts.has(e.hostname)))
    .map((e) => ({ rt: e }))

  const hasRows = memberRows.length || tempRows.length
  const current =
    sel?.kind === 'member' ? memberRows.find((r) => r.dev.device_id === sel.id) :
    sel?.kind === 'temp' ? tempRows.find((r) => r.rt.peer_id === sel.id) : null

  const refreshAll = () => { members.refresh(); peers.refresh(); routes.refresh() }

  return (
    <>
      <div class="toolbar">
        <span class="muted">
          {members.loading ? '加载中…' : `${list.length} 台设备`}
          {!members.loading && tempRows.length > 0 && ` · ${tempRows.length} 台临时设备在线`}
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
                <th>状态</th>
                <th>主机名</th>
                <th>虚拟 IP</th>
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
                return (
                  <tr key={d.device_id}>
                    <td>
                      <div class="dev-name">
                        <span>{d.device_label || '未命名设备'}</span>
                        {isSelf && <span class="badge-role role-root">本机</span>}
                        {d.role === 'root' && <span class="badge-role role-root">主控</span>}
                        {chips.length > 0 && (
                          <span class="chips chips-inline">{chips.map((c) => <span key={c} class="chip">{c}</span>)}</span>
                        )}
                      </div>
                    </td>
                    <td><Dot kind={st.kind} label={st.label} /></td>
                    <td class="mono-cell">{d.hostname || <span class="muted" title="设主机名后可显示在线状态与虚拟 IP">—</span>}</td>
                    <td class="mono-cell">{r ? r.overlayV4 : <span class="muted">—</span>}</td>
                    <td>{connCell(r, d.hostname)}</td>
                    <td class="mono-cell">{r?.sum?.online && !r.isSelf ? latencyUs(r.sum.latencyUs) : r?.isSelf ? '本机' : '—'}</td>
                    <td class="ta-right">
                      <button class="btn btn-ghost btn-sm" onClick={() => setSel({ kind: 'member', id: d.device_id })}>管理</button>
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
          onClose={() => setSel(null)}
          onChanged={members.refresh}
        />
      )}
      {current && sel.kind === 'temp' && (
        <TempDrawer rt={current.rt} zone={zone} onClose={() => setSel(null)} />
      )}
    </>
  )
}

// 连接列：无主机名 → —（带提示）；有主机名未上线 → 离线；在线 → 直连/中继 + 隧道；本机 → 本机。
function connCell(r, hostname) {
  if (!r) {
    if (!hostname) return <span class="muted" title="设主机名后可显示在线/IP">—</span>
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
          <div class="form-row"><label class="field-label">网络域名</label><span class="mono">{rt.hostname}.{zone}</span></div>
        </section>
      )}
      <RuntimeSection rt={rt} />
      <div class="muted drawer-note">临时设备凭密钥接入、不在名册中，无法在此进行治理操作。</div>
    </Drawer>
  )
}

function DeviceDrawer({ device, rt, zone, onClose, onChanged }) {
  const { requireUnlock } = useApp()
  const toast = useToast()
  const fp = device.fingerprint
  const isRoot = device.role === 'root'

  const [label, setLabel] = useState(device.device_label || '')
  const [hostname, setHostname] = useState(device.hostname || '')
  const [relayData, setRelayData] = useState(!!device.capabilities.relay_data)
  const [relayControl, setRelayControl] = useState(!!device.capabilities.relay_control)
  const [cidrs, setCidrs] = useState(device.capabilities.proxy_subnets || [])
  const [newCidr, setNewCidr] = useState('')
  const [note, setNote] = useState('')
  const [reason, setReason] = useState('removed')
  const [confirmRevoke, setConfirmRevoke] = useState(false)
  const [busy, setBusy] = useState('')

  const act = async (tag, fn, okMsg, after) => {
    if (busy) return
    const ok = await requireUnlock()
    if (!ok) return
    setBusy(tag)
    try {
      await fn()
      toast.ok(okMsg)
      // reissue 会换 fingerprint：等列表刷新后 device prop 指向新证书，下个操作才用对 fp
      await onChanged?.()
      after?.()
    } catch (e) {
      toast.err(e.message)
    } finally {
      setBusy('')
    }
  }

  const addCidr = () => {
    const v = newCidr.trim()
    if (!v || cidrs.includes(v)) return
    setCidrs([...cidrs, v])
    setNewCidr('')
  }

  const saveCaps = () => {
    const body = { relay_data: relayData, relay_control: relayControl }
    const orig = device.capabilities.proxy_subnets || []
    if (cidrs.join(',') !== orig.join(',')) {
      if (cidrs.length === 0) body.clear_proxy_subnet = true
      else body.proxy_subnet = cidrs
    }
    return act('caps', () => api.capability(fp, body), '能力已更新')
  }

  const st = STATUS[device.status] || STATUS.active

  return (
    <Drawer
      title={device.device_label || '未命名设备'}
      subtitle={<><Dot kind={st.kind} label={st.label} /> · {(ROLE[device.role] || ROLE.member).label}{rt?.isSelf && ' · 本机'}</>}
      onClose={onClose}
      footer={<button class="btn" onClick={onClose}>关闭</button>}
    >
      {/* 标识 */}
      <section class="drawer-sec">
        <div class="sec-title">标识</div>
        <div class="form-row">
          <label class="field-label">设备名</label>
          <div class="inline-field">
            <input class="field" value={label} onInput={(e) => setLabel(e.currentTarget.value)} placeholder="如：办公笔记本" />
            <button
              class="btn btn-primary btn-sm"
              disabled={busy === 'name' || !label.trim() || label === device.device_label}
              onClick={() => act('name', () => api.rename(fp, label.trim(), note || undefined), '已重命名')}
            >保存</button>
          </div>
        </div>
        <div class="form-row">
          <label class="field-label">主机名<small>（留空清除）</small></label>
          <div class="inline-field">
            <input class="field mono" value={hostname} onInput={(e) => setHostname(e.currentTarget.value)} placeholder="laptop-01" />
            <button
              class="btn btn-primary btn-sm"
              disabled={busy === 'host' || hostname === (device.hostname || '')}
              onClick={() => act('host', () => api.hostname(fp, hostname.trim() || undefined, note || undefined), hostname.trim() ? '主机名已更新' : '主机名已清除')}
            >保存</button>
          </div>
        </div>
        {zone && device.hostname && (
          <div class="form-row">
            <label class="field-label">网络域名<small>（MagicDNS）</small></label>
            <span class="mono">{device.hostname}.{zone}</span>
          </div>
        )}
      </section>

      {/* 运行时（在线时并入连通信息） */}
      {rt && <RuntimeSection rt={rt} />}

      {/* 能力 */}
      <section class="drawer-sec">
        <div class="sec-title">能力</div>
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
        <button class="btn btn-primary btn-sm" disabled={busy === 'caps'} onClick={saveCaps}>
          {busy === 'caps' ? '保存中…' : '保存能力'}
        </button>
      </section>

      {/* 备注（应用于本次签名操作的审计说明） */}
      <section class="drawer-sec">
        <div class="sec-title">操作备注<small>（可选，记入证书审计）</small></div>
        <input class="field" value={note} placeholder="变更原因…" onInput={(e) => setNote(e.currentTarget.value)} />
      </section>

      {/* 状态 / 危险区 */}
      {!isRoot && (
        <section class="drawer-sec danger-sec">
          <div class="sec-title">状态</div>
          {device.status === 'disabled' ? (
            <button class="btn btn-sm" disabled={busy === 'enable'} onClick={() => act('enable', () => api.enable(fp), '已启用')}>
              启用设备
            </button>
          ) : device.status === 'active' ? (
            <button class="btn btn-warn btn-sm" disabled={busy === 'disable'} onClick={() => act('disable', () => api.disable(fp, note || undefined), '已禁用')}>
              禁用设备
            </button>
          ) : (
            <span class="muted">当前状态不可切换</span>
          )}

          {device.status !== 'revoked' && (
            <div class="revoke-box">
              <div class="sec-title">吊销（不可恢复）</div>
              <div class="form-row">
                <label class="field-label">原因</label>
                <select class="field" value={reason} onChange={(e) => setReason(e.currentTarget.value)}>
                  {REASONS.map((r) => <option key={r.v} value={r.v}>{r.t}</option>)}
                </select>
              </div>
              <label class="check-row">
                <input type="checkbox" checked={confirmRevoke} onChange={(e) => setConfirmRevoke(e.currentTarget.checked)} />
                <span>我确认永久吊销「{device.device_label || '该设备'}」，吊销后无法恢复。</span>
              </label>
              <button
                class="btn btn-danger btn-sm"
                disabled={!confirmRevoke || busy === 'revoke'}
                onClick={() => act('revoke', () => api.revoke(fp, reason, note || undefined), '设备已吊销', onClose)}
              >
                {busy === 'revoke' ? '吊销中…' : '吊销设备'}
              </button>
            </div>
          )}
        </section>
      )}
      {isRoot && <div class="muted drawer-note">主控设备不可在此禁用或吊销。</div>}

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
