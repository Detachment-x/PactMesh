import { useState, useCallback } from 'preact/hooks'
import { getJson } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, CopyId, Dot } from '../ui.jsx'
import { ipList as fmtIpList } from '../format.js'
import { InviteModal } from '../invite.jsx'

export function Overview({ onNavigate }) {
  const { network } = useApp()
  const [inviting, setInviting] = useState(false)

  const td = network?.td
  const nid = network?.nid

  const node = usePoll(() => getJson('/api/node'), [], 4000)
  const peers = usePoll(() => getJson('/api/peers'), [], 4000)
  const members = usePoll(
    useCallback(
      () => (td ? getJson(`/api/members?trust_domain_id=${encodeURIComponent(td)}&network_local_id=${encodeURIComponent(nid)}`) : Promise.resolve([])),
      [td, nid],
    ),
    [td, nid],
    8000,
  )
  const pending = usePoll(
    useCallback(
      () => (td ? getJson(`/api/pending?trust_domain_id=${encodeURIComponent(td)}&network_local_id=${encodeURIComponent(nid)}`) : Promise.resolve([])),
      [td, nid],
    ),
    [td, nid],
    6000,
  )

  if (!network) {
    return (
      <EmptyState
        icon="◍"
        title="尚未选择网络"
        hint="在顶栏选择一个网络，或前往「设置 › 高级」创建你的第一个网络。"
      />
    )
  }

  const info = node.data?.node_info
  const onlineCount = peers.data?.peer_infos?.length
  const memberCount = Array.isArray(members.data) ? members.data.length : undefined
  const pendingCount = Array.isArray(pending.data) ? pending.data.length : undefined
  const daemonDown = !!node.error

  return (
    <>
      {/* 快捷动作 */}
      <div class="quick-actions">
        <button class="btn btn-primary" onClick={() => setInviting(true)}>＋ 邀请设备</button>
        {pendingCount > 0 && (
          <button class="btn" onClick={() => onNavigate?.('pending')}>
            待批 <span class="badge-count">{pendingCount}</span>
          </button>
        )}
      </div>

      {/* 健康指标 */}
      <div class="metric-grid">
        <Metric label="设备" value={memberCount} loading={members.loading} onClick={() => onNavigate?.('devices')} />
        <Metric
          label="在线节点"
          value={daemonDown ? '—' : onlineCount}
          loading={peers.loading && !daemonDown}
          sub={daemonDown ? 'daemon 未连接' : undefined}
          onClick={() => onNavigate?.('devices')}
        />
        <Metric
          label="待批"
          value={daemonDown ? '—' : pendingCount}
          accent={pendingCount > 0}
          loading={pending.loading && !daemonDown}
          onClick={() => onNavigate?.('pending')}
        />
      </div>

      {/* 本机节点卡片 */}
      <div class="card">
        <div class="card-title">本机节点</div>
        {node.loading ? (
          <Skeleton rows={3} />
        ) : daemonDown ? (
          <div class="card-degrade">
            <Dot kind="err" label="daemon 未连接" />
            <span class="muted">控制器已就绪，但本机 daemon 未运行或不可达。启动 daemon 后将自动恢复。</span>
          </div>
        ) : info ? (
          <dl class="kv">
            <Row k="主机名" v={info.hostname || '—'} />
            <Row k="虚拟 IP" v={info.ipv4_addr || '—'} mono />
            <Row k="版本" v={info.version || '—'} />
            <Row k="节点号" v={info.peer_id} mono />
            <Row k="实例 ID" v={<CopyId value={info.inst_id} chars={12} />} />
            <Row k="监听" v={(info.listeners || []).join('  ') || '—'} mono />
            {(() => {
              const il = fmtIpList(info.ip_list)
              if (!il) return null
              const v4 = il.v4.map((x) => x.ip + (x.pub ? '（公网）' : ''))
              const v6 = il.v6.map((x) => x.ip + (x.pub ? '（公网）' : ''))
              return (
                <>
                  {v4.length > 0 && <Row k="物理 IPv4" v={v4.join('  ')} mono />}
                  {v6.length > 0 && <Row k="物理 IPv6" v={v6.join('  ')} mono />}
                </>
              )
            })()}
          </dl>
        ) : (
          <span class="muted">无节点信息</span>
        )}
      </div>

      {/* 空网络引导：仅本机一台设备时，引导邀请第一台设备 */}
      {memberCount !== undefined && memberCount <= 1 && (
        <div class="card onb-nudge">
          <div class="card-title">邀请你的第一台设备</div>
          <p class="muted">这个网络目前只有本机。生成一个邀请链接，让笔记本、手机或服务器扫码 / 运行 <code>accept-invite</code> 加入，再到「待批」批准即可。</p>
          <button class="btn btn-primary" onClick={() => setInviting(true)}>＋ 邀请设备</button>
        </div>
      )}

      {inviting && <InviteModal onClose={() => setInviting(false)} />}
    </>
  )
}

function Metric({ label, value, sub, accent, loading, onClick }) {
  const keyAct = onClick
    ? (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onClick()
        }
      }
    : undefined
  return (
    <div
      class={'metric' + (onClick ? ' clickable' : '')}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={keyAct}
      aria-label={onClick ? `${label}：${loading ? '加载中' : value ?? '无'}` : undefined}
    >
      <div class="metric-label">{label}</div>
      <div class={'metric-value' + (accent ? ' accent' : '')}>
        {loading ? '·' : value ?? '—'}
      </div>
      {sub && <div class="metric-sub">{sub}</div>}
    </div>
  )
}

function Row({ k, v, mono }) {
  return (
    <>
      <dt>{k}</dt>
      <dd class={mono ? 'mono' : ''}>{v}</dd>
    </>
  )
}
