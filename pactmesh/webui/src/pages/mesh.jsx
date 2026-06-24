import { useState } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { Skeleton, EmptyState, CopyId, Dot, Drawer } from '../ui.jsx'
import { ipv4, bytes, latencyUs, NAT_TYPE, IDENTITY } from '../format.js'

// 从一个节点的连接集合提炼摘要：是否有活跃连接、隧道类型、最佳延迟、丢包、是否临时设备。
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

export function Mesh() {
  const peers = usePoll(api.peers, [], 4000)
  const routes = usePoll(api.routes, [], 4000)
  const [sel, setSel] = useState(null) // 抽屉选中 peer_id

  const daemonDown = !!peers.error || !!routes.error
  const loading = (peers.loading || routes.loading) && !daemonDown

  const connByPeer = {}
  for (const p of peers.data?.peer_infos || []) connByPeer[p.peer_id] = p.conns
  const my = peers.data?.my_info

  // routes = 可达节点权威清单；附加连接质量。本机不在 routes 里，单列卡片。
  const nodes = (routes.data?.routes || []).map((r) => ({ ...r, sum: connSummary(connByPeer[r.peer_id]) }))
  const current = nodes.find((n) => n.peer_id === sel) || null

  return (
    <>
      <div class="toolbar">
        <span class="muted">
          {loading ? '加载中…' : daemonDown ? 'daemon 未连接' : `${nodes.length} 个可达节点`}
        </span>
        <button class="btn btn-ghost" onClick={() => { peers.refresh(); routes.refresh() }}>刷新</button>
      </div>

      {daemonDown ? (
        <div class="card card-degrade">
          <Dot kind="err" label="daemon 未连接" />
          <span class="muted">连通视图依赖本机 daemon。启动 daemon 后将自动显示节点拓扑与连接质量。</span>
        </div>
      ) : (
        <>
          {my && (
            <div class="card local-node">
              <div class="card-title">
                本机节点 <span class="badge-role role-root">本机</span>
              </div>
              <dl class="kv">
                <dt>主机名</dt><dd>{my.hostname || '—'}</dd>
                <dt>虚拟 IP</dt><dd class="mono">{my.ipv4_addr || '—'}</dd>
                <dt>节点号</dt><dd class="mono">{my.peer_id}</dd>
                <dt>版本</dt><dd>{my.version || '—'}</dd>
              </dl>
            </div>
          )}

          {loading && !nodes.length ? (
            <Skeleton rows={4} />
          ) : !nodes.length ? (
            <EmptyState icon="◌" title="暂无其他节点" hint="网络中还没有其他在线节点。邀请并审批设备后，它们上线即会出现在这里。" />
          ) : (
            <div class="table-wrap">
              <table class="dtable">
                <thead>
                  <tr><th>节点</th><th>虚拟 IP</th><th>连接</th><th>延迟</th><th>丢包</th><th>版本</th><th></th></tr>
                </thead>
                <tbody>
                  {nodes.map((n) => {
                    const s = n.sum
                    const direct = n.next_hop_peer_id === n.peer_id
                    return (
                      <tr key={n.peer_id}>
                        <td>
                          <div class="dev-name">
                            <span>{n.hostname || <span class="muted">节点 {n.peer_id}</span>}</span>
                            {s.credential && <span class="badge-role role-cred">临时设备</span>}
                          </div>
                        </td>
                        <td class="mono-cell">{ipv4(n.ipv4_addr)}</td>
                        <td>
                          {s.online ? (
                            <span class="chips">
                              <span class={'chip ' + (direct ? 'chip-ok' : 'chip-warn')}>{direct ? '直连' : '中继'}</span>
                              <span class="chip">{s.tunnel}</span>
                            </span>
                          ) : (
                            <Dot kind="muted" label="离线" />
                          )}
                        </td>
                        <td class="mono-cell">{s.online ? latencyUs(s.latencyUs) : '—'}</td>
                        <td class="mono-cell">{s.online ? `${((s.loss || 0) * 100).toFixed(0)}%` : '—'}</td>
                        <td class="mono-cell">{n.version || '—'}</td>
                        <td class="ta-right">
                          <button class="btn btn-ghost btn-sm" onClick={() => setSel(n.peer_id)}>详情</button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {current && (
        <NodeDrawer node={current} conns={connByPeer[current.peer_id]} onClose={() => setSel(null)} />
      )}
    </>
  )
}

function NodeDrawer({ node, conns, onClose }) {
  const live = (conns || []).filter((c) => !c.is_closed)
  const nat = node.stun_info?.udp_nat_type
  return (
    <Drawer
      title={node.hostname || `节点 ${node.peer_id}`}
      subtitle={<><span class="mono">{ipv4(node.ipv4_addr)}</span> · 节点 {node.peer_id}</>}
      onClose={onClose}
      footer={<button class="btn" onClick={onClose}>关闭</button>}
    >
      <section class="drawer-sec">
        <div class="sec-title">概况</div>
        <dl class="kv">
          <dt>下一跳</dt><dd class="mono">{node.next_hop_peer_id === node.peer_id ? '直连' : `经节点 ${node.next_hop_peer_id}`}</dd>
          <dt>路径成本</dt><dd class="mono">{node.cost ?? '—'}</dd>
          <dt>NAT 类型</dt><dd>{nat != null ? NAT_TYPE[nat] || nat : '—'}</dd>
          <dt>版本</dt><dd>{node.version || '—'}</dd>
          <dt>实例 ID</dt><dd><CopyId value={node.inst_id} chars={14} /></dd>
        </dl>
        {node.proxy_cidrs?.length > 0 && (
          <div class="form-row">
            <label class="field-label">代理网段</label>
            <div class="chips">{node.proxy_cidrs.map((c) => <span key={c} class="chip"><code>{c}</code></span>)}</div>
          </div>
        )}
      </section>

      <section class="drawer-sec">
        <div class="sec-title">连接 <small>（{live.length} 条活跃）</small></div>
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
      </section>
    </Drawer>
  )
}
