import { useCallback } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, Dot, CopyId } from '../ui.jsx'
import { ipv4, dnsZone } from '../format.js'

// 网络级总览（ztncui 风）：聚合现有只读端点 —— 成员 IP 一览、托管路由、IP 分配模式、
// DNS 状态、访问控制入口。Phase 1 全只读、后端零改动；Phase 2 在此叠加「主控指派 IP / IP 池」。
export function Network({ onNavigate }) {
  const { network } = useApp()
  const td = network?.td
  const nid = network?.nid

  const members = usePoll(
    useCallback(() => (td ? api.members(td, nid) : Promise.resolve([])), [td, nid]),
    [td, nid],
    8000,
  )
  const routes = usePoll(api.routes, [], 5000)
  const peers = usePoll(api.peers, [], 5000)
  const node = usePoll(api.node, [], 5000)

  if (!network) {
    return <EmptyState icon="◍" title="尚未选择网络" hint="在顶栏选择一个网络后查看其网络设置。" />
  }

  // 运行时按 hostname 索引（唯一 join 键）：本机取 my_info/node，其余取 routes。
  const byHost = {}
  const my = peers.data?.my_info || node.data?.node_info
  if (my?.hostname) byHost[my.hostname] = { ip: my.ipv4_addr || '—', online: true, self: true }
  for (const r of routes.data?.routes || []) {
    if (r.hostname) byHost[r.hostname] = { ip: ipv4(r.ipv4_addr), online: true, self: false }
  }

  const list = Array.isArray(members.data) ? members.data : []
  const onlineCount = Object.keys(byHost).length
  const runtimeDown = !!routes.error && !!peers.error && !!node.error
  const zone = dnsZone(my?.config)

  // 托管路由：各节点对外通告的代理网段（hostname/peer 维度）。
  const managed = []
  if (my?.proxy_cidrs?.length) for (const c of my.proxy_cidrs) managed.push({ cidr: c, via: my.hostname || `节点 ${my.peer_id}`, self: true })
  for (const r of routes.data?.routes || []) {
    for (const c of r.proxy_cidrs || []) managed.push({ cidr: c, via: r.hostname || `节点 ${r.peer_id}`, self: false })
  }

  return (
    <>
      {/* 网络信息 */}
      <div class="card">
        <div class="card-title">网络信息</div>
        <dl class="kv">
          <dt>网络名</dt><dd>{network.label}</dd>
          <dt>网络 ID</dt><dd class="mono">{nid}</dd>
          <dt>信任域</dt><dd><CopyId value={td} chars={12} /></dd>
          <dt>设备数</dt><dd>{members.loading ? '·' : list.length}</dd>
          <dt>在线节点</dt><dd>{runtimeDown ? '—' : onlineCount}</dd>
        </dl>
      </div>

      {/* IP 分配 */}
      <div class="card">
        <div class="card-title">IP 分配</div>
        <p class="muted">
          当前网络采用<strong>设备自助分配</strong>：每台设备启动时自选虚拟 IPv4（DHCP 模式，地址冲突会自动重选），或在该设备「本机配置 › 虚拟 IP」中设置静态地址。
        </p>
        <p class="muted">主控集中指派 IP（为指定设备锁定固定地址、可视化 IP 池）正在规划中。</p>
      </div>

      {/* 成员 IP 一览 */}
      <div class="card">
        <div class="card-title">成员 IP</div>
        {members.loading && !list.length ? (
          <Skeleton rows={3} />
        ) : !list.length ? (
          <span class="muted">还没有设备。</span>
        ) : (
          <div class="table-wrap">
            <table class="dtable">
              <thead>
                <tr><th>设备</th><th>主机名</th><th>虚拟 IP</th><th>状态</th></tr>
              </thead>
              <tbody>
                {list.map((d) => {
                  const r = d.hostname ? byHost[d.hostname] : null
                  return (
                    <tr key={d.device_id}>
                      <td>{d.device_label || '未命名设备'}</td>
                      <td class="mono-cell">{d.hostname || <span class="muted">—</span>}</td>
                      <td class="mono-cell">{r ? r.ip : <span class="muted">—</span>}</td>
                      <td>
                        {r ? <Dot kind="ok" label={r.self ? '本机' : '在线'} /> : <Dot kind="muted" label={runtimeDown ? '未知' : '离线'} />}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 托管路由 */}
      <div class="card">
        <div class="card-title">托管路由</div>
        <p class="muted">网络内各设备对外通告、经其可达的网段。在设备的「本机配置 › 路由 / 代理网段」中设置。</p>
        {runtimeDown ? (
          <div class="card-degrade"><Dot kind="err" label="daemon 未连接" /><span class="muted">启动 daemon 后显示托管路由。</span></div>
        ) : !managed.length ? (
          <span class="muted">暂无对外通告的网段。</span>
        ) : (
          <div class="table-wrap">
            <table class="dtable">
              <thead><tr><th>网段</th><th>经由</th></tr></thead>
              <tbody>
                {managed.map((m, i) => (
                  <tr key={i}>
                    <td class="mono-cell">{m.cidr}</td>
                    <td>{m.via}{m.self && <span class="badge-role role-root">本机</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* DNS（只读） */}
      <div class="card">
        <div class="card-title">名称解析<span class="badge-role role-cred-soft">只读</span></div>
        {zone ? (
          <dl class="kv"><dt>网络域</dt><dd class="mono">{zone}</dd></dl>
        ) : (
          <p class="muted">未启用 MagicDNS，或 daemon 未连接。详见「本机配置 › 名称解析」。</p>
        )}
      </div>

      {/* 访问控制入口 */}
      <div class="card">
        <div class="card-title">访问控制</div>
        <p class="muted">控制网络内谁能访问什么。</p>
        <div class="quick-actions">
          <button class="btn" onClick={() => onNavigate?.('policy')}>访问策略</button>
          <button class="btn" onClick={() => onNavigate?.('groups')}>分组</button>
        </div>
      </div>
    </>
  )
}
