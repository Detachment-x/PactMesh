import { useCallback, useState } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { EmptyState, Dot, CopyId, Toggle, InlineEdit, Modal, useToast } from '../ui.jsx'
import { dnsZone } from '../format.js'
import { DeviceRoster } from './devices.jsx'

// 单一网络中心页（ztncui / ZeroTier Central 风）：网络信息 + IP 池设置 + 设备名册（治理表）
// + 托管路由 + DNS（只读）+ 访问控制入口。轮询在此统一持有，向内嵌的设备名册下传（去重）。
// 成员（isRoot=false）降级只读并显示「离开网络」。
export function Network({ onNavigate }) {
  const { network, requireUnlock, refreshInstances } = useApp()
  const toast = useToast()
  const isRoot = !!network?.isRoot
  const td = network?.td
  const nid = network?.nid

  const members = usePoll(
    useCallback(() => (td ? api.members(td, nid) : Promise.resolve([])), [td, nid]),
    [td, nid],
    8000,
  )
  const pool = usePoll(
    useCallback(() => (td ? api.ipPool(td, nid) : Promise.resolve(null)), [td, nid]),
    [td, nid],
    0,
  )
  const routes = usePoll(api.routes, [], 4000)
  const peers = usePoll(api.peers, [], 4000)
  const node = usePoll(api.node, [], 4000)

  const [leaving, setLeaving] = useState(false)
  const [newRoute, setNewRoute] = useState('')

  if (!network) {
    return <EmptyState icon="◍" title="尚未选择网络" hint="在顶栏选择一个网络后查看其设置与设备。" />
  }

  // 在线节点计数（按 hostname，唯一 join 键）：本机 my_info/node + routes 各节点。
  const my = peers.data?.my_info || node.data?.node_info
  const onlineHosts = new Set()
  if (my?.hostname) onlineHosts.add(my.hostname)
  for (const r of routes.data?.routes || []) if (r.hostname) onlineHosts.add(r.hostname)

  const list = Array.isArray(members.data) ? members.data : []
  const runtimeDown = !!routes.error && !!peers.error && !!node.error
  const zone = dnsZone(my?.config)
  const poolData = pool.data || {}

  // 托管路由：各节点对外通告、经其可达的网段（hostname/peer 维度）；本机行可增删。
  const managed = []
  if (my?.proxy_cidrs?.length) for (const c of my.proxy_cidrs) managed.push({ cidr: c, via: my.hostname || `节点 ${my.peer_id}`, self: true })
  for (const r of routes.data?.routes || []) {
    for (const c of r.proxy_cidrs || []) managed.push({ cidr: c, via: r.hostname || `节点 ${r.peer_id}`, self: false })
  }

  // IP 池设置（控制器元数据，需主控解锁；非签名态）。
  const savePool = async (patch) => {
    const ok = await requireUnlock()
    if (!ok) return false
    try {
      await api.ipPoolSet({
        trust_domain_id: td,
        network_local_id: nid,
        ip_pool_cidr: patch.ip_pool_cidr ?? poolData.ip_pool_cidr ?? '',
        auto_assign: patch.auto_assign ?? !!poolData.auto_assign,
      })
      toast.ok('IP 池设置已保存')
      await pool.refresh()
      return true
    } catch (e) {
      toast.err(e.message)
      return false
    }
  }

  // 从池自动为某设备分配空闲 IP（走 assigned-ipv4 签名路径）；设备名册的 IP 单元格调用此项。
  const autoAssign = async (fp) => {
    const ok = await requireUnlock()
    if (!ok) return
    try {
      await api.autoAssign(fp)
      toast.ok('已自动分配 IP')
      members.refresh()
    } catch (e) {
      toast.err(e.message)
    }
  }

  // 本机托管路由增删（daemon RPC，无需签名）。
  const routeOp = async (action, cidr) => {
    try {
      await api.cfgProxyNetwork({ action, cidr })
      toast.ok(action === 'add' ? '已添加本机通告网段' : '已移除')
      routes.refresh(); node.refresh()
      return true
    } catch (e) {
      toast.err(e.message)
      return false
    }
  }
  const addRoute = async () => {
    const v = newRoute.trim()
    if (!v) return
    if (await routeOp('add', v)) setNewRoute('')
  }

  return (
    <>
      {/* 网络信息 */}
      <div class="card">
        <div class="card-title">网络信息{!isRoot && <span class="badge-role role-cred-soft">成员视图</span>}</div>
        <dl class="kv">
          <dt>网络名</dt><dd>{network.label}</dd>
          <dt>网络 ID</dt><dd class="mono">{nid}</dd>
          <dt>信任域</dt><dd><CopyId value={td} chars={12} /></dd>
          <dt>设备数</dt><dd>{members.loading ? '·' : list.length}</dd>
          <dt>在线节点</dt><dd>{runtimeDown ? '—' : onlineHosts.size}</dd>
        </dl>
      </div>

      {/* IP 分配（地址池 + 自动分配总开关） */}
      <div class="card">
        <div class="card-title">IP 分配</div>
        <dl class="kv">
          <dt>地址池网段</dt>
          <dd>
            {isRoot ? (
              <InlineEdit
                value={poolData.ip_pool_cidr || ''}
                placeholder="10.10.0.0/24"
                mono
                title="点击设置自动分配的地址范围"
                onCommit={(v) => savePool({ ip_pool_cidr: v })}
                render={(v) => v ? <span class="mono">{v}</span> : <span class="muted">未设置</span>}
              />
            ) : (poolData.ip_pool_cidr ? <span class="mono">{poolData.ip_pool_cidr}</span> : <span class="muted">未设置</span>)}
          </dd>
          <dt>自动分配</dt>
          <dd>
            {isRoot ? (
              <Toggle
                label={poolData.auto_assign ? '开启' : '关闭'}
                hint="新设备审批时自动从池中分配固定 IP"
                checked={!!poolData.auto_assign}
                onChange={(next) => savePool({ auto_assign: next })}
              />
            ) : (poolData.auto_assign ? <Dot kind="ok" label="开启" /> : <Dot kind="muted" label="关闭" />)}
          </dd>
        </dl>
        <p class="muted">
          未指派的设备默认<strong>自助分配</strong>虚拟 IPv4（DHCP，冲突自动重选）。设置地址池后，可在下方设备表逐台
          <strong>自动分配</strong>或指派固定 IP，经 root 签名的网络状态实时下发。
        </p>
      </div>

      {/* 设备（治理名册，内嵌自 devices.jsx） */}
      <div class="card">
        <div class="card-title">设备</div>
        <DeviceRoster members={members} peers={peers} routes={routes} node={node} pool={pool} onAutoAssign={autoAssign} />
      </div>

      {/* 托管路由（本机通告可编辑） */}
      <div class="card">
        <div class="card-title">托管路由</div>
        <p class="muted">网络内各设备对外通告、经其可达的网段。<strong>本机</strong>通告的网段可在此增删（作用于本机、经数据面下发）。</p>
        {runtimeDown ? (
          <div class="card-degrade"><Dot kind="err" label="daemon 未连接" /><span class="muted">启动 daemon 后显示并可编辑托管路由。</span></div>
        ) : (
          <>
            {managed.length > 0 && (
              <div class="table-wrap">
                <table class="dtable">
                  <thead><tr><th>网段</th><th>经由</th><th></th></tr></thead>
                  <tbody>
                    {managed.map((m, i) => (
                      <tr key={i}>
                        <td class="mono-cell">{m.cidr}</td>
                        <td>{m.via}{m.self && <span class="badge-role role-root">本机</span>}</td>
                        <td class="ta-right">
                          {m.self && <button class="icon-btn danger" title="移除本机通告" onClick={() => routeOp('remove', m.cidr)}>✕</button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {!managed.length && <p class="muted">暂无对外通告的网段。</p>}
            <div class="inline-field route-add">
              <input
                class="field mono"
                value={newRoute}
                placeholder="192.168.9.0/24"
                onInput={(e) => setNewRoute(e.currentTarget.value)}
                onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addRoute())}
              />
              <button class="btn btn-sm" onClick={addRoute}>添加本机通告</button>
            </div>
          </>
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

      {/* 访问控制入口（仅主控） */}
      {isRoot && (
        <div class="card">
          <div class="card-title">访问控制</div>
          <p class="muted">控制网络内谁能访问什么。</p>
          <div class="quick-actions">
            <button class="btn" onClick={() => onNavigate?.('policy')}>访问策略</button>
            <button class="btn" onClick={() => onNavigate?.('groups')}>分组</button>
          </div>
        </div>
      )}

      {/* 离开网络（成员） */}
      {!isRoot && (
        <div class="card danger-card">
          <div class="card-title">离开网络</div>
          <p class="muted">停止本机在此网络的连接并从本机移除该网络。你的设备将立即断开，需重新经邀请加入。</p>
          <button class="btn btn-danger btn-sm" onClick={() => setLeaving(true)}>离开网络</button>
        </div>
      )}

      {leaving && (
        <Modal
          title={`离开网络「${network.label}」`}
          onClose={() => setLeaving(false)}
          footer={
            <>
              <button class="btn" onClick={() => setLeaving(false)}>取消</button>
              <button
                class="btn btn-danger"
                onClick={async () => {
                  try {
                    await api.leave(td, nid)
                    toast.ok('已离开网络')
                    setLeaving(false)
                    refreshInstances()
                  } catch (e) {
                    toast.err(e.message)
                  }
                }}
              >确认离开</button>
            </>
          }
        >
          <p class="modal-note">本机将停止连接并移除该网络配置。此操作只影响本机，不影响网络中的其他设备。</p>
        </Modal>
      )}
    </>
  )
}
