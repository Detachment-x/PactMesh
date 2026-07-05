import { useState, useRef, useEffect } from 'preact/hooks'
import { useApp } from './store.jsx'
import { Overview } from './pages/overview.jsx'
import { Network } from './pages/network.jsx'
import { Pending } from './pages/pending.jsx'
import { Diagnostics } from './pages/diagnostics.jsx'
import { Policy } from './pages/policy.jsx'
import { Groups } from './pages/groups.jsx'
import { Config } from './pages/config.jsx'
import { Advanced } from './pages/advanced.jsx'
import { Onboarding } from './onboarding.jsx'

// 锁定的信息架构（4 组导航，应用最终术语）。D2 起逐页充实。
const NAV = [
  { group: null, items: [{ id: 'overview', label: '概览' }] },
  {
    group: '网络',
    items: [
      { id: 'network', label: '网络' },
      { id: 'pending', label: '待批' },
    ],
  },
  {
    group: '访问控制',
    items: [
      { id: 'policy', label: '访问策略' },
      { id: 'groups', label: '分组' },
    ],
  },
  {
    group: '设置',
    items: [
      { id: 'config', label: '本机配置' },
      { id: 'diagnostics', label: '诊断' },
      { id: 'advanced', label: '高级' },
    ],
  },
]

const LABELS = Object.fromEntries(NAV.flatMap((g) => g.items).map((i) => [i.id, i.label]))

// 治理专属页面：仅主控（持 root）可见；成员降级为精简只读 Console。
const GOV_ONLY = new Set(['pending', 'policy', 'groups', 'advanced'])

export function App() {
  const [active, setActive] = useState('overview')
  const { attached, instancesLoading, network } = useApp()
  const isRoot = !!network?.isRoot
  // 「未加网」空状态（以 ListNetworkInstance 为键）：空载常驻 daemon 起着但零实例挂载
  // → 接管内容区，引导用户建网并运行时加网（不重启 daemon）。
  const onboarding = !instancesLoading && !attached

  // 角色感知导航：成员隐藏治理页并剔除空分组。
  const nav = NAV
    .map((section) => ({
      ...section,
      items: section.items.filter((item) => isRoot || !GOV_ONLY.has(item.id)),
    }))
    .filter((section) => section.items.length)

  // 切到成员网络后若当前停在被隐藏的治理页 → 回落到概览。
  useEffect(() => {
    if (!isRoot && GOV_ONLY.has(active)) setActive('overview')
  }, [isRoot, active])

  const go = (id) => (e) => {
    if (e && e.type === 'keydown') {
      if (e.key !== 'Enter' && e.key !== ' ') return
      e.preventDefault()
    }
    setActive(id)
  }

  return (
    <div class="app-shell">
      <TopBar />
      <div class="body-grid">
        <nav class="sidebar" aria-label="主导航">
          {nav.map((section) => (
            <div key={section.group ?? '_'}>
              {section.group && <div class="nav-group-title">{section.group}</div>}
              {section.items.map((item) => (
                <div
                  key={item.id}
                  class={'nav-item' + (active === item.id ? ' active' : '')}
                  role="button"
                  tabIndex={0}
                  aria-current={active === item.id ? 'page' : undefined}
                  onClick={go(item.id)}
                  onKeyDown={go(item.id)}
                >
                  <span>{item.label}</span>
                </div>
              ))}
            </div>
          ))}
        </nav>
        <main class="content">
          {onboarding ? (
            <Onboarding />
          ) : (
            <Page id={active} title={LABELS[active]} onNavigate={setActive} />
          )}
        </main>
      </div>
    </div>
  )
}

function TopBar() {
  return (
    <header class="topbar">
      <div class="brand">
        <span class="brand-mark" />
        PactMesh
      </div>
      <NetworkPicker />
      <div class="topbar-spacer" />
      <ServiceStatus />
      <LockPill />
    </header>
  )
}

// 常驻服务状态：后台 daemon 是否可达（instances 轮询成败）。所有界面可见，含初始 onboarding。
function ServiceStatus() {
  const { daemonReachable } = useApp()
  return (
    <span
      class={'svc-status' + (daemonReachable ? ' ok' : ' down')}
      title={daemonReachable ? '后台服务已连接' : '后台服务未连接——请启动 PactMesh 服务'}
    >
      <span class="svc-dot" />
      {daemonReachable ? '服务正常' : '服务未连接'}
    </span>
  )
}

function NetworkPicker() {
  const { domains, network, selectNetwork, domainsLoading } = useApp()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    const onDoc = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false)
    document.addEventListener('click', onDoc)
    return () => document.removeEventListener('click', onDoc)
  }, [])

  // 扁平化切换器：直接列出所有网络（域分组隐藏），各带「管理员/成员」角色徽标。
  const nets = domains.flatMap((d) =>
    d.networks.map((nid) => ({ td: d.trust_domain_id, nid, isRoot: !!d.is_root_holder })),
  )
  const hasAny = nets.length > 0
  return (
    <div class="net-picker" ref={ref}>
      <button class="net-trigger" onClick={() => setOpen((o) => !o)} disabled={!hasAny}>
        <span class="net-dot" />
        <span class="net-name">
          {network ? network.nid : domainsLoading ? '加载中…' : hasAny ? '选择网络' : '暂无网络'}
        </span>
        <span class="caret">▾</span>
      </button>
      {open && hasAny && (
        <div class="net-menu">
          {nets.map(({ td, nid, isRoot }) => {
            const sel = network && network.td === td && network.nid === nid
            return (
              <div
                key={td + ' ' + nid}
                class={'net-item' + (sel ? ' active' : '')}
                onClick={() => {
                  selectNetwork(td, nid)
                  setOpen(false)
                }}
              >
                <code>{nid}</code>
                <span class={'badge-role ' + (isRoot ? 'role-root' : 'role-cred-soft')}>{isRoot ? '管理员' : '成员'}</span>
                {sel && <span class="check">✓</span>}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function LockPill() {
  const { unlocked, ttl, lock, requireUnlock } = useApp()
  const fmt = (s) => (s >= 60 ? `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}` : `${s}s`)
  if (unlocked) {
    return (
      <button class="lock-pill unlocked" title="点击锁定" onClick={lock}>
        🔓 已解锁 · {fmt(ttl)}
      </button>
    )
  }
  return (
    <button class="lock-pill" title="点击解锁" onClick={() => requireUnlock()}>
      🔒 已锁定
    </button>
  )
}

// 页面路由：已实现页直接渲染，其余 D3+ 逐步替换占位。
function Page({ id, title, onNavigate }) {
  const { network } = useApp()
  return (
    <div class="page">
      <div class="page-head">
        <h1>{title}</h1>
        {network && (
          <div class="page-sub">
            网络 <code>{network.nid}</code>
            <span class={'badge-role ' + (network.isRoot ? 'role-root' : 'role-cred-soft')}>{network.isRoot ? '管理员' : '成员'}</span>
          </div>
        )}
      </div>
      {id === 'overview' ? (
        <Overview onNavigate={onNavigate} />
      ) : id === 'network' ? (
        <Network onNavigate={onNavigate} />
      ) : id === 'pending' ? (
        <Pending />
      ) : id === 'diagnostics' ? (
        <Diagnostics />
      ) : id === 'policy' ? (
        <Policy />
      ) : id === 'groups' ? (
        <Groups />
      ) : id === 'config' ? (
        <Config />
      ) : id === 'advanced' ? (
        // 设置>高级：信任治理危险区（新建网络/升级管理员）+ 临时设备密钥（R2 落位）。
        <Advanced />
      ) : (
        <div class="placeholder">
          <div>
            <div class="ph-icon">✦</div>
            <p>「{title}」页面将在后续里程碑充实</p>
            <p class="muted">全局框架与概览/邀请已就位</p>
          </div>
        </div>
      )}
    </div>
  )
}
