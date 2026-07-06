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

// 两级顶部导航（无左栏）。
// 行2 — 网络级标签：随顶部切换器选中的网络而变（概览/网络/访问控制）。
// 行1 — 全局项：与网络无关（全局待批 / 本机配置 / 诊断 / 高级）。
// gov=true 的项仅对持根者可见：网络级按「选中网络」判定，全局项按「是否持有任一根网络」判定。
const NET_TABS = [
  { id: 'overview', label: '概览' },
  { id: 'network', label: '网络' },
  { id: 'policy', label: '访问策略', gov: true },
  { id: 'groups', label: '分组', gov: true },
]
const GLOBAL_ITEMS = [
  { id: 'pending', label: '待批', gov: true },
  { id: 'config', label: '本机配置' },
  { id: 'diagnostics', label: '诊断' },
  { id: 'advanced', label: '高级', gov: true },
]
const LABELS = Object.fromEntries([...NET_TABS, ...GLOBAL_ITEMS].map((i) => [i.id, i.label]))
const NET_IDS = new Set(NET_TABS.map((i) => i.id))

export function App() {
  const [active, setActive] = useState('overview')
  const { attached, instancesLoading, domains, network } = useApp()
  const isRoot = !!network?.isRoot
  const anyRoot = domains.some((d) => d.is_root_holder && d.networks.length)
  // 「未加网」空状态（以 ListNetworkInstance 为键）：空载常驻 daemon 起着但零实例挂载
  // → 接管内容区，引导用户建网并运行时加网（不重启 daemon）。
  const onboarding = !instancesLoading && !attached

  const netTabs = NET_TABS.filter((t) => isRoot || !t.gov)
  const globalItems = GLOBAL_ITEMS.filter((t) => anyRoot || !t.gov)

  // 当前页因角色变化被隐藏时回落到概览：网络级治理页按选中网络 isRoot，全局治理页按 anyRoot。
  useEffect(() => {
    const netTab = NET_TABS.find((t) => t.id === active)
    const globItem = GLOBAL_ITEMS.find((t) => t.id === active)
    if ((netTab?.gov && !isRoot) || (globItem?.gov && !anyRoot)) setActive('overview')
  }, [isRoot, anyRoot, active])

  const go = (id) => (e) => {
    if (e && e.type === 'keydown') {
      if (e.key !== 'Enter' && e.key !== ' ') return
      e.preventDefault()
    }
    setActive(id)
  }

  const Tab = ({ id, label, kind }) => (
    <div
      class={kind + (active === id ? ' active' : '')}
      role="button"
      tabIndex={0}
      aria-current={active === id ? 'page' : undefined}
      onClick={go(id)}
      onKeyDown={go(id)}
    >
      {label}
    </div>
  )

  return (
    <div class="app-shell">
      <header class="topbar-stack">
        <div class="topbar-row primary">
          <div class="brand">
            <span class="brand-mark" />
            PactMesh
          </div>
          <NetworkPicker />
          <nav class="nav-global" aria-label="全局导航">
            {globalItems.map((i) => <Tab key={i.id} id={i.id} label={i.label} kind="nav-pill" />)}
          </nav>
          <div class="topbar-spacer" />
          <ServiceStatus />
          <LockPill />
        </div>
        {network && (
          <div class="topbar-row tabs">
            <nav class="nav-tabs" aria-label="网络导航">
              {netTabs.map((t) => <Tab key={t.id} id={t.id} label={t.label} kind="nav-tab" />)}
            </nav>
          </div>
        )}
      </header>
      <main class="content">
        {onboarding ? (
          <Onboarding />
        ) : (
          <Page id={active} title={LABELS[active]} onNavigate={setActive} />
        )}
      </main>
    </div>
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

// 页面路由：网络级页带网络副标；全局页仅标题。
function Page({ id, title, onNavigate }) {
  const { network } = useApp()
  const isNet = NET_IDS.has(id)
  return (
    <div class="page">
      <div class="page-head">
        <h1>{title}</h1>
        {isNet && network && (
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
