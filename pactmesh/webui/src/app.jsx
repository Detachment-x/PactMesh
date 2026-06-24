import { useState, useRef, useEffect } from 'preact/hooks'
import { useApp } from './store.jsx'
import { Overview } from './pages/overview.jsx'
import { Devices } from './pages/devices.jsx'
import { Pending } from './pages/pending.jsx'
import { Mesh } from './pages/mesh.jsx'
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
      { id: 'devices', label: '设备' },
      { id: 'pending', label: '待批' },
      { id: 'mesh', label: '连通' },
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

export function App() {
  const [active, setActive] = useState('overview')
  const { domains, domainsLoading } = useApp()
  // 首启引导：域已加载且无任何网络 → 接管内容区，先带用户建好第一个网络。
  const onboarding = !domainsLoading && domains.length >= 0 && domains.every((d) => !d.networks.length)

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
          {NAV.map((section) => (
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
      <LockPill />
    </header>
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

  const hasAny = domains.some((d) => d.networks.length)
  return (
    <div class="net-picker" ref={ref}>
      <button class="net-trigger" onClick={() => setOpen((o) => !o)} disabled={!hasAny}>
        <span class="net-dot" />
        <span class="net-name">
          {network ? network.label : domainsLoading ? '加载中…' : hasAny ? '选择网络' : '暂无网络'}
        </span>
        <span class="caret">▾</span>
      </button>
      {open && hasAny && (
        <div class="net-menu">
          {domains
            .filter((d) => d.networks.length)
            .map((d) => (
              <div key={d.trust_domain_id} class="net-group">
                <div class="net-group-title">
                  {d.label || d.trust_domain_id.slice(0, 8)}
                  {d.is_root_holder && <span class="tag-root">主控</span>}
                </div>
                {d.networks.map((nid) => {
                  const sel = network && network.td === d.trust_domain_id && network.nid === nid
                  return (
                    <div
                      key={nid}
                      class={'net-item' + (sel ? ' active' : '')}
                      onClick={() => {
                        selectNetwork(d.trust_domain_id, nid)
                        setOpen(false)
                      }}
                    >
                      <code>{nid}</code>
                      {sel && <span class="check">✓</span>}
                    </div>
                  )
                })}
              </div>
            ))}
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
        {network && <div class="page-sub">网络 {network.label} · <code>{network.nid}</code></div>}
      </div>
      {id === 'overview' ? (
        <Overview onNavigate={onNavigate} />
      ) : id === 'devices' ? (
        <Devices />
      ) : id === 'pending' ? (
        <Pending />
      ) : id === 'mesh' ? (
        <Mesh />
      ) : id === 'diagnostics' ? (
        <Diagnostics />
      ) : id === 'policy' ? (
        <Policy />
      ) : id === 'groups' ? (
        <Groups />
      ) : id === 'config' ? (
        <Config />
      ) : id === 'advanced' ? (
        // 设置>高级：信任治理危险区（建域/建网/升根）+ 临时设备密钥（R2 落位）。
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
