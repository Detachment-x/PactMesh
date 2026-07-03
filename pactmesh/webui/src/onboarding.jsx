import { useState, useMemo } from 'preact/hooks'
import { api } from './api.js'
import { useApp } from './store.jsx'
import { useToast } from './ui.jsx'

// 「未加网」空状态（Flow A）：空载常驻 daemon 起着但零实例挂载时接管内容区。
// 先分叉角色（F-1）：新建网络（成为主控）或经邀请加入既有网络（成为成员设备）。
//  - 建网 → 一次性 POST /api/network/run（建域?→建网→自举→封存口令→RunNetworkInstance，不重启）。
//  - 加入 → 预览邀请确认（F-2）→ POST /api/network/join 起后台 accept-invite（非阻塞）→
//    等待主控批准（F-3，轮询 join-status，批准后服务端自动挂载）。
// 有进行中的加入时（含 Console 重开，F-4）直接接管为等待界面。

export function Onboarding() {
  const { pendingJoins, refreshJoins } = useApp()
  const [role, setRole] = useState(null) // null | 'create' | 'join'
  const [dismissed, setDismissed] = useState(false)

  const join = pendingJoins[0]
  const waiting = join && (join.status === 'pending' || join.status === 'submitting')
  const terminal = join && (join.status === 'error' || join.status === 'timeout') && !dismissed

  if (waiting) return <JoinWaiting join={join} />
  if (terminal) {
    return <JoinWaiting join={join} onRetry={() => { setDismissed(true); setRole('join') }} />
  }

  return (
    <div class="onb">
      <div class="onb-hero">
        <div class="onb-mark" />
        <h1>欢迎使用 PactMesh</h1>
        <p class="onb-lead">服务已在后台常驻，但还没有运行中的网络。你可以新建一个网络成为主控，或用邀请链接加入既有网络。</p>
      </div>

      {role === null && <ReuseBanner />}
      {role === null && <RolePicker onPick={setRole} />}
      {role === 'create' && <CreateFlow onBack={() => setRole(null)} />}
      {role === 'join' && <JoinFlow onBack={() => setRole(null)} onSubmitted={() => { setDismissed(false); refreshJoins() }} />}
    </div>
  )
}

// ---------- F-1 角色分叉 ----------
function RolePicker({ onPick }) {
  return (
    <div class="onb-roles">
      <button type="button" class="card onb-role" onClick={() => onPick('create')}>
        <div class="onb-role-icon">＋</div>
        <div class="onb-role-title">新建网络</div>
        <p class="muted">成为网络主控，持有 root 私钥，审批成员、下发策略。适合第一次搭建自己的网络。</p>
      </button>
      <button type="button" class="card onb-role" onClick={() => onPick('join')}>
        <div class="onb-role-icon">↳</div>
        <div class="onb-role-title">加入既有网络</div>
        <p class="muted">用别人给你的邀请链接，作为成员设备加入。提交后等待主控批准，批准后自动上线。</p>
      </button>
    </div>
  )
}

// ---------- 复用并上线：盘上已有但未挂载的网络，一键重新挂载（不重建） ----------
function ReuseBanner() {
  const toast = useToast()
  const { domains, daemonReachable, refreshDomains, refreshInstances, selectNetwork } = useApp()
  const [busy, setBusy] = useState('')
  const disk = useMemo(
    () =>
      domains.flatMap((d) =>
        d.networks.map((nid) => ({ td: d.trust_domain_id, nid, label: d.label || d.trust_domain_id.slice(0, 12) })),
      ),
    [domains],
  )
  if (!daemonReachable || disk.length === 0) return null

  const mount = async (td, nid) => {
    setBusy(td + ' ' + nid)
    try {
      await api.networkMount(td, nid)
      toast.ok('网络已上线')
      refreshDomains()
      refreshInstances()
      selectNetwork(td, nid)
    } catch (e) {
      toast.err('复用上线失败：' + e.message)
      setBusy('')
    }
  }

  return (
    <div class="card onb-reuse">
      <div class="onb-reuse-title">检测到本机已有网络</div>
      <p class="muted">这些网络的配置与密钥仍在本机，只是当前没有运行。可直接复用并上线，无需重建。</p>
      <ul class="onb-reuse-list">
        {disk.map(({ td, nid, label }) => (
          <li key={td + ' ' + nid}>
            <span class="onb-reuse-net"><strong class="mono">{nid}</strong><small class="muted">{label}</small></span>
            <button class="btn btn-primary btn-sm" disabled={!!busy} onClick={() => mount(td, nid)}>
              {busy === td + ' ' + nid ? '上线中…' : '复用并上线'}
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ---------- 建网（成为主控），沿用原一站式 /api/network/run ----------
function CreateFlow({ onBack }) {
  const toast = useToast()
  const { domains, refreshDomains, refreshInstances, selectNetwork, daemonReachable } = useApp()
  const rootDomains = useMemo(() => domains.filter((d) => d.is_root_holder), [domains])
  const hasDiskNetwork = useMemo(() => domains.some((d) => d.networks.length), [domains])

  const [step, setStep] = useState(1)
  const [useExisting, setUseExisting] = useState(rootDomains.length > 0)
  const [existingTd, setExistingTd] = useState(rootDomains[0]?.trust_domain_id || '')
  const [label, setLabel] = useState('')
  const [pass, setPass] = useState('')
  const [nid, setNid] = useState('')
  const [action, setAction] = useState('accept')
  const [noTun, setNoTun] = useState(false)
  const [busy, setBusy] = useState(false)

  const step1Valid = useExisting ? !!existingTd && pass.length >= 8 : label.trim() && pass.length >= 8
  const step2Valid = nid.trim().length > 0

  const finish = async () => {
    setBusy(true)
    try {
      const r = await api.networkRun({
        trust_domain_id: useExisting ? existingTd : undefined,
        domain_label: useExisting ? undefined : label.trim(),
        network_local_id: nid.trim(),
        default_action: action,
        root_passphrase: pass,
        no_tun: noTun,
      })
      toast.ok('网络已上线')
      refreshDomains()
      refreshInstances()
      selectNetwork(r.trust_domain_id, r.network_local_id)
    } catch (e) {
      const msg = /already exists/i.test(e.message)
        ? '该网络已存在于本机。请返回首页用「复用并上线」直接挂载；如需重建，先卸载并勾选彻底删除。'
        : '建网/加网失败：' + e.message
      toast.err(msg)
      setBusy(false)
    }
  }

  return (
    <>
      {!daemonReachable && (
        <div class="warnbar">后台 daemon 暂不可达——新建网络需要它在运行。请确认服务已启动后再试。</div>
      )}
      {daemonReachable && hasDiskNetwork && (
        <div class="onb-note muted">本机已有信任域/网络。若只是想让既有网络重新上线，请返回并用「复用并上线」，无需在此重建。</div>
      )}

      <ol class="onb-steps" aria-label="引导步骤">
        <li class={'onb-step' + (step === 1 ? ' active' : step > 1 ? ' done' : '')}>
          <span class="onb-num">1</span>信任域
        </li>
        <li class={'onb-step' + (step === 2 ? ' active' : '')}>
          <span class="onb-num">2</span>网络
        </li>
      </ol>

      <div class="card onb-card">
        {step === 1 ? (
          <>
            <div class="onb-card-title">选择或新建信任域</div>
            <p class="muted">信任域持有该网络的 root 私钥，你将成为它的主控。口令仅驻留内存、即用即清，绝不落盘。</p>

            {rootDomains.length > 0 && (
              <div class="onb-choice" role="radiogroup" aria-label="信任域来源">
                <button
                  type="button"
                  class={'onb-opt' + (useExisting ? ' sel' : '')}
                  role="radio"
                  aria-checked={useExisting}
                  onClick={() => setUseExisting(true)}
                >
                  使用现有信任域
                </button>
                <button
                  type="button"
                  class={'onb-opt' + (!useExisting ? ' sel' : '')}
                  role="radio"
                  aria-checked={!useExisting}
                  onClick={() => setUseExisting(false)}
                >
                  新建信任域
                </button>
              </div>
            )}

            {useExisting ? (
              <label class="form-row">
                <span class="field-label">信任域</span>
                <select class="field" value={existingTd} onChange={(e) => setExistingTd(e.currentTarget.value)}>
                  {rootDomains.map((d) => (
                    <option key={d.trust_domain_id} value={d.trust_domain_id}>
                      {d.label || d.trust_domain_id.slice(0, 12)}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <label class="form-row">
                <span class="field-label">域名称<small>便于识别</small></span>
                <input class="field" value={label} placeholder="home" onInput={(e) => setLabel(e.currentTarget.value)} />
              </label>
            )}

            <label class="form-row">
              <span class="field-label">管理口令<small>至少 8 位</small></span>
              <input
                class="field"
                type="password"
                autocomplete="new-password"
                value={pass}
                placeholder={useExisting ? '该域的 root 口令' : '为新域设置 root 口令'}
                onInput={(e) => setPass(e.currentTarget.value)}
              />
            </label>

            <div class="onb-actions">
              <button class="btn" onClick={onBack}>返回</button>
              <button class="btn btn-primary" disabled={!step1Valid} onClick={() => setStep(2)}>下一步</button>
            </div>
          </>
        ) : (
          <>
            <div class="onb-card-title">创建并上线网络</div>
            <p class="muted">网络是设备加入的对象。给它一个 ID 和默认放行策略，网络创建后会立即挂到后台 daemon 上运行。</p>

            <label class="form-row">
              <span class="field-label">网络 ID<small>本域内唯一</small></span>
              <input class="field mono" value={nid} placeholder="home-net" onInput={(e) => setNid(e.currentTarget.value)} />
            </label>
            <label class="form-row">
              <span class="field-label">默认策略<small>未命中规则时</small></span>
              <select class="field field-sm" value={action} onChange={(e) => setAction(e.currentTarget.value)}>
                <option value="accept">放行</option>
                <option value="drop">丢弃</option>
              </select>
            </label>
            <label class="check-row">
              <input type="checkbox" checked={noTun} onInput={(e) => setNoTun(e.currentTarget.checked)} />
              <span>不创建虚拟网卡（无 TUN）<small class="muted">用于无 cap_net_admin 的测试/纯中继场景。</small></span>
            </label>

            <div class="onb-actions">
              <button class="btn" disabled={busy} onClick={() => setStep(1)}>上一步</button>
              <button class="btn btn-primary" disabled={busy || !step2Valid || !daemonReachable} onClick={finish}>
                {busy ? '创建并上线中…' : '创建并上线'}
              </button>
            </div>
          </>
        )}
      </div>
    </>
  )
}

// ---------- F-2 加入既有网络：预览确认 → 提交加入申请 ----------
function JoinFlow({ onBack, onSubmitted }) {
  const toast = useToast()
  const [url, setUrl] = useState('')
  const [preview, setPreview] = useState(null)
  const [checking, setChecking] = useState(false)
  const [noTun, setNoTun] = useState(false)
  const [busy, setBusy] = useState(false)

  const doPreview = async () => {
    if (!url.trim() || checking) return
    setChecking(true)
    try {
      const p = await api.invitePreview(url.trim())
      setPreview(p)
    } catch (e) {
      setPreview(null)
      toast.err('邀请链接无效：' + e.message)
    }
    setChecking(false)
  }

  const submit = async () => {
    if (busy) return
    setBusy(true)
    try {
      await api.join({
        invite_url: url.trim(),
        no_tun: noTun,
      })
      toast.ok('已提交加入申请，等待主控批准')
      onSubmitted()
    } catch (e) {
      toast.err('提交加入失败：' + e.message)
      setBusy(false)
    }
  }

  return (
    <div class="card onb-card">
      <div class="onb-card-title">加入既有网络</div>
      <p class="muted">粘贴主控给你的邀请链接。核对信任域与网络无误后提交申请。</p>

      <label class="form-row">
        <span class="field-label">邀请链接<small>privatenetwork://join?…</small></span>
        <textarea
          class="field invite"
          rows={3}
          value={url}
          placeholder="privatenetwork://join?d=…"
          onInput={(e) => { setUrl(e.currentTarget.value); setPreview(null) }}
        />
      </label>

      {!preview ? (
        <div class="onb-actions">
          <button class="btn" onClick={onBack}>返回</button>
          <button class="btn btn-primary" disabled={!url.trim() || checking} onClick={doPreview}>
            {checking ? '校验中…' : '校验邀请'}
          </button>
        </div>
      ) : (
        <>
          <div class="onb-note">
            <div class="kv"><span>信任域</span><b>{preview.domain_label || preview.trust_domain_id.slice(0, 12)}</b></div>
            <div class="kv"><span>网络</span><b>{preview.network_name || preview.network_local_id}</b></div>
            <div class="kv"><span>网络 ID</span><code>{preview.network_local_id}</code></div>
            <div class="kv"><span>落脚点</span><b>{preview.seed_count} 个</b></div>
          </div>

          <label class="check-row">
            <input type="checkbox" checked={noTun} onInput={(e) => setNoTun(e.currentTarget.checked)} />
            <span>不创建虚拟网卡（无 TUN）<small class="muted">用于无 cap_net_admin 的测试/纯中继场景。</small></span>
          </label>

          <div class="onb-actions">
            <button class="btn" disabled={busy} onClick={() => setPreview(null)}>上一步</button>
            <button class="btn btn-primary" disabled={busy} onClick={submit}>
              {busy ? '提交中…' : '提交加入申请'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

// ---------- F-3 等待主控批准 ----------
function JoinWaiting({ join, onRetry }) {
  const label = join.domain_label || (join.trust_domain_id || '').slice(0, 12)
  const netName = join.network_name || join.network_local_id
  const failed = join.status === 'error' || join.status === 'timeout'

  return (
    <div class="onb">
      <div class="onb-hero">
        <div class="onb-mark" />
        <h1>{failed ? '加入未完成' : '等待主控批准'}</h1>
        <p class="onb-lead">
          加入网络 <b>{netName}</b>（信任域 {label}）
        </p>
      </div>

      <div class="card onb-card onb-wait">
        {!failed ? (
          <>
            <div class="onb-spinner" aria-hidden="true" />
            <div class="onb-card-title">申请已提交，等待批准…</div>
            <p class="muted">主控批准后本机会自动上线，无需再操作。可以关闭此页面——稍后重新打开会自动恢复等待。</p>
          </>
        ) : join.status === 'timeout' ? (
          <>
            <div class="onb-card-title">加入超时</div>
            <p class="muted">主控未在时限内批准这次申请。你可以重新发起加入。</p>
            {onRetry && <div class="onb-actions"><button class="btn btn-primary" onClick={onRetry}>重新加入</button></div>}
          </>
        ) : (
          <>
            <div class="onb-card-title">加入出错</div>
            <p class="warnbar">{join.error || '未知错误'}</p>
            {onRetry && <div class="onb-actions"><button class="btn btn-primary" onClick={onRetry}>重新加入</button></div>}
          </>
        )}
      </div>
    </div>
  )
}
