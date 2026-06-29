import { useState, useMemo } from 'preact/hooks'
import { api } from './api.js'
import { useApp } from './store.jsx'
import { useToast } from './ui.jsx'

// 「未加网」空状态（Flow A）：空载常驻 daemon 起着但零实例挂载时接管内容区。
// 两步把用户带到「拥有一个正在运行的网络」——新建/选择信任域（建域）→ 建网，
// 然后一次性 POST /api/network/run（建域?→建网→自举本机→封存口令→对运行中
// daemon 调 RunNetworkInstance，不重启），网络即时上线、设备就此挂上。
// 已有主控信任域时可跳过建域、直接在其下建网。

export function Onboarding() {
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
  const [devPass, setDevPass] = useState('')
  const [remember, setRemember] = useState(true)
  const [noTun, setNoTun] = useState(false)
  const [busy, setBusy] = useState(false)

  const step1Valid = useExisting ? !!existingTd && pass.length >= 8 : label.trim() && pass.length >= 8
  const step2Valid = nid.trim().length > 0 && devPass.length >= 8

  const finish = async () => {
    setBusy(true)
    try {
      const r = await api.networkRun({
        trust_domain_id: useExisting ? existingTd : undefined,
        domain_label: useExisting ? undefined : label.trim(),
        network_local_id: nid.trim(),
        default_action: action,
        root_passphrase: pass,
        device_passphrase: devPass,
        remember,
        no_tun: noTun,
      })
      toast.ok(r.remembered ? '网络已上线（已在本机记住）' : '网络已上线')
      refreshDomains()
      refreshInstances()
      selectNetwork(r.trust_domain_id, r.network_local_id)
    } catch (e) {
      toast.err('建网/加网失败：' + e.message)
      setBusy(false)
    }
  }

  return (
    <div class="onb">
      <div class="onb-hero">
        <div class="onb-mark" />
        <h1>欢迎使用 PactMesh</h1>
        <p class="onb-lead">服务已在后台常驻，但还没有运行中的网络。两步建立你的第一个网络，它会立即上线，随后即可邀请设备加入。</p>
      </div>

      {!daemonReachable && (
        <div class="warnbar">后台 daemon 暂不可达——新建网络需要它在运行。请确认服务已启动后再试。</div>
      )}
      {daemonReachable && hasDiskNetwork && (
        <div class="onb-note muted">检测到本机已有信任域/网络，但当前没有任何实例在运行。可在下方新建并上线一个网络；既有网络的开机自动重连将在后续提供。</div>
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
              <button class="btn btn-primary" disabled={!step1Valid} onClick={() => setStep(2)}>下一步</button>
            </div>
          </>
        ) : (
          <>
            <div class="onb-card-title">创建并上线网络</div>
            <p class="muted">网络是设备加入的对象。先给它一个 ID 和默认放行策略，再为本机设备私钥设置口令——网络创建后会立即挂到后台 daemon 上运行。</p>

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
            <label class="form-row">
              <span class="field-label">设备私钥口令<small>至少 8 位</small></span>
              <input
                class="field"
                type="password"
                autocomplete="new-password"
                value={devPass}
                placeholder="为本机设备私钥设置口令"
                onInput={(e) => setDevPass(e.currentTarget.value)}
              />
            </label>

            <label class="check-row">
              <input type="checkbox" checked={remember} onInput={(e) => setRemember(e.currentTarget.checked)} />
              <span>在本机记住（开机自动重连，推荐）<small class="muted">口令经系统级封装后存于特权文件，绝不明文落盘；不勾选则加网后立即删除封存文件。</small></span>
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

      <p class="onb-foot muted">已经有邀请链接？让目标设备运行 <code>pactmesh accept-invite "&lt;链接&gt;"</code> 即可申请加入既有网络。</p>
    </div>
  )
}
