import { useState, useMemo } from 'preact/hooks'
import { api } from './api.js'
import { useApp } from './store.jsx'
import { useToast } from './ui.jsx'

// 首启引导（Flow A）：当本机尚无任何网络时接管内容区，
// 两步把用户带到「拥有一个可用网络」——新建信任域（建域）→ 在其下建网。
// 已有主控信任域时可跳过建域、直接在既有域下建网。

export function Onboarding() {
  const toast = useToast()
  const { domains, refreshDomains, selectNetwork } = useApp()
  const rootDomains = useMemo(() => domains.filter((d) => d.is_root_holder), [domains])

  const [step, setStep] = useState(1)
  const [useExisting, setUseExisting] = useState(rootDomains.length > 0)
  const [existingTd, setExistingTd] = useState(rootDomains[0]?.trust_domain_id || '')
  const [label, setLabel] = useState('')
  const [pass, setPass] = useState('')
  const [nid, setNid] = useState('')
  const [action, setAction] = useState('accept')
  const [busy, setBusy] = useState(false)

  const step1Valid = useExisting ? !!existingTd && pass.length >= 8 : label.trim() && pass.length >= 8
  const step2Valid = nid.trim().length > 0

  const finish = async () => {
    setBusy(true)
    try {
      let td = existingTd
      if (!useExisting) {
        const r = await api.createDomain(label.trim(), pass)
        td = r.trust_domain_id
      }
      await api.createNetwork({ trust_domain_id: td, network_local_id: nid.trim(), default_action: action, passphrase: pass })
      toast.ok('网络已就绪')
      refreshDomains()
      selectNetwork(td, nid.trim())
    } catch (e) {
      toast.err((useExisting ? '建网失败：' : '建域/建网失败：') + e.message)
      setBusy(false)
    }
  }

  return (
    <div class="onb">
      <div class="onb-hero">
        <div class="onb-mark" />
        <h1>欢迎使用 PactMesh</h1>
        <p class="onb-lead">还没有可用的网络。两步即可建立你的第一个网络，然后邀请设备加入。</p>
      </div>

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
            <div class="onb-card-title">创建网络</div>
            <p class="muted">网络是设备加入的对象。先给它一个 ID，并设定未命中规则时的默认放行策略。</p>

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

            <div class="onb-actions">
              <button class="btn" disabled={busy} onClick={() => setStep(1)}>上一步</button>
              <button class="btn btn-primary" disabled={busy || !step2Valid} onClick={finish}>
                {busy ? '创建中…' : '创建网络'}
              </button>
            </div>
          </>
        )}
      </div>

      <p class="onb-foot muted">已经有邀请链接？让目标设备运行 <code>pactmesh accept-invite "&lt;链接&gt;"</code> 即可申请加入既有网络。</p>
    </div>
  )
}
