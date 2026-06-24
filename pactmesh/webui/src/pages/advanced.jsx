import { useState } from 'preact/hooks'
import { api } from '../api.js'
import { useApp } from '../store.jsx'
import { Modal, CopyId, useToast } from '../ui.jsx'
import { Credentials } from './credentials.jsx'

// 设置 > 高级：信任治理危险区（建域/建网/升根/预授权）+ 临时设备密钥（R2 落位）。

function field(label, sub) {
  return (
    <span class="field-label">{label}{sub && <small>{sub}</small>}</span>
  )
}

// 建立信任域
function CreateDomain() {
  const toast = useToast()
  const [label, setLabel] = useState('')
  const [pass, setPass] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)

  const run = async () => {
    setConfirm(false)
    setBusy(true)
    try {
      const r = await api.createDomain(label.trim(), pass)
      setResult(r)
      toast.ok('信任域已建立')
      setPass('')
    } catch (e) {
      toast.err('建域失败：' + e.message)
    } finally {
      setBusy(false)
    }
  }

  const valid = label.trim() && pass.length >= 8
  return (
    <div class="adv-op">
      <div class="adv-op-title">建立信任域</div>
      <p class="muted">生成一个新的独立信任域（含全新 root 私钥与管理口令）。你将成为其主控。</p>
      <label class="form-row">{field('域名称', '便于识别')}
        <input class="field" value={label} placeholder="home" onInput={(e) => setLabel(e.currentTarget.value)} /></label>
      <label class="form-row">{field('管理口令', '至少 8 位，即用即清')}
        <input class="field" type="password" value={pass} placeholder="新建该域的 root 口令" onInput={(e) => setPass(e.currentTarget.value)} /></label>
      <button class="btn btn-danger" disabled={busy || !valid} onClick={() => setConfirm(true)}>建立信任域</button>
      {result && (
        <div class="adv-result">
          <div class="form-row"><span class="field-label">信任域 ID</span><CopyId value={result.trust_domain_id} chars={40} /></div>
          <div class="muted">已落盘：<code>{result.path}</code>。请妥善保管管理口令——丢失不可恢复。</div>
        </div>
      )}
      {confirm && (
        <Modal title="建立新信任域" onClose={() => setConfirm(false)}
          footer={<><button class="btn" onClick={() => setConfirm(false)}>取消</button>
            <button class="btn btn-danger" onClick={run}>确认建立</button></>}>
          <p class="modal-note">将生成全新 root 私钥并以你输入的口令加密保存。<strong>口令一旦丢失，该域不可恢复。</strong></p>
        </Modal>
      )}
    </div>
  )
}

// 建立网络（既有域下）
function CreateNetwork() {
  const toast = useToast()
  const { domains } = useApp()
  const [td, setTd] = useState('')
  const [nid, setNid] = useState('')
  const [action, setAction] = useState('accept')
  const [pass, setPass] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setConfirm(false)
    setBusy(true)
    try {
      await api.createNetwork({ trust_domain_id: td, network_local_id: nid.trim(), default_action: action, passphrase: pass })
      toast.ok('网络已建立')
      setNid('')
      setPass('')
    } catch (e) {
      toast.err('建网失败：' + e.message)
    } finally {
      setBusy(false)
    }
  }

  const valid = td && nid.trim() && pass.length >= 8
  return (
    <div class="adv-op">
      <div class="adv-op-title">建立网络</div>
      <p class="muted">在既有信任域下创建一个新网络（需该域的管理口令解锁 root 签名）。</p>
      <label class="form-row">{field('信任域')}
        <select class="field" value={td} onChange={(e) => setTd(e.currentTarget.value)}>
          <option value="">选择信任域…</option>
          {domains.filter((d) => d.is_root_holder).map((d) => (
            <option key={d.trust_domain_id} value={d.trust_domain_id}>{d.label || d.trust_domain_id.slice(0, 12)}</option>
          ))}
        </select></label>
      <label class="form-row">{field('网络 ID', '本域内唯一')}
        <input class="field mono" value={nid} placeholder="home-net" onInput={(e) => setNid(e.currentTarget.value)} /></label>
      <label class="form-row">{field('默认策略', '未命中规则时')}
        <select class="field field-sm" value={action} onChange={(e) => setAction(e.currentTarget.value)}>
          <option value="accept">放行</option>
          <option value="drop">丢弃</option>
        </select></label>
      <label class="form-row">{field('管理口令', '解锁该域 root')}
        <input class="field" type="password" value={pass} placeholder="该域管理口令" onInput={(e) => setPass(e.currentTarget.value)} /></label>
      <button class="btn btn-danger" disabled={busy || !valid} onClick={() => setConfirm(true)}>建立网络</button>
      {confirm && (
        <Modal title="建立新网络" onClose={() => setConfirm(false)}
          footer={<><button class="btn" onClick={() => setConfirm(false)}>取消</button>
            <button class="btn btn-danger" onClick={run}>确认建立</button></>}>
          <p class="modal-note">将在所选信任域下签发网络 <code>{nid}</code> 的初始状态。</p>
        </Modal>
      )}
    </div>
  )
}

// 升级节点为主控
function UpgradeRoot() {
  const toast = useToast()
  const { network, requireUnlock } = useApp()
  const [peerId, setPeerId] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setConfirm(false)
    const ok = await requireUnlock()
    if (!ok) return
    setBusy(true)
    try {
      const r = await api.upgradeRoot(Number(peerId))
      toast.ok(r.ack ? `节点 ${peerId} 升级已下发` : '已下发，daemon 未确认')
      setPeerId('')
    } catch (e) {
      toast.err('升根失败：' + e.message)
    } finally {
      setBusy(false)
    }
  }

  const valid = network && Number(peerId) > 0
  return (
    <div class="adv-op">
      <div class="adv-op-title">升级节点为主控</div>
      <p class="muted">把当前网络中的某个节点提升为主控（共享 root 私钥）。对方需先在其本机预授权。节点号见「连通」页。</p>
      <label class="form-row">{field('节点号', 'peer id')}
        <input class="field field-sm mono" type="number" value={peerId} placeholder="1234567" onInput={(e) => setPeerId(e.currentTarget.value)} /></label>
      <button class="btn btn-danger" disabled={busy || !valid} onClick={() => setConfirm(true)}>升级为主控</button>
      {!network && <p class="muted">请先在顶栏选择网络。</p>}
      {confirm && (
        <Modal title="升级节点为主控" onClose={() => setConfirm(false)}
          footer={<><button class="btn" onClick={() => setConfirm(false)}>取消</button>
            <button class="btn btn-danger" onClick={run}>确认升级</button></>}>
          <p class="modal-note">将向节点 <code>{peerId}</code> 下发 root 升级载荷。<strong>升级后该节点拥有完整管理权限，不可轻易撤销。</strong></p>
        </Modal>
      )}
    </div>
  )
}

// 预授权本机被升为主控
function ArmRootUpgrade() {
  const toast = useToast()
  const [pass, setPass] = useState('')
  const [ttl, setTtl] = useState('300')
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setConfirm(false)
    setBusy(true)
    try {
      const r = await api.armRootUpgrade(pass, Number(ttl) || 300)
      toast.ok(`已预授权，有效 ${r.armed_ttl_secs}s`)
      setPass('')
    } catch (e) {
      toast.err('预授权失败：' + e.message)
    } finally {
      setBusy(false)
    }
  }

  const valid = pass.length >= 8 && Number(ttl) > 0
  return (
    <div class="adv-op">
      <div class="adv-op-title">预授权本机升为主控</div>
      <p class="muted">在限定时间内武装本机，接受来自现有主控的升级。设置本机升级后将使用的管理口令。</p>
      <label class="form-row">{field('管理口令', '升级后本机 root 口令，≥8 位')}
        <input class="field" type="password" value={pass} placeholder="本机升级后的 root 口令" onInput={(e) => setPass(e.currentTarget.value)} /></label>
      <label class="form-row">{field('有效期（秒）')}
        <input class="field field-num" type="number" value={ttl} onInput={(e) => setTtl(e.currentTarget.value)} /></label>
      <button class="btn btn-danger" disabled={busy || !valid} onClick={() => setConfirm(true)}>预授权升级</button>
      {confirm && (
        <Modal title="预授权本机升级" onClose={() => setConfirm(false)}
          footer={<><button class="btn" onClick={() => setConfirm(false)}>取消</button>
            <button class="btn btn-danger" onClick={run}>确认预授权</button></>}>
          <p class="modal-note">将在 {ttl} 秒内允许现有主控把本机升级为主控。逾期自动失效。</p>
        </Modal>
      )}
    </div>
  )
}

function DangerZone() {
  const [open, setOpen] = useState(false)
  return (
    <div class="card danger-card">
      <div class="card-title-row">
        <span class="card-title danger-title">⚠ 危险区 · 信任治理</span>
        <button class="btn btn-ghost btn-sm" onClick={() => setOpen((o) => !o)}>{open ? '收起' : '展开'}</button>
      </div>
      <p class="muted">建域 / 建网 / 升级主控属一次性高危操作，直接改写信任结构，无法简单回退。请确认无误后再操作。</p>
      {open && (
        <div class="adv-grid">
          <CreateDomain />
          <CreateNetwork />
          <UpgradeRoot />
          <ArmRootUpgrade />
        </div>
      )}
    </div>
  )
}

export function Advanced() {
  return (
    <>
      <DangerZone />
      <div class="adv-divider">临时设备密钥</div>
      <Credentials />
    </>
  )
}
