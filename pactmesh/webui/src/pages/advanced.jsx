import { useState } from 'preact/hooks'
import { api } from '../api.js'
import { useApp } from '../store.jsx'
import { Modal, useToast } from '../ui.jsx'
import { Credentials } from './credentials.jsx'

// 设置 > 高级：信任治理危险区（新建根网络/升级管理员/预授权）+ 临时设备密钥（R2 落位）。

function field(label, sub) {
  return (
    <span class="field-label">{label}{sub && <small>{sub}</small>}</span>
  )
}

// 新建根网络：与管理域一同建立、负责传输、囊括范围最广的网络。一步建域→建网→自举→上线。
function CreateRootNetwork() {
  const toast = useToast()
  const { refreshDomains, refreshInstances, selectNetwork } = useApp()
  const [name, setName] = useState('')
  const [action, setAction] = useState('accept')
  const [pass, setPass] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)

  const valid = name.trim() && pass.length >= 8

  const run = async () => {
    setConfirm(false)
    setBusy(true)
    try {
      const r = await api.networkRun({
        network_local_id: name.trim(),
        default_action: action,
        root_passphrase: pass,
      })
      toast.ok('根网络已创建并上线')
      setPass('')
      setName('')
      refreshDomains()
      refreshInstances()
      selectNetwork(r.trust_domain_id, r.network_local_id)
    } catch (e) {
      toast.err(/already exists/i.test(e.message) ? '同名网络已存在于本机。' : '创建根网络失败：' + e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="adv-op">
      <div class="adv-op-title">新建根网络</div>
      <p class="muted">创建一个全新的独立根网络：生成专属管理私钥，你成为其管理员。这是承载传输、囊括范围最广的网络，可在其下再建平级网络。</p>
      <label class="form-row">{field('网络名称', '便于识别，本机内唯一')}
        <input class="field mono" value={name} placeholder="home-net" onInput={(e) => setName(e.currentTarget.value)} /></label>
      <label class="form-row">{field('默认策略', '未命中规则时')}
        <select class="field field-sm" value={action} onChange={(e) => setAction(e.currentTarget.value)}>
          <option value="accept">放行</option>
          <option value="drop">丢弃</option>
        </select></label>
      <label class="form-row">{field('管理口令', '至少 8 位，即用即清')}
        <input class="field" type="password" value={pass} placeholder="设置管理口令" onInput={(e) => setPass(e.currentTarget.value)} /></label>
      <button class="btn btn-danger" disabled={busy || !valid} onClick={() => setConfirm(true)}>新建根网络</button>
      {confirm && (
        <Modal title="新建根网络" onClose={() => setConfirm(false)}
          footer={<><button class="btn" onClick={() => setConfirm(false)}>取消</button>
            <button class="btn btn-danger" onClick={run}>确认创建</button></>}>
          <p class="modal-note">将生成全新管理私钥并以你输入的口令加密保存，随即建网上线。<strong>口令一旦丢失，该根网络不可恢复。</strong></p>
        </Modal>
      )}
    </div>
  )
}

// 升级节点为管理员
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
      <div class="adv-op-title">升级节点为管理员</div>
      <p class="muted">把当前网络中的某个节点提升为管理员（共享管理私钥）。对方需先在其本机预授权。节点号见「设备」页节点详情。</p>
      <label class="form-row">{field('节点号', 'peer id')}
        <input class="field field-sm mono" type="number" value={peerId} placeholder="1234567" onInput={(e) => setPeerId(e.currentTarget.value)} /></label>
      <button class="btn btn-danger" disabled={busy || !valid} onClick={() => setConfirm(true)}>升级为管理员</button>
      {!network && <p class="muted">请先在顶栏选择网络。</p>}
      {confirm && (
        <Modal title="升级节点为管理员" onClose={() => setConfirm(false)}
          footer={<><button class="btn" onClick={() => setConfirm(false)}>取消</button>
            <button class="btn btn-danger" onClick={run}>确认升级</button></>}>
          <p class="modal-note">将向节点 <code>{peerId}</code> 下发管理员升级载荷。<strong>升级后该节点拥有完整管理权限，不可轻易撤销。</strong></p>
        </Modal>
      )}
    </div>
  )
}

// 预授权本机被升为管理员
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
      <div class="adv-op-title">预授权本机升为管理员</div>
      <p class="muted">在限定时间内武装本机，接受来自现有管理员的升级。设置本机升级后将使用的管理口令。</p>
      <label class="form-row">{field('管理口令', '升级后本机管理口令，≥8 位')}
        <input class="field" type="password" value={pass} placeholder="本机升级后的管理口令" onInput={(e) => setPass(e.currentTarget.value)} /></label>
      <label class="form-row">{field('有效期（秒）')}
        <input class="field field-num" type="number" value={ttl} onInput={(e) => setTtl(e.currentTarget.value)} /></label>
      <button class="btn btn-danger" disabled={busy || !valid} onClick={() => setConfirm(true)}>预授权升级</button>
      {confirm && (
        <Modal title="预授权本机升级" onClose={() => setConfirm(false)}
          footer={<><button class="btn" onClick={() => setConfirm(false)}>取消</button>
            <button class="btn btn-danger" onClick={run}>确认预授权</button></>}>
          <p class="modal-note">将在 {ttl} 秒内允许现有管理员把本机升级为管理员。逾期自动失效。</p>
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
      <p class="muted">新建根网络 / 升级管理员 / 预授权属一次性高危操作，直接改写信任结构，无法简单回退。请确认无误后再操作。</p>
      {open && (
        <div class="adv-grid">
          <CreateRootNetwork />
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
