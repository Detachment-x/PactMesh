import { useState } from 'preact/hooks'
import qrcode from 'qrcode-generator'
import { postJson } from './api.js'
import { Modal, useToast } from './ui.jsx'
import { useApp } from './store.jsx'

// 把任意文本渲染成二维码 data URL（gif），无外部依赖。
function qrDataUrl(text) {
  const qr = qrcode(0, 'M')
  qr.addData(text)
  qr.make()
  return qr.createDataURL(5, 12)
}

// 邀请设备（一等公民流程，Flow B）：选来源 → 生成 → 二维码 + 复制 + 对方用法。
export function InviteModal({ onClose }) {
  const toast = useToast()
  const { network } = useApp()
  const [localListeners, setLocalListeners] = useState(true)
  const [peerHints, setPeerHints] = useState(true)
  const [seedsText, setSeedsText] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null) // {invite, seed_count, omitted}
  const [copied, setCopied] = useState(false)

  const generate = async () => {
    if (!network || busy) return
    setBusy(true)
    try {
      const seeds = seedsText
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      const data = await postJson('/api/trust/invite', {
        trust_domain_id: network.td,
        network_local_id: network.nid,
        seeds,
        include_peer_hints: peerHints,
        include_local_listeners: localListeners,
        format: 'url',
      })
      setResult(data)
    } catch (e) {
      toast.err('生成邀请失败：' + e.message)
    } finally {
      setBusy(false)
    }
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(result.invite)
      setCopied(true)
      toast.ok('已复制邀请链接')
      setTimeout(() => setCopied(false), 1500)
    } catch {
      toast.err('复制失败，请手动选择文本')
    }
  }

  return (
    <Modal
      title="邀请设备加入"
      width={result ? 460 : 420}
      onClose={onClose}
      footer={
        result ? (
          <>
            <button class="btn" onClick={() => setResult(null)}>重新生成</button>
            <button class="btn btn-primary" onClick={onClose}>完成</button>
          </>
        ) : (
          <>
            <button class="btn" onClick={onClose}>取消</button>
            <button class="btn btn-primary" disabled={busy} onClick={generate}>
              {busy ? '生成中…' : '生成邀请'}
            </button>
          </>
        )
      }
    >
      {!result ? (
        <>
          <p class="modal-note">
            为网络 <strong>{network?.label || '—'}</strong> 生成一次性入网邀请。选择新设备可达的落脚点：
          </p>
          <label class="check-row">
            <input type="checkbox" checked={localListeners} onChange={(e) => setLocalListeners(e.currentTarget.checked)} />
            <span>本机监听地址<small>（自动探测本机公网/接口可达端口）</small></span>
          </label>
          <label class="check-row">
            <input type="checkbox" checked={peerHints} onChange={(e) => setPeerHints(e.currentTarget.checked)} />
            <span>网络入口地址<small>（已登记的公开落脚点）</small></span>
          </label>
          <div class="field-label">额外落脚点（可选，每行一个 tcp://host:port）</div>
          <textarea
            class="field field-area"
            rows={3}
            placeholder="tcp://203.0.113.5:11010"
            value={seedsText}
            onInput={(e) => setSeedsText(e.currentTarget.value)}
          />
        </>
      ) : (
        <div class="invite-result">
          <div class="qr-wrap">
            <img class="qr-img" src={qrDataUrl(result.invite)} alt="邀请二维码" />
          </div>
          <div class="invite-meta">
            含 {result.seed_count} 个落脚点
            {result.omitted > 0 && <span class="muted"> · 已跳过 {result.omitted} 个无效/过期</span>}
          </div>
          <div class="invite-url" onClick={copy} title="点击复制">
            <code>{result.invite}</code>
            <span class="copy-icon">{copied ? '✓' : '⧉'}</span>
          </div>
          <div class="invite-howto">
            对方在新设备运行：
            <code class="howto-cmd">pactmesh accept-invite "&lt;邀请链接&gt;"</code>
            完成后回到「待批」审批即可加入。
          </div>
        </div>
      )}
    </Modal>
  )
}
