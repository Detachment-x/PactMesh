import { useState } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { Skeleton, EmptyState, Dot, Modal, Toggle, CopyId, useToast } from '../ui.jsx'

const fromCsv = (s) => s.split(',').map((x) => x.trim()).filter(Boolean)

function expiryText(unix) {
  if (!unix) return '—'
  const left = unix - Math.floor(Date.now() / 1000)
  if (left <= 0) return '已过期'
  if (left < 3600) return `${Math.floor(left / 60)} 分钟后`
  if (left < 86400) return `${Math.floor(left / 3600)} 小时后`
  return `${Math.floor(left / 86400)} 天后`
}

export function Credentials() {
  const toast = useToast()
  const creds = usePoll(api.credentials, [], 10000)

  const [ttl, setTtl] = useState('3600')
  const [groups, setGroups] = useState('')
  const [cidrs, setCidrs] = useState('')
  const [allowRelay, setAllowRelay] = useState(false)
  const [reusable, setReusable] = useState(true)
  const [cid, setCid] = useState('')
  const [busy, setBusy] = useState(false)
  const [secret, setSecret] = useState(null) // {credential_id, credential_secret}
  const [revoking, setRevoking] = useState(null) // 待确认吊销的 credential_id

  const daemonDown = !!creds.error
  const list = creds.data?.credentials || []

  const generate = async () => {
    const n = Number(ttl)
    if (!n || n <= 0) { toast.err('有效期（秒）必须大于 0'); return }
    setBusy(true)
    try {
      const body = {
        ttl_seconds: n,
        groups: fromCsv(groups),
        allowed_proxy_cidrs: fromCsv(cidrs),
        allow_relay: allowRelay,
        reusable,
      }
      if (cid.trim()) body.credential_id = cid.trim()
      const r = await api.credGenerate(body)
      setSecret(r)
      toast.ok('临时设备密钥已签发')
      setCid('')
      creds.refresh()
    } catch (e) {
      toast.err('签发失败：' + e.message)
    } finally {
      setBusy(false)
    }
  }

  const doRevoke = async () => {
    const id = revoking
    setRevoking(null)
    try {
      await api.credRevoke(id)
      toast.ok('密钥已吊销')
      creds.refresh()
    } catch (e) {
      toast.err('吊销失败：' + e.message)
    }
  }

  if (daemonDown) {
    return (
      <div class="card card-degrade">
        <Dot kind="err" label="daemon 未连接" />
        <span class="muted">临时设备密钥经本机 daemon 签发与吊销，且需以 <code>--secure-mode</code> 运行。启动后即可管理。</span>
      </div>
    )
  }

  return (
    <>
      <div class="card">
        <div class="card-title">签发临时设备密钥</div>
        <p class="muted">无人值守节点（中继 VPS / CI 容器 / 临时访问）凭密钥接入，带有效期、可设代理网段，可复用密钥供多台共用。</p>
        <div class="cred-form">
          <label class="form-row"><span class="field-label">有效期（秒）<small>必填，&gt;0</small></span>
            <input class="field field-num" type="number" value={ttl} onInput={(e) => setTtl(e.currentTarget.value)} /></label>
          <label class="form-row"><span class="field-label">分组<small>逗号分隔，可空</small></span>
            <input class="field" value={groups} placeholder="relay, ci" onInput={(e) => setGroups(e.currentTarget.value)} /></label>
          <label class="form-row"><span class="field-label">代理网段<small>CIDR，逗号分隔，可空</small></span>
            <input class="field mono" value={cidrs} placeholder="10.0.0.0/24" onInput={(e) => setCidrs(e.currentTarget.value)} /></label>
          <label class="form-row"><span class="field-label">密钥 ID<small>可空，自动生成</small></span>
            <input class="field mono" value={cid} placeholder="relay-hk-01" onInput={(e) => setCid(e.currentTarget.value)} /></label>
        </div>
        <Toggle label="允许中继" hint="该节点可为他人转发流量" checked={allowRelay} onChange={setAllowRelay} />
        <Toggle label="可复用" hint="一把密钥可供多台节点共用" checked={reusable} onChange={setReusable} />
        <button class="btn btn-primary" disabled={busy} onClick={generate}>{busy ? '签发中…' : '签发密钥'}</button>

        {secret && (
          <div class="secret-box">
            <div class="secret-warn">⚠ 密钥仅此一次完整显示，请立即复制保存。</div>
            <div class="form-row"><span class="field-label">ID</span><CopyId value={secret.credential_id} chars={40} /></div>
            <div class="form-row"><span class="field-label">密钥</span><CopyId value={secret.credential_secret} chars={40} /></div>
            <div class="muted">节点接入：<code>pactmesh-core --secure-mode --credential &lt;密钥&gt;</code></div>
            <button class="btn btn-sm" onClick={() => setSecret(null)}>我已保存</button>
          </div>
        )}
      </div>

      <div class="card">
        <div class="card-title-row">
          <span class="card-title">现有密钥</span>
          <button class="btn btn-ghost btn-sm" onClick={creds.refresh}>刷新</button>
        </div>
        {creds.loading && !list.length ? (
          <Skeleton rows={3} />
        ) : !list.length ? (
          <EmptyState icon="🔑" title="暂无临时设备密钥" hint="用上方表单签发第一把密钥。" />
        ) : (
          <div class="table-wrap">
            <table class="dtable">
              <thead>
                <tr><th>ID</th><th>分组</th><th>中继</th><th>有效期</th><th>代理网段</th><th></th></tr>
              </thead>
              <tbody>
                {list.map((c) => (
                  <tr key={c.credential_id}>
                    <td><CopyId value={c.credential_id} chars={14} /></td>
                    <td>{c.groups?.length ? <div class="chips">{c.groups.map((g) => <span key={g} class="chip">{g}</span>)}</div> : <span class="muted">—</span>}</td>
                    <td>{c.allow_relay ? <Dot kind="ok" label="是" /> : <span class="muted">否</span>}</td>
                    <td class="mono-cell">{expiryText(c.expiry_unix)}</td>
                    <td class="mono-cell">{c.allowed_proxy_cidrs?.length ? c.allowed_proxy_cidrs.join(', ') : <span class="muted">—</span>}</td>
                    <td class="ta-right"><button class="btn btn-danger btn-sm" onClick={() => setRevoking(c.credential_id)}>吊销</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {revoking && (
        <Modal
          title="吊销临时设备密钥"
          onClose={() => setRevoking(null)}
          footer={
            <>
              <button class="btn" onClick={() => setRevoking(null)}>取消</button>
              <button class="btn btn-danger" onClick={doRevoke}>确认吊销</button>
            </>
          }
        >
          <p class="modal-note">吊销后，凭此密钥接入的节点将无法再连接（不可恢复）。</p>
          <code class="mono">{revoking}</code>
        </Modal>
      )}
    </>
  )
}
