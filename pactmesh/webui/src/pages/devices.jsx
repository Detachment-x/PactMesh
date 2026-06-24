import { useState, useCallback } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, ErrorState, CopyId, Dot, Drawer, Toggle, useToast } from '../ui.jsx'

const ROLE = {
  root: { label: '主控', cls: 'role-root' },
  member: { label: '设备', cls: 'role-member' },
  external: { label: '外部', cls: 'role-ext' },
}
const STATUS = {
  active: { label: '正常', kind: 'ok' },
  disabled: { label: '已禁用', kind: 'warn' },
  revoked: { label: '已吊销', kind: 'err' },
  expired: { label: '已过期', kind: 'muted' },
}
const REASONS = [
  { v: 'unspecified', t: '未指定' },
  { v: 'removed', t: '移除设备' },
  { v: 'device-lost', t: '设备遗失' },
  { v: 'key-compromise', t: '密钥泄露' },
  { v: 'superseded', t: '证书更替' },
]

function capChips(c) {
  const out = []
  if (c.relay_data) out.push('中继数据')
  if (c.relay_control) out.push('中继控制')
  if (c.proxy_subnets?.length) out.push(`代理 ${c.proxy_subnets.length} 段`)
  return out
}

export function Devices() {
  const { network } = useApp()
  const td = network?.td
  const nid = network?.nid
  const [sel, setSel] = useState(null) // 当前抽屉设备 device_id（reissue 后 fingerprint 会变，device_id 稳定）

  const members = usePoll(
    useCallback(() => (td ? api.members(td, nid) : Promise.resolve([])), [td, nid]),
    [td, nid],
    8000,
  )

  if (!network) {
    return <EmptyState icon="◍" title="尚未选择网络" hint="在顶栏选择一个网络后查看其设备。" />
  }
  if (members.error) return <ErrorState error={members.error} onRetry={members.refresh} />

  const list = Array.isArray(members.data) ? members.data : []
  const current = list.find((d) => d.device_id === sel) || null

  return (
    <>
      <div class="toolbar">
        <span class="muted">{members.loading ? '加载中…' : `${list.length} 台设备`}</span>
        <button class="btn btn-ghost" onClick={members.refresh}>刷新</button>
      </div>

      {members.loading && !list.length ? (
        <Skeleton rows={4} />
      ) : !list.length ? (
        <EmptyState
          icon="✦"
          title="还没有设备"
          hint="在「概览」点击「邀请设备」生成邀请，对方接受后到「待批」审批即可加入。"
        />
      ) : (
        <div class="table-wrap">
          <table class="dtable">
            <thead>
              <tr>
                <th>设备</th>
                <th>状态</th>
                <th>主机名</th>
                <th>能力</th>
                <th>指纹</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.map((d) => {
                const role = ROLE[d.role] || ROLE.member
                const st = STATUS[d.status] || STATUS.active
                const chips = capChips(d.capabilities)
                return (
                  <tr key={d.fingerprint}>
                    <td>
                      <div class="dev-name">
                        <span>{d.device_label || '未命名设备'}</span>
                        {d.role === 'root' && <span class="badge-role role-root">主控</span>}
                      </div>
                    </td>
                    <td><Dot kind={st.kind} label={st.label} /></td>
                    <td class="mono-cell">{d.hostname || <span class="muted">—</span>}</td>
                    <td>
                      {chips.length ? (
                        <div class="chips">{chips.map((c) => <span key={c} class="chip">{c}</span>)}</div>
                      ) : (
                        <span class="muted">无</span>
                      )}
                    </td>
                    <td><CopyId value={d.fingerprint} chars={10} /></td>
                    <td class="ta-right">
                      <button class="btn btn-ghost btn-sm" onClick={() => setSel(d.device_id)}>管理</button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {current && (
        <DeviceDrawer
          key={current.device_id}
          device={current}
          onClose={() => setSel(null)}
          onChanged={members.refresh}
        />
      )}
    </>
  )
}

function DeviceDrawer({ device, onClose, onChanged }) {
  const { requireUnlock } = useApp()
  const toast = useToast()
  const fp = device.fingerprint
  const isRoot = device.role === 'root'

  const [label, setLabel] = useState(device.device_label || '')
  const [hostname, setHostname] = useState(device.hostname || '')
  const [relayData, setRelayData] = useState(!!device.capabilities.relay_data)
  const [relayControl, setRelayControl] = useState(!!device.capabilities.relay_control)
  const [cidrs, setCidrs] = useState(device.capabilities.proxy_subnets || [])
  const [newCidr, setNewCidr] = useState('')
  const [note, setNote] = useState('')
  const [reason, setReason] = useState('removed')
  const [confirmRevoke, setConfirmRevoke] = useState(false)
  const [busy, setBusy] = useState('')

  const act = async (tag, fn, okMsg, after) => {
    if (busy) return
    const ok = await requireUnlock()
    if (!ok) return
    setBusy(tag)
    try {
      await fn()
      toast.ok(okMsg)
      // reissue 会换 fingerprint：等列表刷新后，device prop 指向新证书，下个操作才用对 fp
      await onChanged?.()
      after?.()
    } catch (e) {
      toast.err(e.message)
    } finally {
      setBusy('')
    }
  }

  const addCidr = () => {
    const v = newCidr.trim()
    if (!v || cidrs.includes(v)) return
    setCidrs([...cidrs, v])
    setNewCidr('')
  }

  const saveCaps = () => {
    const body = { relay_data: relayData, relay_control: relayControl }
    const orig = device.capabilities.proxy_subnets || []
    if (cidrs.join(',') !== orig.join(',')) {
      if (cidrs.length === 0) body.clear_proxy_subnet = true
      else body.proxy_subnet = cidrs
    }
    return act('caps', () => api.capability(fp, body), '能力已更新')
  }

  const st = STATUS[device.status] || STATUS.active

  return (
    <Drawer
      title={device.device_label || '未命名设备'}
      subtitle={<><Dot kind={st.kind} label={st.label} /> · {(ROLE[device.role] || ROLE.member).label}</>}
      onClose={onClose}
      footer={<button class="btn" onClick={onClose}>关闭</button>}
    >
      {/* 标识 */}
      <section class="drawer-sec">
        <div class="sec-title">标识</div>
        <div class="form-row">
          <label class="field-label">设备名</label>
          <div class="inline-field">
            <input class="field" value={label} onInput={(e) => setLabel(e.currentTarget.value)} placeholder="如：办公笔记本" />
            <button
              class="btn btn-primary btn-sm"
              disabled={busy === 'name' || !label.trim() || label === device.device_label}
              onClick={() => act('name', () => api.rename(fp, label.trim(), note || undefined), '已重命名')}
            >保存</button>
          </div>
        </div>
        <div class="form-row">
          <label class="field-label">主机名<small>（留空清除）</small></label>
          <div class="inline-field">
            <input class="field mono" value={hostname} onInput={(e) => setHostname(e.currentTarget.value)} placeholder="laptop-01" />
            <button
              class="btn btn-primary btn-sm"
              disabled={busy === 'host' || hostname === (device.hostname || '')}
              onClick={() => act('host', () => api.hostname(fp, hostname.trim() || undefined, note || undefined), hostname.trim() ? '主机名已更新' : '主机名已清除')}
            >保存</button>
          </div>
        </div>
        <div class="form-row">
          <label class="field-label">指纹</label>
          <CopyId value={fp} chars={20} />
        </div>
      </section>

      {/* 能力 */}
      <section class="drawer-sec">
        <div class="sec-title">能力</div>
        <Toggle label="中继数据" hint="允许为他人转发数据流量" checked={relayData} onChange={setRelayData} />
        <Toggle label="中继控制" hint="允许参与控制面中继" checked={relayControl} onChange={setRelayControl} />
        <div class="form-row">
          <label class="field-label">代理网段<small>（CIDR，可访问的子网）</small></label>
          {cidrs.length > 0 && (
            <div class="chips editable">
              {cidrs.map((c) => (
                <span key={c} class="chip">
                  <code>{c}</code>
                  <button class="chip-x" onClick={() => setCidrs(cidrs.filter((x) => x !== c))}>✕</button>
                </span>
              ))}
            </div>
          )}
          <div class="inline-field">
            <input
              class="field mono"
              value={newCidr}
              placeholder="10.0.0.0/24"
              onInput={(e) => setNewCidr(e.currentTarget.value)}
              onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addCidr())}
            />
            <button class="btn btn-sm" onClick={addCidr}>添加</button>
          </div>
        </div>
        <button class="btn btn-primary btn-sm" disabled={busy === 'caps'} onClick={saveCaps}>
          {busy === 'caps' ? '保存中…' : '保存能力'}
        </button>
      </section>

      {/* 备注（应用于本次签名操作的审计说明） */}
      <section class="drawer-sec">
        <div class="sec-title">操作备注<small>（可选，记入证书审计）</small></div>
        <input class="field" value={note} placeholder="变更原因…" onInput={(e) => setNote(e.currentTarget.value)} />
      </section>

      {/* 状态 / 危险区 */}
      {!isRoot && (
        <section class="drawer-sec danger-sec">
          <div class="sec-title">状态</div>
          {device.status === 'disabled' ? (
            <button class="btn btn-sm" disabled={busy === 'enable'} onClick={() => act('enable', () => api.enable(fp), '已启用')}>
              启用设备
            </button>
          ) : device.status === 'active' ? (
            <button class="btn btn-warn btn-sm" disabled={busy === 'disable'} onClick={() => act('disable', () => api.disable(fp, note || undefined), '已禁用')}>
              禁用设备
            </button>
          ) : (
            <span class="muted">当前状态不可切换</span>
          )}

          {device.status !== 'revoked' && (
            <div class="revoke-box">
              <div class="sec-title">吊销（不可恢复）</div>
              <div class="form-row">
                <label class="field-label">原因</label>
                <select class="field" value={reason} onChange={(e) => setReason(e.currentTarget.value)}>
                  {REASONS.map((r) => <option key={r.v} value={r.v}>{r.t}</option>)}
                </select>
              </div>
              <label class="check-row">
                <input type="checkbox" checked={confirmRevoke} onChange={(e) => setConfirmRevoke(e.currentTarget.checked)} />
                <span>我确认永久吊销「{device.device_label || '该设备'}」，吊销后无法恢复。</span>
              </label>
              <button
                class="btn btn-danger btn-sm"
                disabled={!confirmRevoke || busy === 'revoke'}
                onClick={() => act('revoke', () => api.revoke(fp, reason, note || undefined), '设备已吊销', onClose)}
              >
                {busy === 'revoke' ? '吊销中…' : '吊销设备'}
              </button>
            </div>
          )}
        </section>
      )}
      {isRoot && <div class="muted drawer-note">主控设备不可在此禁用或吊销。</div>}
    </Drawer>
  )
}
