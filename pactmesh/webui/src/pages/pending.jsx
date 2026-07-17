import { useState, useCallback } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, CopyId, useToast } from '../ui.jsx'

// 全局待批收件箱：聚合本机所有「管理员网络」的入网申请（与当前选中网络无关）。
// 列表只读（无需解锁）；批准按各申请所属网络就地解锁并签发，拒绝走 daemon RPC。
export function Pending() {
  const { domains, requireUnlock } = useApp()
  const toast = useToast()
  const [busy, setBusy] = useState('') // 正在处理的 applicant_pk
  const [bulk, setBulk] = useState(false) // 连批进行中
  const [done, setDone] = useState(() => new Set()) // 乐观隐藏

  // 仅持根者网络能审批入网；成员网络无审批权，不纳入。
  const rootNets = domains
    .filter((d) => d.is_root_holder)
    .flatMap((d) => d.networks.map((nid) => ({ td: d.trust_domain_id, nid, label: nid })))
  const key = rootNets.map((n) => n.td + ' ' + n.nid).join('|')

  const pending = usePoll(
    useCallback(async () => {
      const per = await Promise.all(
        rootNets.map(async (n) => {
          try {
            const rows = await api.pending(n.td, n.nid)
            return (Array.isArray(rows) ? rows : []).map((r) => ({ ...r, _net: n }))
          } catch {
            return []
          }
        }),
      )
      return per.flat()
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [key]),
    [key],
    6000,
  )

  const all = Array.isArray(pending.data) ? pending.data : []
  const list = all.filter((r) => !done.has(r._net.td + ' ' + r._net.nid + ' ' + r.applicant_pk))
  const multiNet = rootNets.length > 1

  const handle = async (req, kind) => {
    if (busy || bulk) return
    const net = req._net
    const uid = net.td + ' ' + net.nid + ' ' + req.applicant_pk
    if (kind === 'approve') {
      const ok = await requireUnlock(net)
      if (!ok) return
    }
    setBusy(uid)
    try {
      if (kind === 'approve') await api.approve(req.applicant_pk, req.device_label)
      else await api.reject(net.td, net.nid, req.applicant_pk)
      setDone((s) => new Set(s).add(uid))
      toast.ok(kind === 'approve' ? `已批准「${req.device_label || '设备'}」` : '已拒绝申请')
      pending.refresh()
    } catch (e) {
      toast.err(e.message)
    } finally {
      setBusy('')
    }
  }

  // 连批：按所属网络分组，每个网络解锁一次（已解锁则复用会话），其内全部就地签发。
  const approveAll = async () => {
    if (bulk || busy || !list.length) return
    const groups = new Map()
    for (const req of list) {
      const net = req._net
      const k = net.td + ' ' + net.nid
      if (!groups.has(k)) groups.set(k, { net, items: [] })
      groups.get(k).items.push(req)
    }
    setBulk(true)
    let ok = 0
    let fail = 0
    try {
      for (const { net, items } of groups.values()) {
        const unlocked = await requireUnlock(net)
        if (!unlocked) break // 取消解锁：停在此网络，已批准的保留
        for (const req of items) {
          const uid = net.td + ' ' + net.nid + ' ' + req.applicant_pk
          try {
            await api.approve(req.applicant_pk, req.device_label)
            setDone((s) => new Set(s).add(uid))
            ok++
          } catch {
            fail++
          }
        }
      }
    } finally {
      setBulk(false)
      pending.refresh()
      if (ok) toast.ok(`已批准 ${ok} 台设备` + (fail ? `，${fail} 台失败` : ''))
      else if (fail) toast.err(`批准失败（${fail} 台）`)
    }
  }

  if (!rootNets.length) {
    return (
      <EmptyState
        icon="✓"
        title="没有可审批的网络"
        hint="你目前不是任何网络的管理员。作为管理员创建或持有网络后，其他设备的入网申请会汇总到这里。"
      />
    )
  }

  return (
    <>
      <div class="toolbar">
        <span class="muted">
          {pending.loading && !all.length ? '加载中…' : `${list.length} 条待批申请`}
          {multiNet && ` · 汇总自 ${rootNets.length} 个网络`}
        </span>
        {list.length > 1 && (
          <button class="btn btn-primary btn-sm" disabled={bulk || !!busy} onClick={approveAll}>
            {bulk ? '批准中…' : `批准全部 (${list.length})`}
          </button>
        )}
        <button class="btn btn-ghost" onClick={pending.refresh}>刷新</button>
      </div>

      {pending.loading && !all.length ? (
        <Skeleton rows={3} />
      ) : !list.length ? (
        <EmptyState icon="✓" title="没有待批申请" hint="新设备运行 accept-invite 后，其申请会出现在这里等待审批。" />
      ) : (
        <div class="pending-list">
          {list.map((req) => {
            const uid = req._net.td + ' ' + req._net.nid + ' ' + req.applicant_pk
            return (
              <div key={uid} class="pending-card">
                <div class="pending-main">
                  <div class="pending-name">
                    {req.device_label || '未命名设备'}
                    {multiNet && <span class="badge-role role-cred-soft">{req._net.label}</span>}
                  </div>
                  {req.hint && <div class="pending-hint">{req.hint}</div>}
                  <div class="pending-pk">
                    <span class="muted">公钥</span> <CopyId value={req.applicant_pk} chars={16} />
                  </div>
                </div>
                <div class="pending-actions">
                  <button
                    class="btn btn-primary btn-sm"
                    disabled={busy === uid || bulk}
                    onClick={() => handle(req, 'approve')}
                  >
                    {busy === uid ? '处理中…' : '批准'}
                  </button>
                  <button
                    class="btn btn-ghost btn-sm"
                    disabled={busy === uid || bulk}
                    onClick={() => handle(req, 'reject')}
                  >
                    拒绝
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </>
  )
}
