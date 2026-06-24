import { useState, useCallback } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, ErrorState, CopyId, useToast } from '../ui.jsx'

export function Pending() {
  const { network, requireUnlock } = useApp()
  const toast = useToast()
  const td = network?.td
  const nid = network?.nid
  const [busy, setBusy] = useState('') // 正在处理的 applicant_pk
  const [done, setDone] = useState(() => new Set()) // 乐观隐藏

  const pending = usePoll(
    useCallback(() => (td ? api.pending(td, nid) : Promise.resolve([])), [td, nid]),
    [td, nid],
    6000,
  )

  if (!network) {
    return <EmptyState icon="◍" title="尚未选择网络" hint="在顶栏选择一个网络后查看入网申请。" />
  }
  if (pending.error) return <ErrorState error={pending.error} onRetry={pending.refresh} />

  const all = Array.isArray(pending.data) ? pending.data : []
  const list = all.filter((r) => !done.has(r.applicant_pk))

  const handle = async (req, kind) => {
    if (busy) return
    if (kind === 'approve') {
      const ok = await requireUnlock()
      if (!ok) return
    }
    setBusy(req.applicant_pk)
    try {
      if (kind === 'approve') await api.approve(req.applicant_pk, req.device_label)
      else await api.reject(td, nid, req.applicant_pk)
      setDone((s) => new Set(s).add(req.applicant_pk))
      toast.ok(kind === 'approve' ? `已批准「${req.device_label || '设备'}」` : '已拒绝申请')
      pending.refresh()
    } catch (e) {
      toast.err(e.message)
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <div class="toolbar">
        <span class="muted">{pending.loading ? '加载中…' : `${list.length} 条待批申请`}</span>
        <button class="btn btn-ghost" onClick={pending.refresh}>刷新</button>
      </div>

      {pending.loading && !all.length ? (
        <Skeleton rows={3} />
      ) : !list.length ? (
        <EmptyState icon="✓" title="没有待批申请" hint="新设备运行 accept-invite 后，其申请会出现在这里等待审批。" />
      ) : (
        <div class="pending-list">
          {list.map((req) => (
            <div key={req.applicant_pk} class="pending-card">
              <div class="pending-main">
                <div class="pending-name">{req.device_label || '未命名设备'}</div>
                {req.hint && <div class="pending-hint">{req.hint}</div>}
                <div class="pending-pk">
                  <span class="muted">公钥</span> <CopyId value={req.applicant_pk} chars={16} />
                </div>
              </div>
              <div class="pending-actions">
                <button
                  class="btn btn-primary btn-sm"
                  disabled={busy === req.applicant_pk}
                  onClick={() => handle(req, 'approve')}
                >
                  {busy === req.applicant_pk ? '处理中…' : '批准'}
                </button>
                <button
                  class="btn btn-ghost btn-sm"
                  disabled={busy === req.applicant_pk}
                  onClick={() => handle(req, 'reject')}
                >
                  拒绝
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  )
}
