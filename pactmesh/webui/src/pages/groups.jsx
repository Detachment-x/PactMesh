import { useState, useCallback, useMemo } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { useApp } from '../store.jsx'
import { Skeleton, EmptyState, ErrorState, CopyId, useToast } from '../ui.jsx'

export function Groups() {
  const { network, requireUnlock } = useApp()
  const toast = useToast()
  const td = network?.td
  const nid = network?.nid

  const tags = usePoll(
    useCallback(() => (td ? api.tags(td, nid) : Promise.resolve([])), [td, nid]),
    [td, nid],
    8000,
  )
  const members = usePoll(
    useCallback(() => (td ? api.members(td, nid) : Promise.resolve([])), [td, nid]),
    [td, nid],
    12000,
  )

  const [tag, setTag] = useState('')
  const [fp, setFp] = useState('')
  const [busy, setBusy] = useState(false)

  const list = Array.isArray(members.data) ? members.data : []
  const labelOf = useMemo(() => {
    const m = {}
    for (const d of list) m[d.fingerprint] = d.device_label || '未命名设备'
    return m
  }, [list])

  if (!network) {
    return <EmptyState icon="◍" title="尚未选择网络" hint="在顶栏选择一个网络后管理其分组。" />
  }
  if (tags.error) return <ErrorState error={tags.error} onRetry={tags.refresh} />

  const groups = Array.isArray(tags.data) ? tags.data : []

  const mutate = async (fingerprint, t, add, okMsg) => {
    if (busy) return
    const ok = await requireUnlock()
    if (!ok) return
    setBusy(true)
    try {
      await api.tagSet(fingerprint, t, add)
      toast.ok(okMsg)
      await tags.refresh()
    } catch (e) {
      toast.err(e.message)
    } finally {
      setBusy(false)
    }
  }

  const addMember = () => {
    const t = tag.trim()
    if (!t || !fp) return
    mutate(fp, t, true, `已加入分组「${t}」`).then(() => setFp(''))
  }

  const active = list.filter((d) => d.status === 'active')

  return (
    <>
      <div class="toolbar">
        <span class="muted">{groups.length} 个分组</span>
        <button class="btn btn-ghost" onClick={tags.refresh}>刷新</button>
      </div>

      {/* 加入分组 */}
      <div class="card">
        <div class="card-title">把设备加入分组</div>
        <div class="group-add">
          <select class="field" value={fp} onChange={(e) => setFp(e.currentTarget.value)}>
            <option value="">选择设备…</option>
            {active.map((d) => (
              <option key={d.fingerprint} value={d.fingerprint}>{d.device_label || '未命名设备'}</option>
            ))}
          </select>
          <input
            class="field"
            list="known-tags"
            value={tag}
            placeholder="分组名（新建或选择）"
            onInput={(e) => setTag(e.currentTarget.value)}
            onKeyDown={(e) => e.key === 'Enter' && addMember()}
          />
          <datalist id="known-tags">
            {groups.map((g) => <option key={g.tag} value={g.tag} />)}
          </datalist>
          <button class="btn btn-primary" disabled={busy || !tag.trim() || !fp} onClick={addMember}>加入</button>
        </div>
        <p class="muted">分组用于在「访问策略」里按组（而非逐台设备）授权。设备可同属多个分组。</p>
      </div>

      {tags.loading && !groups.length ? (
        <Skeleton rows={3} />
      ) : !groups.length ? (
        <EmptyState icon="🏷" title="还没有分组" hint="上方选择设备并填写分组名即可创建第一个分组。" />
      ) : (
        groups.map((g) => (
          <div key={g.tag} class="card group-card">
            <div class="card-title-row">
              <span class="card-title">{g.tag}</span>
              <span class="muted">{g.members.length} 台设备</span>
            </div>
            <div class="chips editable">
              {g.members.map((mfp) => (
                <span key={mfp} class="chip">
                  {labelOf[mfp] || <CopyId value={mfp} chars={10} />}
                  <button class="chip-x" disabled={busy} title="移出分组" onClick={() => mutate(mfp, g.tag, false, `已移出分组「${g.tag}」`)}>✕</button>
                </span>
              ))}
            </div>
          </div>
        ))
      )}
    </>
  )
}
