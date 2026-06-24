import { useState, useEffect, useCallback } from 'preact/hooks'
import { api } from '../api.js'
import { Skeleton, EmptyState, Dot, useToast } from '../ui.jsx'
import { PROTO_OPTS, ACTION_OPTS, CHAINTYPE_OPTS } from '../format.js'

// proto acl.Rule / acl.Chain 无 serde default → 新建必须全字段齐备（15/6），否则 daemon 422。
function newRule() {
  return {
    name: '', description: '', priority: 0, enabled: true, protocol: 5, ports: [],
    source_ips: [], destination_ips: [], source_ports: [], action: 1, rate_limit: 0,
    burst_limit: 0, stateful: false, source_groups: [], destination_groups: [],
  }
}
function newChain() {
  return { name: 'new-chain', chain_type: 1, description: '', enabled: true, rules: [], default_action: 2 }
}
function emptyAcl() {
  return { acl_v1: { chains: [], group: { declares: [], members: [] } } }
}

const csv = (a) => (Array.isArray(a) ? a.join(', ') : '')
const fromCsv = (s) => s.split(',').map((x) => x.trim()).filter(Boolean)

function Sel({ value, opts, onChange }) {
  return (
    <select class="field field-xs" value={value} onChange={(e) => onChange(Number(e.currentTarget.value))}>
      {opts.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
    </select>
  )
}

export function Policy() {
  const toast = useToast()
  const [acl, setAcl] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  const reload = useCallback(async (initial) => {
    if (initial) setLoading(true)
    try {
      const data = await api.config()
      const a = data?.config?.acl
      setAcl(a?.acl_v1 ? structuredClone(a) : emptyAcl())
      setError(null)
      if (!initial) toast.info('已从 daemon 重载当前策略')
    } catch (e) {
      setError(e)
    } finally {
      setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => { reload(true) }, [reload])

  // 草稿编辑：克隆后变更指定路径，避免共享引用。ACL 规模小，每次编辑全克隆可接受。
  const update = (mut) => setAcl((cur) => { const n = structuredClone(cur); mut(n); return n })

  const save = async () => {
    if (saving) return
    setSaving(true)
    try {
      await api.aclSet(acl)
      toast.ok('访问策略已下发')
    } catch (e) {
      toast.err('下发失败：' + e.message)
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <Skeleton rows={5} />
  if (error && !acl) {
    return (
      <div class="card card-degrade">
        <Dot kind="err" label="daemon 未连接" />
        <span class="muted">访问策略经本机 daemon 下发与读取。启动 daemon 后即可编辑。</span>
      </div>
    )
  }

  const chains = acl.acl_v1.chains

  return (
    <>
      <div class="toolbar">
        <span class="muted">{chains.length} 条规则链</span>
        <span class="toolbar-spacer" />
        <button class="btn btn-ghost" onClick={() => reload(false)}>重载</button>
        <button class="btn btn-ghost" onClick={() => update((n) => n.acl_v1.chains.push(newChain()))}>＋规则链</button>
        <button class="btn btn-primary" disabled={saving} onClick={save}>{saving ? '下发中…' : '保存并下发'}</button>
      </div>

      {!chains.length ? (
        <EmptyState
          icon="🛡"
          title="尚无访问策略"
          hint="规则链按链类型（入站/出站/转发）组织规则，匹配不中时走链默认动作。点「＋规则链」开始。"
          action={<button class="btn btn-primary" onClick={() => update((n) => n.acl_v1.chains.push(newChain()))}>＋规则链</button>}
        />
      ) : (
        chains.map((c, ci) => (
          <div key={ci} class="card chain-card">
            <div class="chain-bar">
              <input
                class="field field-sm"
                value={c.name}
                placeholder="链名"
                onChange={(e) => update((n) => { n.acl_v1.chains[ci].name = e.currentTarget.value })}
              />
              <label class="inline-label">类型 <Sel value={c.chain_type} opts={CHAINTYPE_OPTS} onChange={(v) => update((n) => { n.acl_v1.chains[ci].chain_type = v })} /></label>
              <label class="inline-label">默认 <Sel value={c.default_action} opts={ACTION_OPTS} onChange={(v) => update((n) => { n.acl_v1.chains[ci].default_action = v })} /></label>
              <label class="ck-inline">
                <input type="checkbox" checked={c.enabled} onChange={(e) => update((n) => { n.acl_v1.chains[ci].enabled = e.currentTarget.checked })} /> 启用
              </label>
              <span class="toolbar-spacer" />
              <button class="btn btn-ghost btn-sm" onClick={() => update((n) => n.acl_v1.chains[ci].rules.push(newRule()))}>＋规则</button>
              <button class="btn btn-danger btn-sm" onClick={() => update((n) => n.acl_v1.chains.splice(ci, 1))}>删链</button>
            </div>

            {!c.rules.length ? (
              <div class="muted chain-empty">该链暂无规则，匹配不中即走默认动作「{ACTION_OPTS.find(([v]) => v === c.default_action)?.[1]}」。</div>
            ) : (
              <div class="table-wrap">
                <table class="dtable edit">
                  <thead>
                    <tr>
                      <th>启用</th><th>名称</th><th>优先级</th><th>协议</th><th>端口</th>
                      <th>源 IP</th><th>目的 IP</th><th>源组</th><th>目的组</th><th>动作</th><th>限速</th><th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {c.rules.map((r, ri) => {
                      const set = (mut) => update((n) => mut(n.acl_v1.chains[ci].rules[ri]))
                      return (
                        <tr key={ri}>
                          <td><input type="checkbox" checked={r.enabled} onChange={(e) => set((x) => { x.enabled = e.currentTarget.checked })} /></td>
                          <td><input class="field field-xs" value={r.name} placeholder="规则名" onChange={(e) => set((x) => { x.name = e.currentTarget.value })} /></td>
                          <td><input class="field field-num" type="number" value={r.priority} onChange={(e) => set((x) => { x.priority = Number(e.currentTarget.value) || 0 })} /></td>
                          <td><Sel value={r.protocol} opts={PROTO_OPTS} onChange={(v) => set((x) => { x.protocol = v })} /></td>
                          <td><input class="field field-xs" value={csv(r.ports)} placeholder="80, 443" onChange={(e) => set((x) => { x.ports = fromCsv(e.currentTarget.value) })} /></td>
                          <td><input class="field field-xs mono" value={csv(r.source_ips)} placeholder="10.0.0.0/24" onChange={(e) => set((x) => { x.source_ips = fromCsv(e.currentTarget.value) })} /></td>
                          <td><input class="field field-xs mono" value={csv(r.destination_ips)} placeholder="任意" onChange={(e) => set((x) => { x.destination_ips = fromCsv(e.currentTarget.value) })} /></td>
                          <td><input class="field field-xs" value={csv(r.source_groups)} placeholder="分组名" onChange={(e) => set((x) => { x.source_groups = fromCsv(e.currentTarget.value) })} /></td>
                          <td><input class="field field-xs" value={csv(r.destination_groups)} placeholder="分组名" onChange={(e) => set((x) => { x.destination_groups = fromCsv(e.currentTarget.value) })} /></td>
                          <td><Sel value={r.action} opts={ACTION_OPTS} onChange={(v) => set((x) => { x.action = v })} /></td>
                          <td><input class="field field-num" type="number" value={r.rate_limit} title="包/秒，0=不限" onChange={(e) => set((x) => { x.rate_limit = Number(e.currentTarget.value) || 0 })} /></td>
                          <td><button class="btn btn-danger btn-sm" onClick={() => update((n) => n.acl_v1.chains[ci].rules.splice(ri, 1))}>×</button></td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ))
      )}
      <p class="muted policy-note">规则按优先级从高到低匹配；源组/目的组对应「分组」页中的成员分组。编辑后点「保存并下发」热重载到 daemon。</p>
    </>
  )
}
