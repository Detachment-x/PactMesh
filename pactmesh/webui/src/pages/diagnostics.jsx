import { useState, useMemo } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { Skeleton, EmptyState, Dot } from '../ui.jsx'
import { sockAddr, bytes, ago, PROTOCOL, CONN_STATE, ACL_ACTION } from '../format.js'

const labelStr = (m) =>
  Object.entries(m.labels || {})
    .map(([k, v]) => `${k}=${v}`)
    .join(' ')

export function Diagnostics() {
  const stats = usePoll(api.stats, [], 5000)
  const acl = usePoll(api.aclStats, [], 5000)
  const [q, setQ] = useState('')

  const daemonDown = !!stats.error && !!acl.error

  const metrics = stats.data?.metrics || []
  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase()
    if (!t) return metrics
    return metrics.filter((m) => m.name.toLowerCase().includes(t) || labelStr(m).toLowerCase().includes(t))
  }, [metrics, q])

  const a = acl.data?.acl_stats
  const global = a?.global ? Object.entries(a.global) : []
  const rules = (a?.rules || []).filter((r) => (r.stat?.packet_count || 0) > 0)
  const conns = a?.conn_track || []

  if (daemonDown) {
    return (
      <div class="card card-degrade">
        <Dot kind="err" label="daemon 未连接" />
        <span class="muted">诊断数据来自本机 daemon 的运行指标与 ACL 统计。启动 daemon 后将自动显示。</span>
      </div>
    )
  }

  return (
    <>
      {/* 系统指标 */}
      <div class="card">
        <div class="card-title-row">
          <span class="card-title">系统指标</span>
          <input class="field field-inline" placeholder="过滤指标…" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
        </div>
        {stats.error ? (
          <span class="muted">指标不可用：{stats.error.message}</span>
        ) : stats.loading && !metrics.length ? (
          <Skeleton rows={4} />
        ) : !filtered.length ? (
          <EmptyState icon="📊" title={metrics.length ? '无匹配指标' : '暂无指标'} hint={metrics.length ? '调整过滤条件。' : 'daemon 暂未上报运行指标。'} />
        ) : (
          <div class="table-wrap">
            <table class="dtable compact">
              <thead><tr><th>指标</th><th>标签</th><th class="ta-right">值</th></tr></thead>
              <tbody>
                {filtered.map((m, i) => (
                  <tr key={m.name + i}>
                    <td class="mono-cell">{m.name}</td>
                    <td class="mono-cell muted">{labelStr(m) || '—'}</td>
                    <td class="ta-right mono-cell">{m.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ACL 全局计数 */}
      <div class="card">
        <div class="card-title">访问控制统计</div>
        {acl.error ? (
          <span class="muted">ACL 统计不可用：{acl.error.message}</span>
        ) : acl.loading && !a ? (
          <Skeleton rows={2} />
        ) : !global.length ? (
          <span class="muted">暂无全局计数</span>
        ) : (
          <div class="metric-grid">
            {global.map(([k, v]) => (
              <div key={k} class="metric"><div class="metric-label">{k}</div><div class="metric-value">{v}</div></div>
            ))}
          </div>
        )}
      </div>

      {/* 规则命中 */}
      {rules.length > 0 && (
        <div class="card">
          <div class="card-title">规则命中</div>
          <div class="table-wrap">
            <table class="dtable compact">
              <thead><tr><th>规则</th><th>动作</th><th class="ta-right">命中包</th><th class="ta-right">字节</th></tr></thead>
              <tbody>
                {rules.map((r, i) => (
                  <tr key={i}>
                    <td>{r.rule?.name || <span class="muted">#{r.rule?.priority ?? i}</span>}</td>
                    <td>{ACL_ACTION[r.rule?.action] ?? '—'}</td>
                    <td class="ta-right mono-cell">{r.stat?.packet_count ?? 0}</td>
                    <td class="ta-right mono-cell">{bytes(r.stat?.byte_count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 连接跟踪 */}
      <div class="card">
        <div class="card-title">连接跟踪 <small class="muted">（{conns.length}）</small></div>
        {!conns.length ? (
          <span class="muted">暂无活跃连接记录</span>
        ) : (
          <div class="table-wrap">
            <table class="dtable compact">
              <thead><tr><th>源</th><th>目标</th><th>协议</th><th>状态</th><th class="ta-right">包</th><th class="ta-right">字节</th><th class="ta-right">活跃</th></tr></thead>
              <tbody>
                {conns.map((c, i) => {
                  const st = CONN_STATE[c.state] || { t: c.state, kind: 'muted' }
                  return (
                    <tr key={i}>
                      <td class="mono-cell">{sockAddr(c.src_addr)}</td>
                      <td class="mono-cell">{sockAddr(c.dst_addr)}</td>
                      <td>{PROTOCOL[c.protocol] ?? c.protocol}</td>
                      <td><Dot kind={st.kind} label={st.t} /></td>
                      <td class="ta-right mono-cell">{c.packet_count ?? 0}</td>
                      <td class="ta-right mono-cell">{bytes(c.byte_count)}</td>
                      <td class="ta-right mono-cell">{ago(c.last_seen)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
